@echo off
REM ===========================================================================
REM  setup.bat
REM
REM  Performs every step in README.md:
REM    1. Python venv + dependencies
REM    2. Deploys Keycloak locally in Docker + configures realm/client/user
REM    3. Deploys EJBCA (Community) locally in Docker + CA/admin cert
REM    4. Provisions AWS (RDS MySQL, SES sender, Bedrock check), tagged Project=tcx
REM    5. Writes .env
REM
REM  Requires on PATH: docker, aws (v2, configured), python, openssl, curl, powershell
REM ===========================================================================
setlocal enabledelayedexpansion

REM ---------------------------------------------------------------------------
REM Configuration
REM ---------------------------------------------------------------------------
set "PROJECT_TAG=tcx"
set "AWS_REGION=us-east-2"
set "BEDROCK_MODEL_ID=us.meta.llama4-scout-17b-instruct-v1:0"
set "SES_SENDER_EMAIL=user@example.com"

set "KEYCLOAK_CONTAINER=tcx-keycloak"
set "EJBCA_CONTAINER=tcx-ejbca"
REM 26.3: ships supported RFC 8693 token exchange without a preview feature flag.
set "KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.3"
set "EJBCA_IMAGE=keyfactor/ejbca-ce:latest"
set "KEYCLOAK_PORT=8080"
set "EJBCA_HTTPS_PORT=8443"
set "EJBCA_HTTP_PORT=8082"

set "KC_REALM=mcp-realm"
set "KC_CLIENT_ID=mcp-app-client"
set "KC_DEMO_USER=testuser"

set "EJBCA_CA_NAME=UserCA"
REM Built-in profiles (EJBCA CE can't create custom ones headlessly).
set "EJBCA_CERT_PROFILE=ENDUSER"
set "EJBCA_END_ENTITY_PROFILE=EMPTY"

set "RDS_ID=tcx-mysql"
set "RDS_SG_NAME=tcx-rds-sg"
set "RDS_SUBNET_GROUP=tcx-public"
set "RDS_DB=mysqldb"
set "RDS_USER=admin"

REM This script lives in .\scripts but operates on the project root (parent dir),
REM so cd there regardless of where it is invoked from.
cd /d "%~dp0.."

REM ---------------------------------------------------------------------------
REM 0. Preflight
REM ---------------------------------------------------------------------------
echo(
echo ==^> Checking prerequisites
for %%C in (docker aws python openssl curl) do (
    where %%C >nul 2>&1 || (echo [error] '%%C' is required but not found on PATH. & exit /b 1)
)
docker info >nul 2>&1 || (echo [error] Docker daemon is not running. & exit /b 1)
aws sts get-caller-identity --region %AWS_REGION% >nul 2>&1 || (echo [error] AWS credentials not configured. Run 'aws configure'. & exit /b 1)
echo     Prerequisites satisfied. Region: %AWS_REGION%

REM Generate secrets
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"`) do set "KC_ADMIN_PASSWORD=%%i"
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"`) do set "KC_CLIENT_SECRET=%%i"
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"`) do set "KC_DEMO_PASSWORD=%%i"
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"`) do set "EJBCA_ADMIN_CERT_PASSWORD=%%i"
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"`) do set "RDS_PASS=%%i"
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"`) do set "APP_SECRET_KEY=%%i"

REM ---------------------------------------------------------------------------
REM 1. Python venv + dependencies
REM ---------------------------------------------------------------------------
echo(
echo ==^> Creating Python virtual environment and installing dependencies
if not exist ".venv\Scripts\activate.bat" python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul
pip install -r requirements.txt || (echo [error] pip install failed. & exit /b 1)
if not exist certs mkdir certs

REM ---------------------------------------------------------------------------
REM 2. Deploy Keycloak
REM ---------------------------------------------------------------------------
echo(
echo ==^> Deploying Keycloak in Docker
docker rm -f %KEYCLOAK_CONTAINER% >nul 2>&1
docker run -d --name %KEYCLOAK_CONTAINER% -p %KEYCLOAK_PORT%:8080 ^
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=%KC_ADMIN_PASSWORD% ^
    -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=%KC_ADMIN_PASSWORD% ^
    %KEYCLOAK_IMAGE% start-dev >nul || (echo [error] Failed to start Keycloak. & exit /b 1)

echo     Waiting for Keycloak to become ready...
set "KC_READY="
for /l %%i in (1,1,60) do (
    if not defined KC_READY (
        curl -sf http://localhost:%KEYCLOAK_PORT%/realms/master >nul 2>&1 && set "KC_READY=1"
        if not defined KC_READY ping -n 4 127.0.0.1 >nul
    )
)
if not defined KC_READY (echo [error] Keycloak did not become ready. & exit /b 1)
echo     Keycloak up at http://localhost:%KEYCLOAK_PORT%

echo ==^> Configuring Keycloak realm/client/user
set "KCADM=/opt/keycloak/bin/kcadm.sh"
docker exec %KEYCLOAK_CONTAINER% %KCADM% config credentials --server http://localhost:8080 --realm master --user admin --password %KC_ADMIN_PASSWORD%
docker exec %KEYCLOAK_CONTAINER% %KCADM% create realms -s realm=%KC_REALM% -s enabled=true 2>nul
REM Create the confidential client with the secret we generated (no read-back needed).
docker exec %KEYCLOAK_CONTAINER% %KCADM% create clients -r %KC_REALM% -s clientId=%KC_CLIENT_ID% -s enabled=true -s publicClient=false -s directAccessGrantsEnabled=true -s serviceAccountsEnabled=true -s standardFlowEnabled=false -s secret=%KC_CLIENT_SECRET%
docker exec %KEYCLOAK_CONTAINER% %KCADM% create users -r %KC_REALM% -s username=%KC_DEMO_USER% -s enabled=true -s email=%KC_DEMO_USER%@example.com -s emailVerified=true -s firstName=Test -s lastName=User 2>nul
docker exec %KEYCLOAK_CONTAINER% %KCADM% set-password -r %KC_REALM% --username %KC_DEMO_USER% --new-password %KC_DEMO_PASSWORD%
REM RFC 8693 standard token exchange: downscope the login token to aud=mcp-server
REM so the MCP server can reject a leaked full-session token (idempotent helper).
echo ==^> Configuring token exchange (mcp-server audience, mcp-audience scope)
set "KC_HOST=http://localhost:%KEYCLOAK_PORT%"
set "KC_ADMIN_USER=admin"
set "KC_AUDIENCE=mcp-server"
set "KC_EXCHANGE_SCOPE=mcp-audience"
python scripts\kc_token_exchange.py || echo [warn] Token exchange configuration failed - see README to configure it manually.
echo     Keycloak configured.

REM ---------------------------------------------------------------------------
REM 3. Deploy EJBCA
REM ---------------------------------------------------------------------------
echo(
echo ==^> Deploying EJBCA (Community) in Docker
docker rm -f %EJBCA_CONTAINER% >nul 2>&1
docker run -d --name %EJBCA_CONTAINER% -p %EJBCA_HTTP_PORT%:8080 -p %EJBCA_HTTPS_PORT%:8443 ^
    -e TLS_SETUP_ENABLED=true %EJBCA_IMAGE% >nul || (echo [error] Failed to start EJBCA. & exit /b 1)

echo     Waiting for EJBCA (first boot can take 1-2 minutes)...
set "EJBCA_READY="
for /l %%i in (1,1,100) do (
    if not defined EJBCA_READY (
        curl -sk https://localhost:%EJBCA_HTTPS_PORT%/ejbca/publicweb/healthcheck/ejbcahealth 2>nul | findstr /i "ALLOK" >nul && set "EJBCA_READY=1"
        if not defined EJBCA_READY ping -n 4 127.0.0.1 >nul
    )
)
if not defined EJBCA_READY echo [warn] EJBCA health check timed out - continuing, EJBCA steps may fail.
echo     EJBCA up at https://localhost:%EJBCA_HTTPS_PORT%/ejbca/

REM Detect CLI path
set "EJBCA_CLI=/opt/keyfactor/bin/ejbca/ejbca.sh"
docker exec %EJBCA_CONTAINER% bash -lc "command -v ejbca.sh" >nul 2>&1 && set "EJBCA_CLI=ejbca.sh"

REM Generate the EJBCA CLI sequence into a temp shell script and run it inside the container.
set "EJBCA_SH=%TEMP%\ejbca_setup.sh"
if exist "%EJBCA_SH%" del "%EJBCA_SH%"
>>"%EJBCA_SH%" echo #!/bin/bash
>>"%EJBCA_SH%" echo CLI="%EJBCA_CLI%"
>>"%EJBCA_SH%" echo PW="$1"
>>"%EJBCA_SH%" echo $CLI ca init "%EJBCA_CA_NAME%" "CN=%EJBCA_CA_NAME%,O=%PROJECT_TAG%,C=US" soft null 2048 RSA 3650 --policy 2.5.29.32.0 SHA256WithRSA ^|^| echo "CA may already exist"
REM Enable Certificate Management REST (disabled by default on CE). The app enrolls
REM user certs via /v1/certificate/pkcs10enroll, which creates+re-enrolls the end
REM entity itself - the End Entity REST API is absent from EJBCA CE.
>>"%EJBCA_SH%" echo $CLI config protocols enable --name "REST Certificate Management" ^|^| echo "REST Certificate Management may already be enabled"
>>"%EJBCA_SH%" echo $CLI ra addendentity --username api-admin --dn "CN=api-admin,O=%PROJECT_TAG%" --caname ManagementCA --type 1 --token P12 --password "$PW" --certprofile ENDUSER --eeprofile EMPTY ^|^| echo "api-admin may already exist"
>>"%EJBCA_SH%" echo $CLI ra setclearpwd api-admin "$PW" ^|^| true
>>"%EJBCA_SH%" echo $CLI roles addrolemember --role "Super Administrator Role" --caname ManagementCA --with CertificateAuthenticationToken:WITH_COMMONNAME --value api-admin ^|^| true
>>"%EJBCA_SH%" echo cd /tmp ^&^& $CLI batch api-admin
>>"%EJBCA_SH%" echo $CLI ca getcacert "%EJBCA_CA_NAME%" /tmp/UserCA.pem ^|^| true

echo ==^> Configuring EJBCA (CA, REST, api-admin cert)
docker cp "%EJBCA_SH%" %EJBCA_CONTAINER%:/tmp/ejbca_setup.sh >nul
docker exec %EJBCA_CONTAINER% bash -lc "tr -d '\r' < /tmp/ejbca_setup.sh > /tmp/ejbca_run.sh && bash /tmp/ejbca_run.sh '%EJBCA_ADMIN_CERT_PASSWORD%'"

REM Copy generated artifacts out (batch writes the keystore to /tmp/p12/ since it runs from /tmp)
docker cp %EJBCA_CONTAINER%:/tmp/p12/api-admin.p12 certs\api-admin.p12 >nul 2>&1 && echo     Copied api-admin.p12 || echo [warn] Could not locate api-admin.p12 in the EJBCA container.
docker cp %EJBCA_CONTAINER%:/tmp/UserCA.pem certs\UserCA.pem >nul 2>&1 && echo     Copied UserCA.pem || echo [warn] Could not export UserCA.pem.

if not exist certs\api-admin.p12 (
    echo [warn] -------------------------------------------------------------------
    echo [warn] EJBCA auto-configuration was only partially successful.
    echo [warn] Check https://localhost:%EJBCA_HTTPS_PORT%/ejbca/adminweb/ and verify CA %EJBCA_CA_NAME%
    echo [warn] exists and certs\api-admin.p12 + certs\UserCA.pem were created. The app uses the
    echo [warn] built-in %EJBCA_CERT_PROFILE% / %EJBCA_END_ENTITY_PROFILE% profiles - no custom profiles needed.
    echo [warn] -------------------------------------------------------------------
)

REM ---------------------------------------------------------------------------
REM 4. AWS - Bedrock check
REM ---------------------------------------------------------------------------
echo(
echo ==^> Checking AWS Bedrock access for Llama 4 Scout
aws bedrock list-foundation-models --region %AWS_REGION% --query "modelSummaries[?contains(modelId,'llama4-scout')].modelId" --output text 2>nul | findstr llama4-scout >nul && (echo     Llama 4 Scout visible in Bedrock.) || (echo [warn] Enable 'Llama 4 Scout 17B Instruct' in Bedrock ^> Model access.)
echo     App will invoke inference profile: %BEDROCK_MODEL_ID%

REM ---------------------------------------------------------------------------
REM 5. AWS - SES sender verification
REM ---------------------------------------------------------------------------
echo(
echo ==^> Verifying SES sender identity %SES_SENDER_EMAIL%
aws sesv2 create-email-identity --email-identity %SES_SENDER_EMAIL% --tags Key=Project,Value=%PROJECT_TAG% --region %AWS_REGION% >nul 2>&1 && (echo     SES verification email sent.) || (echo     SES identity already exists or pending.)
echo [warn] ACTION REQUIRED: click the verification link emailed to %SES_SENDER_EMAIL%.

REM ---------------------------------------------------------------------------
REM 6. AWS - RDS MySQL
REM ---------------------------------------------------------------------------
echo(
echo ==^> Provisioning Amazon RDS MySQL (tagged Project=%PROJECT_TAG%)

REM --- default VPC (capture via temp file to avoid for/f escaping pitfalls) ---
aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId" --output text --region %AWS_REGION% > "%TEMP%\vpc.txt" 2>nul
set "VPC_ID="
set /p VPC_ID=<"%TEMP%\vpc.txt"
del "%TEMP%\vpc.txt" >nul 2>&1
if "%VPC_ID%"=="None" set "VPC_ID="
if not defined VPC_ID (echo [error] No default VPC found in %AWS_REGION%. & exit /b 1)
echo     Default VPC: %VPC_ID%

REM --- security group ---
aws ec2 describe-security-groups --filters "Name=group-name,Values=%RDS_SG_NAME%" "Name=vpc-id,Values=%VPC_ID%" --query "SecurityGroups[0].GroupId" --output text --region %AWS_REGION% > "%TEMP%\sg.txt" 2>nul
set "SG_ID="
set /p SG_ID=<"%TEMP%\sg.txt"
del "%TEMP%\sg.txt" >nul 2>&1
if "%SG_ID%"=="None" set "SG_ID="
if defined SG_ID (
    echo     Reusing security group !SG_ID!
) else (
    aws ec2 create-security-group --group-name %RDS_SG_NAME% --description "tcx RDS MySQL access" --vpc-id %VPC_ID% --region %AWS_REGION% --tag-specifications "ResourceType=security-group,Tags=[{Key=Project,Value=%PROJECT_TAG%}]" --query GroupId --output text > "%TEMP%\sg.txt" 2>nul
    set /p SG_ID=<"%TEMP%\sg.txt"
    del "%TEMP%\sg.txt" >nul 2>&1
    echo     Created security group !SG_ID!
)
if not defined SG_ID (echo [error] Could not create/find the RDS security group. & exit /b 1)

REM --- ingress from this host's public IP ---
set "MY_IP="
curl -s https://checkip.amazonaws.com > "%TEMP%\ip.txt" 2>nul
set /p MY_IP=<"%TEMP%\ip.txt"
del "%TEMP%\ip.txt" >nul 2>&1
aws ec2 authorize-security-group-ingress --group-id !SG_ID! --protocol tcp --port 3306 --cidr !MY_IP!/32 --region %AWS_REGION% >nul 2>&1 && (echo     Authorized 3306 from !MY_IP!/32) || (echo     Ingress rule already present.)

REM --- Public DB subnet group ---
REM A publicly-accessible RDS instance is only reachable if it sits in a subnet
REM whose route table routes 0.0.0.0/0 to an Internet Gateway. The VPC default
REM subnet group may include private subnets (corporate VPCs with a Transit
REM Gateway), so build a group of only IGW-routed subnets (one per AZ). Public
REM subnet discovery is done in PowerShell (route-table walk is painful in cmd).
set "PUBSUB_PS=%TEMP%\pubsubnets.ps1"
if exist "%PUBSUB_PS%" del "%PUBSUB_PS%"
>>"%PUBSUB_PS%" echo param($VpcId,$Region)
>>"%PUBSUB_PS%" echo $subnets = (aws ec2 describe-subnets --region $Region --filters "Name=vpc-id,Values=$VpcId" --query "Subnets[].{Id:SubnetId,Az:AvailabilityZone}" --output json) ^| ConvertFrom-Json
>>"%PUBSUB_PS%" echo $mainRt = aws ec2 describe-route-tables --region $Region --filters "Name=vpc-id,Values=$VpcId" "Name=association.main,Values=true" --query "RouteTables[0].RouteTableId" --output text
>>"%PUBSUB_PS%" echo $seen=@{}; $out=@()
>>"%PUBSUB_PS%" echo foreach ($s in $subnets) {
>>"%PUBSUB_PS%" echo   $rt = aws ec2 describe-route-tables --region $Region --filters "Name=association.subnet-id,Values=$($s.Id)" --query "RouteTables[0].RouteTableId" --output text
>>"%PUBSUB_PS%" echo   if ($rt -eq 'None' -or [string]::IsNullOrWhiteSpace($rt)) { $rt = $mainRt }
>>"%PUBSUB_PS%" echo   $gw = aws ec2 describe-route-tables --region $Region --route-table-ids $rt --query "RouteTables[0].Routes[?DestinationCidrBlock=='0.0.0.0/0'].GatewayId" --output text
>>"%PUBSUB_PS%" echo   if ($gw -match 'igw-' -and -not $seen.ContainsKey($s.Az)) { $seen[$s.Az]=$true; $out += $s.Id }
>>"%PUBSUB_PS%" echo }
>>"%PUBSUB_PS%" echo $out -join ' '
set "PUBLIC_SUBNETS="
for /f "usebackq delims=" %%i in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%PUBSUB_PS%" %VPC_ID% %AWS_REGION%`) do set "PUBLIC_SUBNETS=%%i"
del "%PUBSUB_PS%" >nul 2>&1
if not defined PUBLIC_SUBNETS (echo [error] Could not find public IGW-routed subnets in %VPC_ID%. & exit /b 1)
echo     Public subnets: !PUBLIC_SUBNETS!

aws rds describe-db-subnet-groups --db-subnet-group-name %RDS_SUBNET_GROUP% --region %AWS_REGION% >nul 2>&1
if errorlevel 1 (
    aws rds create-db-subnet-group --db-subnet-group-name %RDS_SUBNET_GROUP% --db-subnet-group-description "tcx public subnets for RDS" --subnet-ids !PUBLIC_SUBNETS! --region %AWS_REGION% --tags Key=Project,Value=%PROJECT_TAG% >nul || (echo [error] Failed to create DB subnet group ^(need public subnets in 2+ AZs^). & exit /b 1)
    echo     Created DB subnet group %RDS_SUBNET_GROUP%
) else (
    echo     Reusing DB subnet group %RDS_SUBNET_GROUP%
)

REM --- DB instance (single-line create; no caret continuation inside blocks) ---
aws rds describe-db-instances --db-instance-identifier %RDS_ID% --region %AWS_REGION% >nul 2>&1
if errorlevel 1 (
    aws rds create-db-instance --db-instance-identifier %RDS_ID% --db-instance-class db.t3.micro --engine mysql --master-username %RDS_USER% --master-user-password %RDS_PASS% --allocated-storage 20 --db-name %RDS_DB% --vpc-security-group-ids !SG_ID! --db-subnet-group-name %RDS_SUBNET_GROUP% --publicly-accessible --backup-retention-period 0 --no-multi-az --storage-encrypted --region %AWS_REGION% --tags Key=Project,Value=%PROJECT_TAG% >nul || (echo [error] RDS creation failed. & exit /b 1)
    echo     RDS creation started ^(~10-15 minutes^)...
) else (
    echo     RDS instance %RDS_ID% already exists - reusing.
)
echo     Waiting for RDS to become available...
aws rds wait db-instance-available --db-instance-identifier %RDS_ID% --region %AWS_REGION%
aws rds describe-db-instances --db-instance-identifier %RDS_ID% --query "DBInstances[0].Endpoint.Address" --output text --region %AWS_REGION% > "%TEMP%\rds.txt" 2>nul
set "RDS_HOST="
set /p RDS_HOST=<"%TEMP%\rds.txt"
del "%TEMP%\rds.txt" >nul 2>&1
echo     RDS endpoint: %RDS_HOST%

REM --- reachability guard: confirm the instance is in a public subnet ---
aws ec2 describe-network-interfaces --region %AWS_REGION% --filters "Name=group-id,Values=!SG_ID!" "Name=description,Values=RDSNetworkInterface" --query "NetworkInterfaces[0].SubnetId" --output text > "%TEMP%\eni.txt" 2>nul
set "RDS_ENI_SUBNET="
set /p RDS_ENI_SUBNET=<"%TEMP%\eni.txt"
del "%TEMP%\eni.txt" >nul 2>&1
echo !PUBLIC_SUBNETS! | findstr /C:"!RDS_ENI_SUBNET!" >nul && (echo     RDS is in public subnet !RDS_ENI_SUBNET!.) || (echo [warn] RDS interface subnet !RDS_ENI_SUBNET! is not a known public subnet - the DB may be unreachable.)

echo ==^> Seeding database schema (mysqldb.users)
set "SEED=%TEMP%\seed_db.py"
if exist "%SEED%" del "%SEED%"
>>"%SEED%" echo import os, pymysql
>>"%SEED%" echo c = pymysql.connect(host=os.environ['RDS_HOST'], user=os.environ['RDS_USER'], password=os.environ['RDS_PASS'], database=os.environ['RDS_DB'], port=3306, connect_timeout=20)
>>"%SEED%" echo cur = c.cursor()
>>"%SEED%" echo cur.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(255), email VARCHAR(255))")
>>"%SEED%" echo cur.execute("INSERT IGNORE INTO users (id,username,email) VALUES (1,'alice','alice@example.com'),(2,'bob','bob@example.com')")
>>"%SEED%" echo c.commit(); c.close(); print("   Seeded users table.")
python "%SEED%" || echo [warn] Seeding failed - seed the users table manually.
del "%SEED%" >nul 2>&1

REM ---------------------------------------------------------------------------
REM 7. Write .env
REM ---------------------------------------------------------------------------
echo(
echo ==^> Writing .env
>.env echo # Generated by setup.bat
>>.env echo AWS_REGION=%AWS_REGION%
>>.env echo BEDROCK_MODEL_ID=%BEDROCK_MODEL_ID%
>>.env echo SES_SENDER_EMAIL=%SES_SENDER_EMAIL%
>>.env echo SES_REGION=%AWS_REGION%
>>.env echo KEYCLOAK_URL=http://localhost:%KEYCLOAK_PORT%
>>.env echo KEYCLOAK_REALM=%KC_REALM%
>>.env echo KEYCLOAK_CLIENT_ID=%KC_CLIENT_ID%
>>.env echo KEYCLOAK_CLIENT_SECRET=%KC_CLIENT_SECRET%
>>.env echo KEYCLOAK_ADMIN_USER=admin
>>.env echo KEYCLOAK_ADMIN_PASSWORD=%KC_ADMIN_PASSWORD%
>>.env echo KEYCLOAK_TOKEN_AUDIENCE=mcp-server
>>.env echo KEYCLOAK_TOKEN_EXCHANGE_SCOPE=mcp-audience
>>.env echo EJBCA_URL=https://localhost:%EJBCA_HTTPS_PORT%
>>.env echo EJBCA_CA_NAME=%EJBCA_CA_NAME%
>>.env echo EJBCA_CERT_PROFILE=%EJBCA_CERT_PROFILE%
>>.env echo EJBCA_END_ENTITY_PROFILE=%EJBCA_END_ENTITY_PROFILE%
>>.env echo EJBCA_API_ADMIN_CERT_PATH=./certs/api-admin.p12
>>.env echo EJBCA_API_ADMIN_CERT_PASSWORD=%EJBCA_ADMIN_CERT_PASSWORD%
>>.env echo CERT_VALIDITY_DAYS=7
>>.env echo RDS_HOST=%RDS_HOST%
>>.env echo RDS_PORT=3306
>>.env echo RDS_USER=%RDS_USER%
>>.env echo RDS_PASS=%RDS_PASS%
>>.env echo RDS_DB=%RDS_DB%
>>.env echo APP_SECRET_KEY=%APP_SECRET_KEY%
echo     .env written.

echo(
echo ==^> Setup complete
echo     Keycloak : http://localhost:%KEYCLOAK_PORT%  (admin / %KC_ADMIN_PASSWORD%)
echo     EJBCA    : https://localhost:%EJBCA_HTTPS_PORT%/ejbca/
echo     RDS      : %RDS_HOST%
echo     Demo user: %KC_DEMO_USER% / %KC_DEMO_PASSWORD%  (realm %KC_REALM%)
echo(
echo     Remaining manual actions:
echo       - Click the SES verification link emailed to %SES_SENDER_EMAIL%
echo       - Ensure Bedrock model access for Llama 4 Scout is enabled
echo(
echo     Launch the app:  run.bat   (then open http://localhost:8501)
echo     Tear down:       cleanup.bat
endlocal
