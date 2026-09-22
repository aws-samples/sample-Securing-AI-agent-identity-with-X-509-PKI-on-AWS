@echo off
REM ===========================================================================
REM  cleanup.bat
REM    - Removes Keycloak and EJBCA Docker containers
REM    - Deletes AWS RDS instance + security group
REM    - Deletes SES sender identity
REM    - Deletes all mcp/* secrets in Secrets Manager
REM    - Removes generated certs
REM  Only AWS resources for this project (Project=tcx) are touched.
REM
REM  Usage: cleanup.bat [-y]   (-y skips the confirmation prompt)
REM ===========================================================================
setlocal enabledelayedexpansion

set "PROJECT_TAG=tcx"
set "AWS_REGION=us-east-2"
set "SES_SENDER_EMAIL=user@example.com"
set "KEYCLOAK_CONTAINER=tcx-keycloak"
set "EJBCA_CONTAINER=tcx-ejbca"
set "RDS_ID=tcx-mysql"
set "RDS_SG_NAME=tcx-rds-sg"
set "RDS_SUBNET_GROUP=tcx-public"

REM This script lives in .\scripts but operates on the project root (parent dir),
REM so cd there regardless of where it is invoked from.
cd /d "%~dp0.."

if /i "%~1"=="-y"    goto :confirmed
if /i "%~1"=="--yes" goto :confirmed
echo This will DELETE the Docker containers and AWS resources tagged Project=%PROJECT_TAG% (RDS, SES, secrets).
set /p "ANS=Continue? [y/N] "
if /i not "!ANS!"=="y" if /i not "!ANS!"=="yes" (echo Aborted. & exit /b 0)
:confirmed

echo(
echo ==^> Removing Docker containers
for %%C in (%KEYCLOAK_CONTAINER% %EJBCA_CONTAINER%) do (
    docker rm -f %%C >nul 2>&1 && echo     Removed %%C || echo     %%C not present.
)

echo(
echo ==^> Deleting RDS instance %RDS_ID%
aws rds describe-db-instances --db-instance-identifier %RDS_ID% --region %AWS_REGION% >nul 2>&1
if errorlevel 1 (
    echo     RDS instance not found.
) else (
    aws rds delete-db-instance --db-instance-identifier %RDS_ID% --skip-final-snapshot --delete-automated-backups --region %AWS_REGION% >nul
    echo     Deletion requested; waiting for full deletion...
    aws rds wait db-instance-deleted --db-instance-identifier %RDS_ID% --region %AWS_REGION% && echo     RDS deleted. || echo [warn] Timed out waiting for RDS deletion.
)

echo(
echo ==^> Deleting DB subnet group %RDS_SUBNET_GROUP%
aws rds describe-db-subnet-groups --db-subnet-group-name %RDS_SUBNET_GROUP% --region %AWS_REGION% >nul 2>&1
if errorlevel 1 (
    echo     DB subnet group not found.
) else (
    set "SUBGRP_DONE="
    for /l %%a in (1,1,10) do (
        if not defined SUBGRP_DONE (
            aws rds delete-db-subnet-group --db-subnet-group-name %RDS_SUBNET_GROUP% --region %AWS_REGION% >nul 2>&1 && set "SUBGRP_DONE=1"
            if defined SUBGRP_DONE (echo     Deleted DB subnet group %RDS_SUBNET_GROUP%) else (echo     Still in use, retrying ^(%%a/10^)... & ping -n 16 127.0.0.1 >nul)
        )
    )
    if not defined SUBGRP_DONE echo [warn] Could not delete %RDS_SUBNET_GROUP% - delete it manually once RDS ENIs are released.
)

echo(
echo ==^> Deleting security group %RDS_SG_NAME%
aws ec2 describe-security-groups --filters "Name=group-name,Values=%RDS_SG_NAME%" --query "SecurityGroups[0].GroupId" --output text --region %AWS_REGION% > "%TEMP%\sg.txt" 2>nul
set "SG_ID="
set /p SG_ID=<"%TEMP%\sg.txt"
del "%TEMP%\sg.txt" >nul 2>&1
if "%SG_ID%"=="None" set "SG_ID="
if defined SG_ID (
    set "SG_DONE="
    for /l %%a in (1,1,10) do (
        if not defined SG_DONE (
            aws ec2 delete-security-group --group-id !SG_ID! --region %AWS_REGION% >nul 2>&1 && set "SG_DONE=1"
            if defined SG_DONE (echo     Deleted security group !SG_ID!) else (echo     Still in use, retrying ^(%%a/10^)... & ping -n 16 127.0.0.1 >nul)
        )
    )
    if not defined SG_DONE echo [warn] Could not delete %RDS_SG_NAME% - delete it manually once RDS ENIs are released.
) else (
    echo     Security group not found.
)

echo(
echo ==^> Deleting SES sender identity %SES_SENDER_EMAIL%
aws sesv2 delete-email-identity --email-identity %SES_SENDER_EMAIL% --region %AWS_REGION% >nul 2>&1 && echo     Deleted SES identity. || echo     SES identity not found.

echo(
echo ==^> Deleting Secrets Manager secrets under mcp/*
aws secretsmanager list-secrets --region %AWS_REGION% --query "SecretList[?starts_with(Name, 'mcp/')].Name" --output text > "%TEMP%\secrets.txt" 2>nul
set "SECRETS="
set /p SECRETS=<"%TEMP%\secrets.txt"
del "%TEMP%\secrets.txt" >nul 2>&1
if defined SECRETS (
    for %%n in (%SECRETS%) do aws secretsmanager delete-secret --secret-id %%n --force-delete-without-recovery --region %AWS_REGION% >nul 2>&1 && echo     Deleted secret %%n
) else (
    echo     No mcp/* secrets found.
)

echo(
echo ==^> Removing generated certificates
del /q certs\api-admin.p12 certs\UserCA.pem >nul 2>&1
echo     Done.

echo(
echo ==^> Cleanup complete
echo     Note: .venv and .env were left in place. Remove them manually if desired.
endlocal
