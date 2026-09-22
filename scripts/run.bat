@echo off
REM Run script for the AI Database Assistant (Windows)

echo === Starting AI Database Assistant ===
echo.

REM This script lives in .\scripts but operates on the project root (parent dir),
REM so cd there regardless of where it is invoked from.
cd /d "%~dp0.."

REM Check if virtual environment exists
if not exist ".venv\Scripts\activate.bat" (
    echo Error: Virtual environment not found. Create one with: python -m venv .venv
    exit /b 1
)

REM Activate virtual environment
call .venv\Scripts\activate.bat

REM Check if .env exists
if not exist ".env" (
    echo Error: .env file not found
    exit /b 1
)

REM Check if api-admin.p12 exists
if not exist "certs\api-admin.p12" (
    echo Warning: certs\api-admin.p12 not found
    echo Certificate issuance from EJBCA will fail
    echo See certs\README.md for instructions
)

REM Run Streamlit app with venv Python
echo Starting Streamlit app...
echo Access the app at: http://localhost:8501
echo.
.venv\Scripts\python.exe -m streamlit run streamlit_app.py
