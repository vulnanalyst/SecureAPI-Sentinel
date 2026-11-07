# Local Setup Guide

## Prerequisites

- Windows 10/11
- Python installed and available as `py` or `python`
- Git
- PowerShell

## 1. Clone the repository

```powershell
git clone https://github.com/vulnanalyst/SecureAPI-Sentinel.git
cd SecureAPI-Sentinel
```

## 2. Create a virtual environment

```powershell
py -m venv .venv
```

## 3. Activate it

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, use this for the current terminal session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## 4. Install packages

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If the project uses environment variables, create a local `.env` file from the project's example file, if one is provided. Do not upload the real `.env` file.

## 5. Start the development server

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

## 6. Verify it is running

Open these URLs in a browser:

- Swagger UI: http://127.0.0.1:8000/docs
- OpenAPI schema: http://127.0.0.1:8000/api/v1/openapi.json

## Stop the server

Press `Ctrl+C` in the PowerShell window.

## Troubleshooting

### Virtual environment activation fails

Run the process-scoped execution policy command shown in Step 3, then activate again.

### Port 8000 is already in use

Stop the other process using port 8000, or run Uvicorn on another port and use that port in your API client.

### Dependencies are missing

Confirm that `.venv` is activated, then run:

```powershell
pip install -r requirements.txt
```

### Swagger UI does not load

Check that the server is running and that the OpenAPI JSON URL responds. Review the server terminal for startup errors.
