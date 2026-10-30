
@echo off
cd /d "%~dp0"

call .venv\Scripts\activate.bat

set "FLASK_SECRET_KEY=6f761dcaf831c9dc016a83d67a04bd48eebb58b9e52cefceae06a79d9afe5386"
set "ADMIN_USERNAME=admin"
set "ADMIN_PASSWORD=123AAA321"

python app.py

pause
