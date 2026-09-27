@echo off
rem Double-click to start LeakCheck. Close this window to stop it.
rem The first run sets up a private Python environment in .venv; that one
rem step downloads dependencies. After that, nothing is downloaded.
setlocal
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && py -3 -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>nul && set "PY=py -3"
if not defined PY (
  where python >nul 2>nul && python -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo LeakCheck needs Python 3.11 or newer. Install it from python.org, then run this again.
  pause
  exit /b 1
)

rem (Re)install only when requirements.txt changed since the last setup.
fc /b requirements.txt .venv\.leakcheck-installed >nul 2>nul
if errorlevel 1 (
  echo Setting up LeakCheck ^(first run only; needs internet^)...
  %PY% -m venv .venv || goto :fail
  .venv\Scripts\python -m pip install --quiet --disable-pip-version-check -r requirements.txt || goto :fail
  copy /y requirements.txt .venv\.leakcheck-installed >nul
)

.venv\Scripts\python -m leakcheck open
if errorlevel 1 goto :fail
exit /b 0

:fail
echo.
echo Something went wrong (see above).
pause
exit /b 1
