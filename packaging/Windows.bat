@echo off
setlocal
set "DA_DIR=%LOCALAPPDATA%\Microsoft\WindowsApps"
set "DA_EXE=%DA_DIR%\archaeologist.exe"
if not exist "%DA_DIR%" mkdir "%DA_DIR%"
if not exist "%~dp0archaeologist-windows.exe" (
  echo Place archaeologist-windows.exe beside this installer first.
  exit /b 1
)
copy /Y "%~dp0archaeologist-windows.exe" "%DA_EXE%" >nul
echo Digital Archaeologist installed to %DA_EXE%
echo Open a new terminal and run: archaeologist --help
