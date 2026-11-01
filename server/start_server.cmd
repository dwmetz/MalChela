@echo off
rem MalChela Server Launcher (Windows, cmd wrapper for start_server.ps1)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_server.ps1" %*
