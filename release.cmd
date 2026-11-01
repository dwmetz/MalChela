@echo off
rem MalChela release build (Windows, cmd wrapper for release.ps1)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0release.ps1" %*
