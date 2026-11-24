@echo off
rem Chuot phai file nay -> Run as administrator
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-controller.ps1"
