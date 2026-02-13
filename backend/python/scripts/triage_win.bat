@echo off
REM Windows Triage Script for Better Call Chadi
REM Collects Process List, Network Connections, and Autoruns

set OUTFILE=triage_data.txt
echo [START] Windows Triage > %OUTFILE%
date /t >> %OUTFILE%
time /t >> %OUTFILE%

echo. >> %OUTFILE%
echo [SYSTEM INFO] >> %OUTFILE%
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> %OUTFILE%
whoami >> %OUTFILE%

echo. >> %OUTFILE%
echo [PROCESS LIST] >> %OUTFILE%
tasklist /v >> %OUTFILE%

echo. >> %OUTFILE%
echo [NETWORK CONNECTIONS] >> %OUTFILE%
netstat -ano >> %OUTFILE%

echo. >> %OUTFILE%
echo [AUTORUNS - REGISTRY] >> %OUTFILE%
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run >> %OUTFILE%
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run >> %OUTFILE%

echo. >> %OUTFILE%
echo [END] >> %OUTFILE%

echo Triage Complete. Upload %OUTFILE% to the Dashboard.
