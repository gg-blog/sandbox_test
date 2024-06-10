@echo off
setlocal enabledelayedexpansion

:: Get the current time
for /f "tokens=1-4 delims=:.," %%a in ("%time%") do (
    set /a HH=%%a, MM=%%b, SS=%%c, FF=%%d
)

:: Add 10 seconds
set /a MM+=1
if !MM! geq 60 (
    set /a MM-=60
    set /a HH+=1
    if !HH! geq 24 set /a HH-=24
)

:: Format the time with leading zeros
if !HH! lss 10 set HH=0!HH!
if !MM! lss 10 set MM=0!MM!
echo !HH!:!MM!
:: Create the scheduled task
schtasks /create /tn "MyTask" /tr "notepad.exe" /sc once /st !HH!:!MM! /f
