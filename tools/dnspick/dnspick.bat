@echo off
rem dnspick launcher: double-click to run, pick a mode, then pick the egress adapter.
rem This file is deliberately ASCII-only and does NOT call chcp: changing the code page
rem inside a batch file corrupts cmd's parsing of the remaining lines when the file holds
rem non-ASCII text. dnspick.exe sets the console to UTF-8 itself, so its Chinese output
rem still renders correctly.
rem For scripted use call the exe directly, e.g. dnspick.exe --full --interface "WLAN"
setlocal
cd /d "%~dp0"

if not exist dnspick.exe (
	echo [ERROR] dnspick.exe not found in this folder.
	echo         Build it first:  go build -o dnspick.exe ./cmd/dnspick
	echo.
	pause
	exit /b 1
)

cls
echo ============================================
echo   dnspick - local broadband DNS picker
echo ============================================
echo.
echo   1) Quick mode       (~1 min, asks which adapter to use)
echo   2) Full mode        (~6 min: + recursion / poisoning / ECS / TTFB)
echo   3) List adapters    (which NICs exist and what DNS each one has)
echo   4) Quick, CN DNS    (China public resolvers only)
echo   5) Exit
echo.
set "choice="
set /p "choice=Enter a number and press Enter [1]: "
if "%choice%"=="" set "choice=1"

if "%choice%"=="1" goto quick
if "%choice%"=="2" goto full
if "%choice%"=="3" goto listif
if "%choice%"=="4" goto cn
if "%choice%"=="5" goto end

echo.
echo [WARN] No such option: "%choice%"
echo.
pause
exit /b 1

:quick
rem No --interface here on purpose: the exe asks in the terminal when one is not given.
dnspick.exe
goto done

:full
dnspick.exe --full
goto done

:listif
dnspick.exe --list-interfaces
goto done

:cn
dnspick.exe --servers 223.5.5.5,223.6.6.6,119.29.29.29,119.28.28.28,114.114.114.114,180.76.76.76
goto done

:done
echo.
echo ============================================
echo Done. Result files: dnspick-result-*.txt in this folder.
echo Run dnspick.bat again for another test.
echo ============================================
echo.
pause
goto end

:end
endlocal
exit /b 0
