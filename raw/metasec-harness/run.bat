@echo off
REM ===================================================================
REM  Self-contained metasec unidbg harness (Windows).
REM  All unidbg jars are bundled in deps\ -- no maven / internet needed.
REM  Only requirement: JDK 8 (set JAVA8 below or put java.exe on PATH).
REM ===================================================================
setlocal enabledelayedexpansion

REM --- JDK 8 location. If `java` is already JDK8 on PATH, leave blank. ---
if "%JAVA8%"=="" set JAVA8=C:\Program Files\Java\jdk1.8.0_xxx\bin
REM ----------------------------------------------------------------------

cd /d "%~dp0"

set JAVAC="%JAVA8%\javac"
set JAVA="%JAVA8%\java"
if not exist "%JAVA8%\java.exe" (
  REM fall back to java on PATH
  set JAVAC=javac
  set JAVA=java
)

if not exist "libs\libmetasec_ml.so" (
  echo ERROR: missing libs\libmetasec_ml.so ^(arm64-v8a^)
  exit /b 1
)

REM classpath = every jar in deps\  (Java expands the trailing \* )
set CP=deps\*

if not exist build mkdir build
%JAVAC% -encoding UTF-8 -cp "%CP%" -d build src\MetasecDump.java
if errorlevel 1 exit /b 1

set TIMEPROP=
if not "%FAKE_TIME%"=="" set TIMEPROP=-Dunidbg.fake.time.ms=%FAKE_TIME%

%JAVA% -Dunidbg.tgkill.drop=true %TIMEPROP% %JVM_OPTS% -cp "build;%CP%" MetasecDump %*
endlocal
