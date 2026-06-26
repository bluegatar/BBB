@echo off
REM Compile + run the metasec unidbg harness (Windows).
REM Edit UNIDBG_DIR and JAVA8 below for your machine.
setlocal enabledelayedexpansion

REM --- configure these ---
if "%UNIDBG_DIR%"=="" set UNIDBG_DIR=C:\unidbg
if "%JAVA8%"=="" set JAVA8=C:\Program Files\Java\jdk1.8.0_xxx\bin
REM -----------------------

cd /d "%~dp0"

if not exist "libs\libmetasec_ml.so" (
  echo ERROR: put libmetasec_ml.so ^(arm64-v8a^) into %cd%\libs\
  exit /b 1
)

REM Locate the unidbg-android jar (skip sources/javadoc jars).
set UA_JAR=
for %%f in ("%UNIDBG_DIR%\unidbg-android\target\unidbg-android-*.jar") do (
  echo %%~nxf | findstr /i "sources javadoc" >nul || set UA_JAR=%%f
)
if "%UA_JAR%"=="" (
  echo ERROR: unidbg-android jar not found. Build unidbg first:
  echo   cd /d "%UNIDBG_DIR%" ^&^& mvnw.cmd -pl unidbg-android -am install -DskipTests
  exit /b 1
)

REM Build classpath: unidbg-android jar + all its maven deps.
pushd "%UNIDBG_DIR%"
call mvnw.cmd -q -pl unidbg-android dependency:build-classpath -Dmdep.outputFile=%TEMP%\cp.txt
popd
set /p DEPS=<"%TEMP%\cp.txt"
set CP=%UA_JAR%;%DEPS%

if not exist build mkdir build
"%JAVA8%\javac" -cp "%CP%" -d build src\MetasecDump.java
if errorlevel 1 exit /b 1

set TIMEPROP=
if not "%FAKE_TIME%"=="" set TIMEPROP=-Dunidbg.fake.time.ms=%FAKE_TIME%

"%JAVA8%\java" -Dunidbg.tgkill.drop=true %TIMEPROP% %JVM_OPTS% -cp "build;%CP%" MetasecDump %*
endlocal
