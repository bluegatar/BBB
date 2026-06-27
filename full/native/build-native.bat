@echo off
REM ============================================================================
REM Build a GraalVM Native Image (exe) of MetasecDump.
REM Requires: GraalVM CE java8 21.3.1 with native-image, and MSVC C++ build tools.
REM Run from full\ : native\build-native.bat
REM ============================================================================
setlocal

set GRAALVM=C:\Users\Administrator\tools\graalvm-ce-java8-21.3.1
set NI=%GRAALVM%\bin\native-image.cmd

REM --- load MSVC x64 environment (cl.exe / link.exe / Windows SDK) ---
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" (
  echo ERROR: vcvars64.bat not found at "%VCVARS%"
  exit /b 1
)
call "%VCVARS%"

cd /d "%~dp0\.."

set CP=build;deps/*

"%NI%" ^
  -cp "%CP%" ^
  -H:ConfigurationFileDirectories=native/config,native/config-extra,native/config-jna ^
  -H:Name=metasecdump ^
  -H:Path=native ^
  --no-fallback ^
  --allow-incomplete-classpath ^
  --report-unsupported-elements-at-runtime ^
  -H:+ReportExceptionStackTraces ^
  --initialize-at-run-time=com.sun.jna ^
  -Dunidbg.tgkill.drop=true ^
  MetasecDump

echo NATIVE_IMAGE_EXIT=%errorlevel%
endlocal
