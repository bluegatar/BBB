@echo off
REM ============================================================
REM  组装"绿色版整包" metasec-portable/ 并打成 metasec-portable.zip
REM
REM  用法：
REM     build-portable.bat "C:\path\to\jdk8\jre"
REM
REM  参数 1 = 一个 JDK8 的 jre 目录(会被整目录拷进 metasec-portable\jre)。
REM           例如  "C:\Program Files\Eclipse Adoptium\jdk-8.0.472.8-hotspot\jre"
REM
REM  前置：在本仓库根执行；full\MetasecDump-obf.jar 已由 ZKM 生成
REM        (见 full\zkm\run-zkm.bat)，且 full\deps、full\libs 就位。
REM ============================================================
setlocal
set JRE_SRC=%~1
if "%JRE_SRC%"=="" (
  echo [ERR] 需要传入 JDK8 的 jre 目录作为参数 1
  echo       例: build-portable.bat "C:\Program Files\Eclipse Adoptium\jdk-8.0.472.8-hotspot\jre"
  exit /b 1
)

set ROOT=%~dp0..
set OUT=%~dp0metasec-portable

echo [*] 清理旧目录 ...
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%"
mkdir "%OUT%\libs"

echo [*] 拷入内置 JRE: %JRE_SRC%
xcopy /e /i /q "%JRE_SRC%" "%OUT%\jre" >nul

echo [*] 拷入 deps / libs / 混淆 jar ...
xcopy /e /i /q "%ROOT%\full\deps" "%OUT%\deps" >nul
copy /y "%ROOT%\full\libs\libmetasec_ml.so" "%OUT%\libs\" >nul
copy /y "%ROOT%\full\MetasecDump-obf.jar" "%OUT%\" >nul

echo [*] 拷入 run.py / README / requirements ...
copy /y "%~dp0metasec-portable-src\run.py" "%OUT%\" >nul
copy /y "%~dp0metasec-portable-src\README.txt" "%OUT%\" >nul
copy /y "%~dp0metasec-portable-src\requirements.txt" "%OUT%\" >nul

echo [*] 打 zip ...
if exist "%~dp0metasec-portable.zip" del /q "%~dp0metasec-portable.zip"
powershell -NoProfile -Command "Compress-Archive -Path '%OUT%' -DestinationPath '%~dp0metasec-portable.zip' -Force"

echo [+] done: %~dp0metasec-portable.zip
endlocal
