@echo off
REM 用法： run-zkm.bat  "C:\path\to\ZKM.jar"
REM 在 full\ 目录下用 ZKM 混淆 MetasecDump.jar -> MetasecDump-obf.jar
setlocal
if "%~1"=="" (
    echo 用法: run-zkm.bat "C:\path\to\ZKM.jar"
    exit /b 1
)
set ZKM=%~1
cd /d "%~dp0\.."

REM 1) 先打成 jar
call zkm\make-jar.bat || exit /b 1

REM 2) 跑 ZKM 脚本（注意：用 JDK8 跑 ZKM 最稳，与目标字节码版本一致）
echo [run-zkm] java -jar "%ZKM%" zkm\script.zkm
java -jar "%ZKM%" zkm\script.zkm
if errorlevel 1 (
    echo [run-zkm] ZKM 失败，请看上面的报错（多半是 rt.jar 路径要改、或某个 classpath 缺失）。
    exit /b 1
)
echo [run-zkm] 完成 -> MetasecDump-obf.jar
endlocal
