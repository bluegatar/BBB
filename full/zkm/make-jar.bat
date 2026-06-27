@echo off
REM 把已编译的 MetasecDump 类（build\MetasecDump.class + build\MetasecDump$*.class）
REM 打包成待混淆的 MetasecDump.jar，放在 full\ 下。
setlocal
cd /d "%~dp0\.."
if not exist build\MetasecDump.class (
    echo [make-jar] 没找到 build\MetasecDump.class，请先用 JDK8 编译 MetasecDump。
    exit /b 1
)
jar cf MetasecDump.jar -C build .
echo [make-jar] 生成 MetasecDump.jar:
jar tf MetasecDump.jar
endlocal
