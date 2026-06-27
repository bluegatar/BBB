@echo off
REM 验证混淆后的 jar 仍能正常产出 6 个签名头。
REM 用法： verify.bat "C:\path\to\jdk8\bin"
setlocal
if "%~1"=="" ( set JBIN=java ) else ( set JBIN=%~1\java.exe )
cd /d "%~dp0\.."
echo [verify] 用混淆后的 MetasecDump-obf.jar 跑一次（dynarmic 后端, pump=2s）...
"%JBIN%" -Dbackend=dynarmic -Dpump.seconds=2 -Dunidbg.tgkill.drop=true ^
    -cp "MetasecDump-obf.jar;deps/*" MetasecDump
echo.
echo [verify] 如果上面打印了 X-Argus/X-Gorgon/X-Helios/X-Khronos/X-Ladon/X-Medusa
echo          和 __HEADERS_JSON__，说明混淆后功能正常。
endlocal
