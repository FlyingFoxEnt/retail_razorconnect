@echo off
rem Builds pa_capture.exe next to this file (the interop assembly is copied beside it).
setlocal
set TM=C:\Program Files (x86)\SCE\PSP2\Tools\Target Manager Server\bin
copy /y "%TM%\Interop.PSP2TMAPILib.dll" "%~dp0" >nul
"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /o+ /out:"%~dp0pa_capture.exe" /r:"%~dp0Interop.PSP2TMAPILib.dll" "%~dp0pa_capture.cs"
