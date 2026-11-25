@echo off
setlocal
cd /d "%~dp0"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" exit /b 1
for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -property installationPath`) do set "VS=%%I"
if not defined VS exit /b 1
call "%VS%\Common7\Tools\VsDevCmd.bat" -arch=amd64 -winsdk=10.0.28000.0 >nul
if errorlevel 1 exit /b 1
set "KIT=C:\Program Files (x86)\Windows Kits\10"
set "INCLUDE=%KIT%\Include\10.0.28000.0\km;%KIT%\Include\10.0.28000.0\shared;%KIT%\Include\10.0.28000.0\ucrt;%INCLUDE%"
set "LIB=%KIT%\Lib\10.0.28000.0\km\x64;%LIB%"
if not exist out mkdir out

cl /nologo /W4 /WX /O2 /kernel /GS- /D_AMD64_ /DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00 /Idriver /c /Fo:out\svm_probe.obj driver\svm_probe.c
if errorlevel 1 exit /b 1
cl /nologo /W4 /WX /O2 /kernel /GS- /D_AMD64_ /DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00 /Idriver /c /Fo:out\svm_run.obj driver\svm_run.c
if errorlevel 1 exit /b 1
ml64 /nologo /c /Foout\svm_enter.obj driver\svm_enter.asm
if errorlevel 1 exit /b 1
ml64 /nologo /c /Foout\svmctl_guest.obj lab\svmctl_guest.asm
if errorlevel 1 exit /b 1
link /nologo /driver /subsystem:native /entry:DriverEntry /machine:x64 /map:out\svm_probe.map /out:out\svm_probe.sys out\svm_probe.obj out\svm_run.obj out\svm_enter.obj ntoskrnl.lib hal.lib
if errorlevel 1 exit /b 1

cl /nologo /W4 /WX /O2 /Idriver /Ilab /Fo:out\svmctl.obj /Fe:out\svmctl.exe lab\svmctl.c out\svmctl_guest.obj /link /INCREMENTAL:NO
if errorlevel 1 exit /b 1
cl /nologo /W4 /WX /O2 /Idriver /Ilab /Fo:out\svm_open_worker.obj /Fe:out\svm_open_worker.exe lab\svm_open_worker.c /link /INCREMENTAL:NO
if errorlevel 1 exit /b 1
cl /nologo /W4 /WX /O2 /Idriver /Ilab /Fo:out\svm_open_demo.obj /Fe:out\svm_open_demo.exe lab\svm_open_demo.c out\svmctl_guest.obj /link /INCREMENTAL:NO
if errorlevel 1 exit /b 1
cl /nologo /W4 /WX /O2 /DUNICODE /D_UNICODE /Fo:out\ntopen_probe.obj /Fe:out\ntopen_probe.exe lab\ntopen_probe.c /link /INCREMENTAL:NO
exit /b %errorlevel%
