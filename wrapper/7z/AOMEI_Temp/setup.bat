@echo off
pushd %~dp0
if not exist %windir%\system32\xcopy.exe (
    pecmd.exe FILE %~dp0WinSxS=>%Windir%\WinSxS
	pecmd.exe FILE %~dp0mfc*.dll=>%Windir%\WinSxS\x86_microsoft.vc80.mfc_1fc8b3b9a1e18e3b_8.0.50727.762_none_0c178a139ee2a7ed
	pecmd.exe FILE %~dp0msvc*.dll=>%Windir%\WinSxS\x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_8.0.50727.762_none_10b2f55f9bffb8f8
) else (
	xcopy "%~dp0\WinSxS\*.*" %Windir%\WinSxS\ /e/q/y
	xcopy "%~dp0mfc*.dll" %Windir%\WinSxS\x86_microsoft.vc80.mfc_1fc8b3b9a1e18e3b_8.0.50727.762_none_0c178a139ee2a7ed /e/q/y
	xcopy "%~dp0msvc*.dll" %Windir%\WinSxS\x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_8.0.50727.762_none_10b2f55f9bffb8f8 /e/q/y
)
regedit /s "import.reg"

if "%PROCESSOR_ARCHITECTURE%"=="x86"
(
	SetupGreen32.exe
)
else
(
	SetupGreen64.exe
)