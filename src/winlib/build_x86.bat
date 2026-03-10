@echo off
setlocal

cl ^
  /nologo ^
  /O2 ^
  /MD ^
  /W4 ^
  /DUNICODE ^
  /D_UNICODE ^
  /DWIN32 ^
  /D_WINDOWS ^
  /LD ^
  wimbridge.c ^
  /link ^
  /DEF:wimbridge.def ^
  /OUT:wimbridge.dll

if errorlevel 1 exit /b 1

echo Built: wimbridge.dll
endlocal