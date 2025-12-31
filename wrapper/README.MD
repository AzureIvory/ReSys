rc payload.rc

cl /nologo /O1 /GS- /DNDEBUG /utf-8 wrapper.c payload.res ^
  /link /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF user32.lib shell32.lib shlwapi.lib
