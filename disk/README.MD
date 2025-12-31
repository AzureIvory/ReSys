cl /EHsc /LD /D_WIN32_DCOM /DUNICODE /D_UNICODE /D_WINVER=0x0601 /D_WIN32_WINNT=0x0601 disk.cpp ^
  /link /DEF:disk.def ole32.lib uuid.lib /out:disk.dll
