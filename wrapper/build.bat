cl /O2 /MT /DUNICODE /D_UNICODE /I7z wrapper.c ^
  7z\7zAlloc.c 7z\7zArcIn.c 7z\7zBuf.c 7z\7zCrc.c 7z\7zCrcOpt.c 7z\7zDec.c ^
  7z\7zStream.c ^
  7z\CpuArch.c 7z\Bra.c 7z\Bra86.c 7z\Bcj2.c 7z\Delta.c ^
  7z\LzmaDec.c 7z\Lzma2Dec.c ^
  /link /SUBSYSTEM:CONSOLE Shlwapi.lib Shell32.lib Ole32.lib User32.lib