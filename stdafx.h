// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include <ntifs.h>


#define OFFSET_PROCSLINKS_WIN7_X64 0x188
#define OFFSET_PROCPID_WIN7_X64 0x180

#define OFFSET_PROCSLINKS_WIN7_X86 0xb8
#define OFFSET_PROCPID_WIN7_X86 0xb4

#define OFFSET_PROCSLINKS_WIN10_X86 0x188
#define OFFSET_PROCPID_WIN10_X86 0x180

#define OFFSET_PROCSLINKS_WIN10_X64 0x188
#define OFFSET_PROCPID_WIN10_X64 0x180

#define PATHDEVICEDRIVER L"\\device\\bppassdriver7"
#define PATHDEVICEDRIVERLINK L"\\??\\bppassdriver7"
