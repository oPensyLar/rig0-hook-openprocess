#include "stdafx.h"

typedef NTSTATUS (*QUERY_INFO_PROCESS) (
__in HANDLE ProcessHandle,
__in PROCESSINFOCLASS ProcessInformationClass,
__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
__in ULONG ProcessInformationLength,
__out_opt PULONG ReturnLength
);

QUERY_INFO_PROCESS ZwQueryInformationProcess;


#define OFFSET_PROCSLINKS_WIN7_X64 0x188
#define OFFSET_PROCPID_WIN7_X64 0x180

#define OFFSET_PROCSLINKS_WIN7_X86 0xb8
#define OFFSET_PROCPID_WIN7_X86 0xb4

#define OFFSET_PROCSLINKS_WIN10_X86 0x188
#define OFFSET_PROCPID_WIN10_X86 0x180

#define OFFSET_PROCSLINKS_WIN10_X64 0x188
#define OFFSET_PROCPID_WIN10_X64 0x180


BOOLEAN GetProcessName(unsigned int procId);
unsigned long FindProcess(unsigned int targetPid);
BOOLEAN ListProcess();

;