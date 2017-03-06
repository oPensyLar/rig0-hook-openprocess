#include "stdafx.h"

typedef NTSTATUS (*QUERY_INFO_PROCESS) (
__in HANDLE ProcessHandle,
__in PROCESSINFOCLASS ProcessInformationClass,
__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
__in ULONG ProcessInformationLength,
__out_opt PULONG ReturnLength
);

QUERY_INFO_PROCESS ZwQueryInformationProcess;

BOOLEAN GetProcessName(unsigned int procId);
unsigned long FindProcess(unsigned int targetPid);
BOOLEAN ListProcess();

;