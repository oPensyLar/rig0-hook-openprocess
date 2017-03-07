#include "stdafx.h"

//TypeDef
typedef struct ServiceDescriptorEntry
{
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;

} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

 
typedef NTSTATUS (*TypZwOpenProc)(OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL);
TypZwOpenProc ZwOpenProcessIni;



//declspec
__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
 





//Macros
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]

 
#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
 


#define HOOK_SYSCALL(_Function, _Hook, _Orig )  \
_Orig = (PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)
 


#define UNHOOK_SYSCALL(_Function, _Hook, _Orig ) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)
 





//Variables
typedef DWORD (ULONG);
PMDL  g_pmdlSystemCall;
PVOID *MappedSystemCallTable;





//Declaracion de funciones


//Declaramos la API para poder trabajar con ella.
NTSYSAPI NTSTATUS NTAPI ZwOpenProcess (OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL);
 


NTSTATUS Unhookear();
NTSTATUS Hookear();
