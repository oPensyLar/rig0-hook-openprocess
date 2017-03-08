#include "stdafx.h"

//TypeDef
typedef struct ServiceDescriptorEntry
{
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;

} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;


//Declaracion original
//NTSYSAPI NTSTATUS NTAPI ZwOpenProcess (OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL);

//Tipo de dato
//typedef NTSTATUS (*TypZwOpenProc)(OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL); TypZwOpenProc ZwOpenProcessIni;


typedef WINBASEAPI __out_opt HINSTANCE WINAPI  (*TypLoadLibr) (IN LPCWSTR lpLibFileName); TypLoadLibr LoadLibrayIni;






//Definicion de variable
//TypLoadLibr ZwOpenProcessIni;
TypLoadLibr LoadLibrayIni;



//declspec
__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
 





//Macros
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]

 
#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
 

//HOOK_SYSCALL(API, NuestraFuncion, Direccióninicial);
#define HOOK_SYSCALL(_Function, _Hook, _Orig )  \
_Orig = (PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)
 

//UNHOOK_SYSCALL(API, NuestraFuncion, Direccióninicial);
#define UNHOOK_SYSCALL(_Function, _Hook, _Orig ) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)
 








//Variables
typedef DWORD (ULONG);
PMDL  g_pmdlSystemCall;
PVOID *MappedSystemCallTable;





//Declaracion de funciones
//Declaramos la API para poder trabajar con ella.
WINBASEAPI __out_opt HMODULE WINAPI LoadLibraryW(__in LPCWSTR lpLibFileName);



//NTSYSAPI NTSTATUS NTAPI ZwOpenProcess (OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL);

/*

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcess (
    __out PHANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PCLIENT_ID ClientId
    );

*/


/*

WINBASEAPI __out_opt HMODULE WINAPI LoadLibraryW(__in LPCWSTR lpLibFileName);

*/ 


NTSTATUS Unhookear();
NTSTATUS Hookear();
