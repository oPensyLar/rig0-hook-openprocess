#include "hooks.h"


/*

NTSYSAPI NTSTATUS NTAPI ZwOpenProcess (__out PHANDLE ProcessHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __in_opt PCLIENT_ID ClientId);

*/


//WINBASEAPI __out_opt HMODULE WINAPI LoadLibraryW(__in LPCWSTR lpLibFileName);

WINBASEAPI __out_opt HMODULE WINAPI NewLoadLibray(__in LPCWSTR lpLibFileName)
{



/*   HANDLE PID;
 
    __try //Utilizamos el bloque try para evitar BSOD
    {
		PID = ClientId->UniqueProcess;
	}
 
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_INVALID_PARAMETER;
	}
 
	//DbgPrint("PID: 0x%x",PID);
 


	//Verificamos el pid
	if (PID == (HANDLE) 1824 ) 
	//Retornamos acceso denegado
	return STATUS_ACCESS_DENIED; 



	else 
		//Llamamos a la API nativa y retornamos el resultado correcto
		return ZwOpenProcessIni(ProcessHandle, DesiredAccess,ObjectAttributes, ClientId); 

*/

}




NTSTATUS Unhookear()
{

   UNHOOK_SYSCALL(ZwOpenProcess, ZwOpenProcessIni, NewZwOpenProcess);
 
   //Eliminamos la MDL
   if(g_pmdlSystemCall)
   {
      MmUnmapLockedPages(MappedSystemCallTable, g_pmdlSystemCall);
      IoFreeMdl(g_pmdlSystemCall);
   }
}







NTSTATUS Hookear()
{

	//Variable que contrendra la direccion que apunta ZwOpenProcess
	LoadLibrayIni =(TypLoadLibr)(SYSTEMSERVICE(LoadLibraryW));



 
   //Creamos la MDL para deshabilitar la protección de memoria
   //MDL = Memory Descriptor List
   //g_pmdlSystemCall contiene la direccion a reemplazar
   g_pmdlSystemCall = MmCreateMdl(NULL, KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices*4);



	//Si g_pmdlSystemCall es NULL entonces no tenemos direccion de la funcion a hookear
	//Salimos
   if(!g_pmdlSystemCall)
      return STATUS_UNSUCCESSFUL;



 
   MmBuildMdlForNonPagedPool(g_pmdlSystemCall);
   g_pmdlSystemCall->MdlFlags = g_pmdlSystemCall->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA; 
   MappedSystemCallTable = MmMapLockedPages(g_pmdlSystemCall, KernelMode);
 
 
   DbgPrint("Hookeando...");

   //HOOK_SYSCALL(API, NuestraFuncion, Direccióninicial);
   HOOK_SYSCALL( LoadLibraryW, NewLoadLibray, LoadLibrayIni);
 
   return STATUS_SUCCESS;
}