#include "hooks.h"

NTSTATUS NewZwOpenProcess(OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL)
{
   HANDLE PID;
 
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
	ZwOpenProcessIni =(TypZwOpenProc)(SYSTEMSERVICE(ZwOpenProcess));


 
   //Creamos la MDL para deshabilitar la protección de memoria
   g_pmdlSystemCall = MmCreateMdl(NULL, KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices*4);




   if(!g_pmdlSystemCall)
      return STATUS_UNSUCCESSFUL;



 
   MmBuildMdlForNonPagedPool(g_pmdlSystemCall);
   g_pmdlSystemCall->MdlFlags = g_pmdlSystemCall->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA; 
   MappedSystemCallTable = MmMapLockedPages(g_pmdlSystemCall, KernelMode);
 
 
   DbgPrint("Hookeando...");
   HOOK_SYSCALL( ZwOpenProcess, NewZwOpenProcess, ZwOpenProcessIni );
 
   return STATUS_SUCCESS;
}