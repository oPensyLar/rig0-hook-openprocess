#include "proc.h"









NTSTATUS GetProcessImageName(HANDLE hProc, PUNICODE_STRING procImg)
{
	NTSTATUS ret = STATUS_ACCESS_DENIED;
	PUNICODE_STRING imgName = NULL;
	ULONG retLen = 0;
	ULONG buffLength = 0;
	PVOID buffer;
	UNICODE_STRING routineName;

	if(ZwQueryInformationProcess == NULL)
	{
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		ZwQueryInformationProcess = (QUERY_INFO_PROCESS) 	MmGetSystemRoutineAddress(&routineName);

		if(NULL == ZwQueryInformationProcess)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

	}

	else
	{

		//Obtenemos el size del proceso =)
		ret = ZwQueryInformationProcess(hProc, ProcessImageFileName, NULL, 0, &retLen);

		if(ret != STATUS_INFO_LENGTH_MISMATCH)	
		{
			return ret;
		}

		//Chequeamos el size que provoque un overflow
		buffLength = retLen - sizeof(UNICODE_STRING);

		if(procImg->MaximumLength < buffLength)		
		{
			procImg->Length = (USHORT) buffLength;
			return STATUS_BUFFER_OVERFLOW;
		}

		//Allocalizamos la nueva longitud
		buffer = ExAllocatePoolWithTag(PagedPool, retLen, "ipgD");


		if(buffer == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}


		ret = ZwQueryInformationProcess(hProc, ProcessImageFileName, buffer, retLen, &retLen);		


		if(NT_SUCCESS(ret))
		{
			imgName = (PUNICODE_STRING) buffer;
			RtlCopyUnicodeString(procImg, imgName);
		}
	}

	return ret;
}










BOOLEAN ListProcess()	
{


	unsigned long eProc, aux, proc, ret;
	PLIST_ENTRY listEntry, listEntry_otra;
	unsigned int pidProc = 0;
	int ii = 0;
	NTSTATUS status = 0;
	//MAP_MEMORY_REGION_RESULT result = { 0 };
	INJECT_DLL dats = { IT_Thread };



	//Obtenemos el System
	eProc = (unsigned long) PsGetCurrentProcess();

	//Punteros del siguiente y anterior proceso link
	listEntry = (PLIST_ENTRY *) (eProc + OFFSET_PROCSLINKS_WIN7_X86);



	aux = (unsigned long) listEntry->Blink;
	proc = (unsigned long) listEntry;


	pidProc = *((int *) (proc + OFFSET_PROCPID_WIN7_X86));	

	
	//*(ULONG*)ioBuffer = (ULONG)sizeRequired;
	//RtlCopyMemory( ioBuffer, &result, sizeof( result ) );    	


	while(aux != proc)
	{		

		proc-= OFFSET_PROCSLINKS_WIN7_X86;
		ret = proc;

		pidProc = *((int *)(proc + OFFSET_PROCPID_WIN7_X86));


		dats.pid = pidProc;
		dats.type = IT_MMap;
		dats.imageBase = 0x1;
		dats.imageSize = 0x2;
		status = Injector(&dats);



		if(NT_SUCCESS(status))
		{
			DbgPrint("RTL - Injected PID %d", pidProc);
		}

			else
			{
				DbgPrint("RTL - NOT injected PID %d", pidProc);
			}

		
		//GetProcessName(pidProc);


/*		if(pidProc > 1000)
		{

			DbgPrint(":: HIDDEN %d ::", pidProc);

			listEntry_otra = (LIST_ENTRY *)(proc + OFFSET_PROCSLINKS_WIN7_X86);
			listEntry_otra->Blink->Flink = listEntry_otra->Flink;
			listEntry_otra->Flink->Blink = listEntry_otra->Blink;

		}

		DbgPrint("BBPass - foundPid '%d'", pidProc);
*/

		listEntry = listEntry->Flink;
		proc = (unsigned long) listEntry;
	}



	return TRUE;
}











unsigned long FindProcess(unsigned int targetPid)
{
	unsigned long eproc, aux, proc, ret = -100;
	PLIST_ENTRY listEntry;
	unsigned int pidProc;

	//Obtenemos el System
	eproc = (unsigned long) PsGetCurrentProcess();

	//Punteros del siguiente y anterior proceso link
	listEntry = (PLIST_ENTRY *) (eproc + OFFSET_PROCSLINKS_WIN7_X64);



	aux = (unsigned long) listEntry->Blink;
	proc = (unsigned long) listEntry;

	pidProc = *((int *) (proc + OFFSET_PROCPID_WIN7_X64));	




	while(aux != proc && pidProc != targetPid)
	{
		proc = OFFSET_PROCSLINKS_WIN7_X64;
		ret = proc;

		pidProc = *((int *) (proc + OFFSET_PROCPID_WIN7_X64));

		listEntry = listEntry->Flink;
		proc = (unsigned long) listEntry;
	}




	return ret;
}






BOOLEAN GetProcessName(unsigned int procId)
{

	NTSTATUS status;
	PEPROCESS eProc;
	HANDLE hProc;
	UNICODE_STRING procImg = {0};


	//Llenamos la estructura PEPROCESS
	status = PsLookupProcessByProcessId(procId, &eProc);


	//Si status no es igual a NT_SUCCESS entonces FALSE contigo
	if(!NT_SUCCESS(status))	
	{
		DbgPrint("BBPass - PsLookupProcessByProcessId() FALSE");
		return FALSE;
	}



	//Obtenemos el handle del proceso
	status = ObOpenObjectByPointer(eProc, 0, NULL, 0, 0, KernelMode, &hProc);

	if(!NT_SUCCESS(status))
	{
		DbgPrint("BBPass - ObOpenObjectByPointer() FALSE");
		ObDereferenceObject(eProc);
		eProc = NULL;
		return FALSE;				
	}



	//Obtenes el nombre
	procImg.Length = 0;
	procImg.MaximumLength = 1024;
	//Initializate buffer
	procImg.Buffer = ExAllocatePoolWithTag(NonPagedPool, procImg.MaximumLength, "2leN");

	if(procImg.Buffer == NULL)
	{
		DbgPrint("BBPass - ExAllocatePoolWithTag() FALSE");
		ZwClose(hProc);
		ObDereferenceObject(eProc);
		eProc = NULL;
		return FALSE;

	}

	RtlZeroMemory(procImg.Buffer, procImg.MaximumLength);
	status = GetProcessImageName(hProc, &procImg);	
	DbgPrint("AFUERAA '%wZ'", &procImg);


	return TRUE;
}


