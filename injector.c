#include "injector.h"
#include <ntstrsafe.h>




/// <summary>
/// Get exported function address
/// </summary>
/// <param name="pBase">Module base</param>
/// <param name="name_ord">Function name or ordinal</param>
/// <param name="pProcess">Target process for user module</param>
/// <param name="baseName">Dll name for api schema</param>
/// <returns>Found address, NULL if not found</returns>
PVOID BBGetModuleExport( IN PVOID pBase, IN PCCHAR name_ord, IN PEPROCESS pProcess, IN PUNICODE_STRING baseName )
{
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
    PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
    PIMAGE_EXPORT_DIRECTORY pExport = NULL;
    ULONG expSize = 0;
    ULONG_PTR pAddress = 0;

    ASSERT( pBase != NULL );
    if (pBase == NULL)
        return NULL;

    /// Not a PE file
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
    pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

    // Not a PE file
    if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // 64 bit image
    if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
        expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    // 32 bit image
    else
    {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
        expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    PUSHORT pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
    PULONG  pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
    PULONG  pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

    for (ULONG i = 0; i < pExport->NumberOfFunctions; ++i)
    {
        USHORT OrdIndex = 0xFFFF;
        PCHAR  pName = NULL;

        // Find by index
        if ((ULONG_PTR)name_ord <= 0xFFFF)
        {
            OrdIndex = (USHORT)i;
        }
        // Find by name
        else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
        {
            pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
            OrdIndex = pAddressOfOrds[i];
        }
        // Weird params
        else
            return NULL;

        if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
            ((ULONG_PTR)name_ord > 0xFFFF && strcmp( pName, name_ord ) == 0))
        {
            pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;

            // Check forwarded export
            if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize)
            {
                WCHAR strbuf[256] = { 0 };
                ANSI_STRING forwarder = { 0 };
                ANSI_STRING import = { 0 };

                UNICODE_STRING uForwarder = { 0 };
                ULONG delimIdx = 0;
                PVOID forwardBase = NULL;
                PVOID result = NULL;

                // System image, not supported
                if (pProcess == NULL)
                    return NULL;

                RtlInitAnsiString( &forwarder, (PCSZ)pAddress );
                RtlInitEmptyUnicodeString( &uForwarder, strbuf, sizeof( strbuf ) );

                RtlAnsiStringToUnicodeString( &uForwarder, &forwarder, FALSE );
                for (ULONG j = 0; j < uForwarder.Length / sizeof( WCHAR ); j++)
                {
                    if (uForwarder.Buffer[j] == L'.')
                    {
                        uForwarder.Length = (USHORT)(j * sizeof( WCHAR ));
                        uForwarder.Buffer[j] = L'\0';
                        delimIdx = j;
                        break;
                    }
                }

                // Get forward function name/ordinal
                RtlInitAnsiString( &import, forwarder.Buffer + delimIdx + 1 );
                RtlAppendUnicodeToString( &uForwarder, L".dll" );

                //
                // Check forwarded module
                //
                UNICODE_STRING resolved = { 0 };
                UNICODE_STRING resolvedName = { 0 };
                BBResolveImagePath( NULL, pProcess, KApiShemaOnly, &uForwarder, baseName, &resolved );
                BBStripPath( &resolved, &resolvedName );

                forwardBase = BBGetUserModule( pProcess, &resolvedName, PsGetProcessWow64Process( pProcess ) != NULL );
                result = BBGetModuleExport( forwardBase, import.Buffer, pProcess, &resolvedName );
                RtlFreeUnicodeString( &resolved );

                return result;
            }

            break;
        }
    }

    return (PVOID)pAddress;
}







/// <summary>
/// Create worker thread for user-mode calls
/// </summary>
/// <param name="pContext">Map context</param>
/// <returns>Status code</returns>
NTSTATUS BBCreateWorkerThread( IN PMMAP_CONTEXT pContext )
{
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T codeSize = 0x1000;
    ASSERT( pContext != NULL );
    if (pContext == NULL)
        return STATUS_INVALID_PARAMETER;

    pContext->pWorkerBuf = NULL;
    status = ZwAllocateVirtualMemory( ZwCurrentProcess(), &pContext->pWorkerBuf, 0, &codeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    if (NT_SUCCESS( status ))
    {
        PUCHAR pBuf = pContext->pWorkerBuf;
        UNICODE_STRING ustrNtdll;
        BOOLEAN wow64 = PsGetProcessWow64Process( pContext->pProcess ) != NULL;

        RtlUnicodeStringInit(&ustrNtdll, L"ntdll.dll");

        PVOID pNtDelayExec = BBGetModuleExport(
            BBGetUserModule( pContext->pProcess, &ustrNtdll, wow64 ),
            "NtDelayExecution", pContext->pProcess, NULL
            );

        if (pNtDelayExec)
        {
            OBJECT_ATTRIBUTES obattr = { 0 };
            PLARGE_INTEGER pDelay = (PLARGE_INTEGER)(pBuf + 0x100);
            pDelay->QuadPart = -(5ll * 10 * 1000);
            ULONG ofst = 0;

            if (wow64)
            {            
                *(PUCHAR)(pBuf + ofst) = 0x68;                      // push pDelay
                *(PULONG)(pBuf + ofst + 1) = (ULONG)(ULONG_PTR)pDelay;      //
                ofst += 5;

                *(PUSHORT)(pBuf + ofst) = 0x016A;                   // push TRUE
                ofst += 2;

                *(PUCHAR)(pBuf + ofst) = 0xB8;                      // mov eax, pFn
                *(PULONG)(pBuf + ofst + 1) = (ULONG)(ULONG_PTR)pNtDelayExec;//
                ofst += 5;

                *(PUSHORT)(pBuf + ofst) = 0xD0FF;                   // call eax
                ofst += 2;

                *(PUSHORT)(pBuf + ofst) = 0xF0EB;                   // jmp
                ofst += 2;
            }
            else
            {
                *(PUSHORT)(pBuf + ofst) = 0xB948;           // mov rcx, TRUE
                *(PULONG_PTR)(pBuf + ofst + 2) = TRUE;      //
                ofst += 10;

                *(PUSHORT)(pBuf + ofst) = 0xBA48;           // mov rdx, pDelay
                *(PVOID*)(pBuf + ofst + 2) = pDelay;        //
                ofst += 10;

                *(PUSHORT)(pBuf + ofst) = 0xB848;           // mov rax, pNtDelayExec
                *(PVOID*)(pBuf + ofst + 2) = pNtDelayExec;  //
                ofst += 10;

                *(PUSHORT)(pBuf + ofst) = 0xD0FF;           // call rax
                ofst += 2;

                *(PUSHORT)(pBuf + ofst) = 0xDEEB;           // jmp
                ofst += 2;
            }

            InitializeObjectAttributes( &obattr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL );
            status = ZwCreateThreadEx(
                &pContext->hWorker, THREAD_ALL_ACCESS, &obattr,
                ZwCurrentProcess(), pContext->pWorkerBuf, NULL, 0,
                0, 0x1000, 0x100000, NULL
                );

            if (NT_SUCCESS( status ))
                ObReferenceObjectByHandle( pContext->hWorker, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &pContext->pWorker, NULL );
        }
        else
        {
            status = STATUS_NOT_FOUND;
        }
    }

    return status;
}





NTSTATUS InjectDllWithParam(unsigned int pid, UNICODE_STRING path, InjectType itype, ULONG initRVA ,const UNICODE_STRING initArg, BOOLEAN unlink, BOOLEAN erasePE, BOOLEAN wait)
{
	INJECT_DLL data = { IT_Thread };	
}






NTSTATUS BBMapUserImage(IN PEPROCESS pProcess, IN PUNICODE_STRING path, IN PVOID buffer, IN ULONG_PTR size, IN BOOLEAN asImage, IN KMmapFlags flags, IN ULONG initRVA,IN PWCH initArg, OUT PMODULE_DATA pImage)
{


	NTSTATUS status = 0;
	MMAP_CONTEXT context = { 0 };


	//The ASSERT macro tests an expression. 
	//If the expression is false, it breaks into the kernel debugger.
    ASSERT(pProcess != NULL);

    if (pProcess == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    context.pProcess = pProcess;
    InitializeListHead(&context.modules);


    status = BBCreateWorkerThread( &context );


    if(NT_SUCCESS(status))
    {
        SIZE_T mapSize = 0x2000;
        status = ZwAllocateVirtualMemory( ZwCurrentProcess(), &context.userMem, 0, &mapSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    }


	return status;
}




NTSTATUS Injector(IN PINJECT_DLL dats)
{
	HANDLE hProc = (HANDLE) dats->pid;
	PEPROCESS eProc = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(hProc, &eProc);
	KAPC_STATE apc;
	unsigned int flagExit = 0;
	PVOID sysBuffer;
	UNICODE_STRING DllPath;
	UNICODE_STRING NtdllName;

	//Success
	if(NT_SUCCESS(status))
	{

		//BOOLEAN is64b = (PsGetProcessWow64Process(eProc) != NULL) ? TRUE : FALSE;
		LARGE_INTEGER timeOut = {0};


		//Chequea si es un proceso que se va a cerrar
		if(KeWaitForSingleObject(eProc, Executive, KernelMode, FALSE, &timeOut) == STATUS_WAIT_0)
		{
			status = STATUS_PROCESS_IS_TERMINATING;
		}

			else
			{

		        // Copy mmap image buffer to system space.
		        // Buffer will be released in mapping routine automatically
		        if(dats->type == IT_MMap && dats->imageBase)
		        {
		            __try
		            {	
		            	//ProbeForRead routine checks that a user-mode buffer actually resides in the user portion of the address space, and is correctly aligned. 	        	
		        		ProbeForRead((PVOID)dats->imageBase, dats->imageSize, 1);

		        		//The ExAllocatePoolWithTag routine allocates pool memory of the specified type and returns a pointer to the allocated block.
		        		sysBuffer = ExAllocatePoolWithTag(PagedPool, dats->imageSize, BB_POOL_TAG);


		        		RtlCopyMemory(sysBuffer, (PVOID)dats->imageBase, dats->imageSize);

		        	}

			        	__except (EXCEPTION_EXECUTE_HANDLER)
			        	{
			        		flagExit = 1;
			        		status = STATUS_INVALID_USER_BUFFER;
			        	}
		        }		      

				
		        if(flagExit == 0)
		        {
		        	KeStackAttachProcess(eProc, &apc);

		        	RtlInitUnicodeString(&DllPath, dats->FullDllPath);
		        	RtlInitUnicodeString(&NtdllName, L"ntdll.dll");

					// Handle manual map separately
			        if (dats->type == IT_MMap)
			        {
			        	MODULE_DATA mod = {0};

			            __try
			            {
			                status = BBMapUserImage(eProc, &DllPath, sysBuffer, dats->imageSize, dats->asImage, dats->flags, dats->initRVA, dats->initArg, &mod);
			            }			        	


							__except (EXCEPTION_EXECUTE_HANDLER)
							{
								status = EXCEPTION_EXECUTE_HANDLER;
							}

			        }

		        }		        

			}
	}


	if(eProc)
	{
		ObDereferenceObject(eProc);
	}

	return status;

}
