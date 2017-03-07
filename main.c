/*

> makecert -sv code.pvk -n "CN=DevelSecurity" code.cer -e 12/30/2090 -r 



> pvk2pfx -pvk code.pvk -spc code.cer -pfx code.pfx -po password123_test



> certutil -addstore "TrustedPublisher" "C:\Users\opensylarwin\Documents\Visual Studio 2015\Projects\oPenKernelLoader\driver\sign\sign\code.pvk"



> signtool sign /t http://timestamp.digicert.com /n "DevelSecurity" "C:\Users\opensylarwin\Desktop\driver\amd64\bbpass.sys"



> signtool sign /t http://timestamp.digicert.com /n "DevelSecurity" "C:\Users\opensylarwin\Desktop\driver\i386\bbpass.sys"



*/

//#include <wdm.h>
//#include <ntddk.h>

#include "stdafx.h"
#include "proc.h"
#include "hooks.h"

/*

PCHAR StrCut(PCHAR buff, unsigned int indxCut, unsigned int lenBuff)
{
	unsigned int indx = 0;
	PCHAR ret = '\0';

	while(indx < indxCut && indx < lenBuff)
	{
		ret[indx] = buff[indx];
	}

	ret[indx] = '\0';

	return ret;
}

*/

/*

unsigned long DecodePayload(PCHAR inputBuff)
{

	CHAR tmpStr[30];
	
	//size_t szInputBuff;	
	//RtlStringCbLength(inputBuff, sizeof(inputBuff), szInputBuff); 

	ULONG i = 0;

	for(; i<=9; i++)
	{
		tmpStr[i] = inputBuff[i];
	}

	tmpStr[10] = "\0";

	DbgPrint("First 10 words '%s'", tmpStr);
}

*/




void Byebye(PDRIVER_OBJECT DriverObject)
{	
    UNICODE_STRING usDosDeviceName;
    RtlInitUnicodeString(&usDosDeviceName, PATHDEVICEDRIVER);
    IoDeleteSymbolicLink(&usDosDeviceName);
    Unhookear();
}




NTSTATUS fnMsg(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

	#define MSGOK "1"
	#define MSGNOTOK "0"
	#define WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x00000001, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

	NTSTATUS st = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack;
	PCHAR inputBuff;
	char *outputBuff;
	unsigned int strLen;
	char *msg = MSGOK;
	unsigned int *pid;
	unsigned int siz = sizeof(MSGOK);	

	stack = IoGetCurrentIrpStackLocation(Irp);

	switch(stack->Parameters.DeviceIoControl.IoControlCode)
	{
		case WRITE:
			
			//DbgPrint("BBPass-Driver - Funcion escribir llamada");
			//DbgPrint("BBPass-Driver - Asociando buffers");
			//strlen(inputBuff);			

			//Inicializa los buffers
			
			//pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;

			inputBuff = Irp->AssociatedIrp.SystemBuffer;							
			strLen = stack->Parameters.DeviceIoControl.InputBufferLength;
			inputBuff[strLen] = '\0';
			outputBuff = inputBuff;	

			//pid = reinterpret_cast<unsigned int *> (inputBuff);
			pid = 1233;

			if(outputBuff && inputBuff)
			{
				//DbgPrint("BBPass - Driver Ok");

				//Si hay datos en InputBuffer
				if(strLen > 0)
				{					

					//DecodePayload(inputBuff);

					DbgPrint("BBPass - Dats recividos '%s' longitud '%d' \r\n", inputBuff, pid);

					//ListProcess();

					Hookear();

					//Si hay datos en el Output Buffer
					if(stack->Parameters.DeviceIoControl.OutputBufferLength>= siz)
					{
						//strpcy hacia outputBuff
						RtlCopyMemory(outputBuff, msg, siz);

						//Ajustamos el tamano del buffer de salida sino no sale nada
						Irp->IoStatus.Information = siz;

						st = STATUS_SUCCESS;						
					}

						else
						{
							//No puede enviar datos
							Irp->IoStatus.Information = 0;
							st = STATUS_BUFFER_TOO_SMALL;
						}
				}
			}

			else
				//DbgPrint("BBPass - Driver ERROR");

		break;
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return st;
}




NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{

	const WCHAR device[] = PATHDEVICEDRIVER;
	const WCHAR sLink[] = PATHDEVICEDRIVERLINK;

	UNICODE_STRING dev,lnk;	
	NTSTATUS st;	
	unsigned int i; 

	DriverObject->DriverUnload=Byebye;
 
	//Redirige todas las fns de control (?) a la funcion fnMsg
	for(i=0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = fnMsg;

	//Para usar una cadena de caracteres UNICODE desde MU	

	//Copia dev -> \\device\\driver5
	RtlInitUnicodeString(&dev, device);

	//Copia a lnk -> \\??\\midriver5
	RtlInitUnicodeString(&lnk, sLink);

	//Crea el devices dentro de \\device\\driver5
	st = IoCreateDevice(DriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, 0, 0, &DriverObject);

	//Si no puedes crear \\device\\driver5
	if(NT_SUCCESS(st))
	{

		//Crea un link de \\??\\midriver5 to \\device\\driver5
		st = IoCreateSymbolicLink(&lnk, &dev);

		if(!NT_SUCCESS(st))
		{
			//Elemina el \\device\\driver5
			IoDeleteDevice(DriverObject->DeviceObject);
			//DbgPrint("BBPass-Driver - Error IoCreateSymbolicLink()");
		}

			else
			{				
				//DbgPrint("BBPass-Driver - IoCreateSymbolicLink Success");
			}

	}

		else
		{
			//DbgPrint("BBPass-Driver - IoCreateDevice Success");			
		}

return st;
}