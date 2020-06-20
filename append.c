#include <ntifs.h>
#include <wdm.h>
#include <windef.h>

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

BYTE readBuffer[4] = { 0 };

ULONG offset = 0x10;

VOID MyProcessNotify(HANDLE  ParentId, HANDLE  ProcessId, BOOLEAN  Create)
{
	if (Create&&ProcessId != (HANDLE)4&&ProcessId!=0)
	{
		PEPROCESS tempEp = NULL;

		NTSTATUS status = STATUS_SUCCESS;

		PUCHAR porcessbaseaddr = NULL;

		KAPC_STATE temp_stack = { 0 };

		status = PsLookupProcessByProcessId(ProcessId, &tempEp);

		if (tempEp)
		{
			ObDereferenceObject(tempEp);

			porcessbaseaddr = (PUCHAR)PsGetProcessSectionBaseAddress(tempEp);

			if (!porcessbaseaddr)
			{
				DbgPrint("Get processbassaddr failed \n");

				return;
			}

			// ׼��������ɽ��в���

			RtlZeroMemory(readBuffer, sizeof(readBuffer));	//���������õ�����Ĵ�С

			KeStackAttachProcess(tempEp, &temp_stack);

			//this is in r3 memory

			__try{

				ProbeForRead(porcessbaseaddr+offset,sizeof(readBuffer),1);
//����ʹ�� RtlCopyMemory ������д��Ļ� �����ݶ���û������� ���Ƕ��ڴ���� �ǲ��ܽ���д������� ��ôҪ��ô���
				RtlCopyMemory((PVOID)readBuffer, (PVOID)(porcessbaseaddr + offset), sizeof(readBuffer));


			}
			__except (1)
			{
				DbgPrint("bad mem \n");
			}

			KeUnstackDetachProcess(&temp_stack);

			for (int i = 0; i < sizeof(readBuffer);i++)
			{
				DbgPrint("Read %x", readBuffer[i]);
			}
			return;
		}
	}
}


void mydUnload(IN PDRIVER_OBJECT DriverObject)   
{
	PsSetCreateProcessNotifyRoutine(MyProcessNotify, TRUE);

	DbgPrint("unload \n");
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	DriverObject->DriverUnload = mydUnload;

	status = PsSetCreateProcessNotifyRoutine(MyProcessNotify, FALSE);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("process notify false!");
	}


	return status;
}

