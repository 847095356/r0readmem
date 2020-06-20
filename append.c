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

			// 准备工作完成进行操作

			RtlZeroMemory(readBuffer, sizeof(readBuffer));	//可以用来拿到数组的大小

			KeStackAttachProcess(tempEp, &temp_stack);

			//this is in r3 memory

			__try{

				ProbeForRead(porcessbaseaddr+offset,sizeof(readBuffer),1);
//这里使用 RtlCopyMemory 来进行写入的话 对数据段是没有问题的 但是对于代码段 是不能进行写入操作的 那么要怎么解决
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

