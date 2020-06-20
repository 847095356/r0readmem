
//��д������ô����		�ؼ����о���Ҫ���� ͨ��������������

#include <ntifs.h>
#include <wdm.h>
#include <windef.h>

BYTE readandwrite[] = { 0xc0 };

KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

VOID WPONx64(KIRQL irql)
{
	UINT cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

void mydUnload(IN PDRIVER_OBJECT DriverObject)
{

}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	DriverObject->DriverUnload = mydUnload;

	HANDLE pid = (HANDLE)2580;

	PEPROCESS targetprocess = NULL;

	KAPC_STATE apcstack = { 0 };

	BYTE code[] = { 0xcc };

	PVOID targetaddress = (PVOID)0x400000;

	PMDL tempmdl = NULL;

	PUCHAR pmapped = NULL;

	status = PsLookupProcessByProcessId(pid, &targetprocess);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("error  %x \n", status);

		return status;
	}

	ObDereferenceObject(targetprocess);

	KeStackAttachProcess(targetprocess, &apcstack);

	tempmdl = IoAllocateMdl(targetaddress, 1, FALSE, FALSE, NULL);

	if (!tempmdl)
	{
		DbgPrint("allocatemdl failed \n");

		KeUnstackDetachProcess(&apcstack);

		return STATUS_UNSUCCESSFUL;
	}

	MmBuildMdlForNonPagedPool(tempmdl);

	__try
	{
		pmapped = (PUCHAR)MmMapLockedPages(tempmdl, KernelMode);
	}
	__except (1)
	{
		DbgPrint("Lock or Map MDL Failed  \n");

		IoFreeMdl(tempmdl);

		KeUnstackDetachProcess(&apcstack);

		return STATUS_UNSUCCESSFUL;
	}

	//
	//	���Զ�
	//


	DbgPrint("read <%x>  \n", *pmapped);


	//
	//����д
	//
	
	RtlCopyMemory(pmapped, code, 1);

	DbgPrint("written read <%x>  \n", *pmapped);

	MmUnmapLockedPages((PVOID)pmapped, tempmdl);

	IoFreeMdl(tempmdl);


	//
	//	��Ϊֱ�ӵĶ�д���� ֱ�ӵ�
	//

	__try
	{
		ProbeForRead(targetaddress, 1, 1);		//����ʹ�ö�����Ϊ���ǲ�������һ�����ܹ�д���ڴ�
												//���ֱ��ʹ�� ProbeForWrite�ǻᱨ��� ����ʹ���������������ֻ��Ϊ����֤��ַ�Ƿ���Ч
		KIRQL  tempirql = WPOFFx64();

		RtlCopyMemory();

		WPONx64(tempirql);
	}
	__except (1)
	{
		DbgPrint("error page");

		KeUnstackDetachProcess(&apcstack);

		return STATUS_UNSUCCESSFUL;
	}

	KeUnstackDetachProcess(&apcstack);

	return status;
}