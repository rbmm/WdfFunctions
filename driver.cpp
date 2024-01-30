#include "stdafx.h"

_NT_BEGIN
#include "..\kpdb\module.h"

#include "wdfindex.h"

typedef struct WDF_DRIVER_GLOBALS *PWDF_DRIVER_GLOBALS;
typedef struct WDF_OBJECT_ATTRIBUTES *PWDF_OBJECT_ATTRIBUTES;

typedef struct WDFMEMORY__ *WDFMEMORY;

EXTERN_C_START

PVOID __imp_WdfMemoryCreate = 0, __imp_WdfMemoryCreatePreallocated = 0;

DECLSPEC_IMPORT
NTSTATUS
NTAPI
WdfMemoryCreate(
				_In_
				PWDF_DRIVER_GLOBALS DriverGlobals,
				_In_opt_
				PWDF_OBJECT_ATTRIBUTES Attributes,
				_In_
				_Strict_type_match_
				POOL_TYPE PoolType,
				_In_opt_
				ULONG PoolTag,
				_In_
				_When_(BufferSize == 0, __drv_reportError(BufferSize cannot be zero))
				size_t BufferSize,
				_Out_
				WDFMEMORY* Memory,
				_Outptr_opt_result_bytebuffer_(BufferSize)
				PVOID* Buffer
				);


DECLSPEC_IMPORT
NTSTATUS
NTAPI
WdfMemoryCreatePreallocated(
							_In_
							PWDF_DRIVER_GLOBALS DriverGlobals,
							_In_opt_
							PWDF_OBJECT_ATTRIBUTES Attributes,
							_In_ __drv_aliasesMem
							PVOID Buffer,
							_In_
							_When_(BufferSize == 0, __drv_reportError(BufferSize cannot be zero))
							size_t BufferSize,
							_Out_
							WDFMEMORY* Memory
							);

EXTERN_C_END

NTSTATUS
NTAPI
hook_WdfMemoryCreate(
					 _In_
					 PWDF_DRIVER_GLOBALS DriverGlobals,
					 _In_opt_
					 PWDF_OBJECT_ATTRIBUTES Attributes,
					 _In_
					 _Strict_type_match_
					 POOL_TYPE PoolType,
					 _In_opt_
					 ULONG PoolTag,
					 _In_
					 _When_(BufferSize == 0, __drv_reportError(BufferSize cannot be zero))
					 size_t BufferSize,
					 _Out_
					 WDFMEMORY* Memory,
					 _Outptr_opt_result_bytebuffer_(BufferSize)
					 PVOID* Buffer
					 )
{
	PVOID buf = 0;
	if (!Buffer) Buffer = &buf;
	
	NTSTATUS status = WdfMemoryCreate(DriverGlobals, Attributes, PoolType, PoolTag, BufferSize, Memory, Buffer);
	
	static LONG _S_count;

	LONG count = InterlockedIncrementNoFence(&_S_count);
	if (count <= 0x1000)
	{
		ULONG d;
		PVOID ret = _ReturnAddress();
		PCSTR name;
		PCSTR func = CModule::GetNameFromVa(ret, &d, &name);
		
		if (!func)
		{
			func = "";
		}

		DbgPrint("%04x %p, %s+%x >> WdfMemoryCreate(%.4s, %x, %x, %p)=%x [%p %p]\n", count,
			ret, func, d, &PoolTag, PoolType, BufferSize, Attributes, status, *Memory, *Buffer);

	}

	return status;
}

NTSTATUS
NTAPI
hook_WdfMemoryCreatePreallocated(
								 _In_
								 PWDF_DRIVER_GLOBALS DriverGlobals,
								 _In_opt_
								 PWDF_OBJECT_ATTRIBUTES Attributes,
								 _In_ __drv_aliasesMem
								 PVOID Buffer,
								 _In_
								 _When_(BufferSize == 0, __drv_reportError(BufferSize cannot be zero))
								 size_t BufferSize,
								 _Out_
								 WDFMEMORY* Memory
								 )
{
	NTSTATUS status = WdfMemoryCreatePreallocated(DriverGlobals, Attributes, Buffer, BufferSize, Memory);

	static LONG _S_count;

	LONG count = InterlockedIncrementNoFence(&_S_count);
	if (count <= 0x1000)
	{
		ULONG d=0;
		PVOID ret = _ReturnAddress();
		PCSTR name;
		PCSTR func = CModule::GetNameFromVa(ret, &d, &name);

		if (!func)
		{
			func = "";
		}

		DbgPrint("%04x %p, %s+%x >> WdfMemoryCreatePreallocated(%x, %p %p)=%x [%p]\n", count,
			ret, func, d, BufferSize, Buffer, Attributes, status, *Memory);
	}

	return status;
}

NTSTATUS GetSpyInfo(_Inout_ PUNICODE_STRING RegistryPath, _Out_ PULONG hash, _Out_ PSTR WdfFunctions, _In_ ULONG cch);

void** _G_MyWdfFunctions;
void** _G_WdfFunctions;
void*** _G_pWdfFunctions;

void NTAPI DriverUnload(PDRIVER_OBJECT /*DriverObject*/)
{
	DbgPrint("DriverUnload (%p)\n", _G_MyWdfFunctions);

	if (_G_pWdfFunctions)
	{
		*_G_pWdfFunctions = _G_WdfFunctions;
	}

	if (_G_MyWdfFunctions)
	{
		ExFreePool(_G_MyWdfFunctions);
	}
}

EXTERN_C
NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrint("ep(%p)", DriverObject);
	DriverObject->DriverUnload = DriverUnload;

	ULONG h;
	char szWdfFunctions[_countof("WdfFunctions_MMmmm")];
	NTSTATUS status = GetSpyInfo(RegistryPath, &h, szWdfFunctions, _countof(szWdfFunctions));

	if (0 > status)
	{
		DbgPrint("GetSpyInfo=%x\n", status);
		return status;
	}

	DbgPrint("[%08x] %s\n\n", h, szWdfFunctions);

	LoadNtModule(1, &h);

	if (CModule* nt = CModule::ByHash(h))
	{
		if (void*** pWdfFunctions = (void***)nt->GetVaFromName(szWdfFunctions))
		{
			void** WdfFunctions = *pWdfFunctions;

			DbgPrint("WdfFunctions=%p %p\n", pWdfFunctions, WdfFunctions);

			if (_G_MyWdfFunctions = (void**)ExAllocatePool(NonPagedPoolNx, WdfFunctionTableNumEntries * sizeof(void*)))
			{
				_G_pWdfFunctions = pWdfFunctions;
				_G_WdfFunctions = WdfFunctions;

				memcpy(_G_MyWdfFunctions, WdfFunctions, WdfFunctionTableNumEntries*sizeof(void*));

				__imp_WdfMemoryCreate = WdfFunctions[WdfMemoryCreateTableIndex];
				__imp_WdfMemoryCreatePreallocated = WdfFunctions[WdfMemoryCreatePreallocatedTableIndex];

				_G_MyWdfFunctions[WdfMemoryCreateTableIndex] = hook_WdfMemoryCreate;
				_G_MyWdfFunctions[WdfMemoryCreatePreallocatedTableIndex] = hook_WdfMemoryCreatePreallocated;

				*pWdfFunctions = _G_MyWdfFunctions;

				return STATUS_SUCCESS;
			}

			return STATUS_NO_MEMORY;
		}
	}

	return STATUS_OBJECT_NAME_NOT_FOUND;
}

_NT_END