#include "stdafx.h"

_NT_BEGIN

#include "..\kpdb\module.h"

inline NTSTATUS ifRegSz(PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi)
{
	switch (pkvpi->Type)
	{
	case REG_SZ:
	case REG_EXPAND_SZ:
		if (pkvpi->DataLength >= sizeof WCHAR &&
			!(pkvpi->DataLength & 1) &&
			!*(PWSTR)(pkvpi->Data + pkvpi->DataLength - sizeof(WCHAR)))
		{
			return STATUS_SUCCESS;
		}
	}

	return STATUS_OBJECT_TYPE_MISMATCH;
}

NTSTATUS GetSpyInfo(_Inout_ PUNICODE_STRING RegistryPath, _Out_ PULONG hash, _Out_ PSTR WdfFunctions, _In_ ULONG cch)
{
	DbgPrint("GetSpyInfo(\"%wZ\")\n", RegistryPath);

	HANDLE hKey;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, RegistryPath, OBJ_CASE_INSENSITIVE };
	NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &oa);

	if (0 <= status)
	{
		union {
			CHAR buf[0x100];
			KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 kvpi;
		};

		ULONG cb;
		RtlInitUnicodeString(RegistryPath, L"SpyDrv");

		status = ZwQueryValueKey(hKey, RegistryPath, KeyValuePartialInformationAlign64, buf, sizeof(buf), &cb);

		NtClose(hKey);

		if (0 <= status)
		{
			if (0 <= (status = ifRegSz(&kvpi)))
			{
				DbgPrint("key: %S\n", kvpi.Data);

				WCHAR sz[64+_countof(buf)];
				swprintf_s(sz, _countof(sz), L"\\Registry\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s", (PWSTR)kvpi.Data);
				RtlInitUnicodeString(RegistryPath, sz);

				if (0 <= (status = ZwOpenKey(&oa.RootDirectory, KEY_READ, &oa)))
				{
					RtlInitUnicodeString(RegistryPath, L"ImagePath");

					status = ZwQueryValueKey(oa.RootDirectory, RegistryPath, KeyValuePartialInformationAlign64, buf, sizeof(buf), &cb);

					if (0 <= status && 0 <= (status = ifRegSz(&kvpi)))
					{
						PWSTR psz = (PWSTR)kvpi.Data;
						if (PWSTR pc = wcsrchr(psz, L'\\'))
						{
							psz = pc + 1;
						}

						DbgPrint("driver: %S\n", psz);

						if (0 <= (status = RtlUnicodeToMultiByteN(buf, _countof(buf), 0, psz, ((ULONG)wcslen(psz)+1)*sizeof(WCHAR))))
						{
							*hash = HashString(buf, 0);

							RtlInitUnicodeString(RegistryPath, L"Parameters\\Wdf");

							if (0 <= (status = ZwOpenKey(&hKey, KEY_READ, &oa)))
							{
								RtlInitUnicodeString(RegistryPath, L"WdfMajorVersion");

								if (0 <= (status = ZwQueryValueKey(hKey, RegistryPath, 
									KeyValuePartialInformationAlign64, buf, sizeof(buf), &cb)))
								{
									ULONG WdfMajorVersion, WdfMinorVersion;
									if (REG_DWORD == kvpi.Type)
									{
										WdfMajorVersion = (ULONG&)kvpi.Data;

										RtlInitUnicodeString(RegistryPath, L"WdfMinorVersion");

										if (0 <= (status = ZwQueryValueKey(hKey, RegistryPath, 
											KeyValuePartialInformationAlign64, buf, sizeof(buf), &cb)))
										{
											if (REG_DWORD == kvpi.Type)
											{
												WdfMinorVersion = (ULONG&)kvpi.Data;

												status = 0 < sprintf_s(WdfFunctions, cch, "WdfFunctions_%02u%03u", 
													WdfMajorVersion, WdfMinorVersion) ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
											}
											else
											{
												status = STATUS_OBJECT_TYPE_MISMATCH;
											}
										}
									}
									else
									{
										status = STATUS_OBJECT_TYPE_MISMATCH;
									}
								}
								NtClose(hKey);
							}
						}
					}

					NtClose(oa.RootDirectory);
				}
			}
		}
	}

	return status;
}

_NT_END