#pragma once
#define WIN32_NO_STATUS
#include <Windows.h>
#include <Winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

namespace native::structs
{
	typedef PVOID (NTAPI* MmGetSystemRoutineAddress_t)(PUNICODE_STRING);
}
