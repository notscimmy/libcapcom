#pragma once

#include <functional>
#include "structs.h"

using namespace native::structs;

namespace capcom::wrapper
{
	static const std::string device_name = "\\\\.\\Htsysm72FB";
	static const DWORD ioctl_x64 = 0xAA013044u;

	class capcom_wrapper
	{
	private:
		HANDLE driver_handle;

	public:
		capcom_wrapper();

		void open_driver_handle();
		void close_driver_handle();
		void execute_in_kernel(std::function<void(MmGetSystemRoutineAddress_t)> user_function);
	};
}
