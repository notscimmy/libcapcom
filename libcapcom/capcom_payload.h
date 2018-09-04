#pragma once

#include <Windows.h>
#include <stdint.h>

namespace capcom::payload
{
	static const uint32_t user_function_ptr_offset = 0x2;
	static uint8_t code_template[] =
	{
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, user_function_ptr
		0xFF, 0xE0													// jmp rax
	};

	struct capcom_payload
	{
		void* ptr_to_code;
		uint8_t code[sizeof(code_template)];
	};

	capcom_payload* build_capcom_payload(uintptr_t user_function_wrapper);
}