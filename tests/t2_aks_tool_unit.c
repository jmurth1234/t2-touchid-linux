// SPDX-License-Identifier: GPL-2.0-only
#define main t2_aks_tool_program_main
#include "../src/t2-aks-tool.c"
#undef main

#include <assert.h>

int main(void)
{
	const unsigned char secret[] = { 't', 'e', 's', 't', '!' };
	const unsigned char context[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	};
	unsigned char *request = NULL;
	uint32_t request_length = 0;

	assert(build_verify_password_acm_request(1, -501, secret,
						 sizeof(secret), context, 0x200, &request,
						 &request_length) == 0);
	assert(request != NULL);
	assert(request_length == 56);
	assert(get_le32(request) == 1);
	assert(get_le64(request + 4) == 1);
	assert((int32_t)get_le32(request + 12) == -501);
	assert(get_le32(request + 16) == sizeof(secret));
	assert(memcmp(request + 20, secret, sizeof(secret)) == 0);
	assert(request[25] == 0 && request[26] == 0 && request[27] == 0);
	assert(get_le32(request + 28) == sizeof(context));
	assert(memcmp(request + 32, context, sizeof(context)) == 0);
	assert(get_le64(request + 48) == 0x200);
	memset(request, 0, request_length);
	free(request);

	request = NULL;
	assert(build_verify_password_acm_request(1, 4, secret, sizeof(secret),
						 context, 0x280, &request,
						 &request_length) == 0);
	assert(get_le64(request + 48) == 0x280);
	memset(request, 0, request_length);
	free(request);

	request = NULL;
	assert(build_verify_password_acm_request(1, 0, secret, sizeof(secret),
						 context, 0x200, &request,
						 &request_length) == -1);
	return 0;
}
