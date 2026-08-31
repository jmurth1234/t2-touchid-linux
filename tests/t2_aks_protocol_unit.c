// SPDX-License-Identifier: GPL-2.0-only
#include "../src/t2_aks_protocol.h"

#include <assert.h>
#include <string.h>

static void put_le32(unsigned char *value, uint32_t number)
{
	value[0] = number;
	value[1] = number >> 8;
	value[2] = number >> 16;
	value[3] = number >> 24;
}

static void put_le64(unsigned char *value, uint64_t number)
{
	put_le32(value, (uint32_t)number);
	put_le32(value + 4, (uint32_t)(number >> 32));
}

static size_t make_request(unsigned char request[176], size_t password_length,
			   size_t context_length)
{
	size_t padded_length = (password_length + 3) & ~(size_t)3;
	size_t length = 32 + padded_length + context_length;

	memset(request, 0, 176);
	put_le32(request, 1);
	put_le64(request + 4, 1);
	put_le32(request + 12, (uint32_t)-501);
	put_le32(request + 16, (uint32_t)password_length);
	memset(request + 20, 'x', password_length);
	put_le32(request + 20 + padded_length, (uint32_t)context_length);
	memset(request + 24 + padded_length, 0xa5, context_length);
	put_le64(request + 24 + padded_length + context_length, 0x200);
	return length;
}

int main(void)
{
	unsigned char request[176];
	unsigned char uuid_request[16] = { 0 };
	size_t length, index;

	put_le64(uuid_request + 4, 1);
	put_le32(uuid_request + 12, (uint32_t)-501);
	assert(t2_aks_copy_keybag_uuid_request_allowed(uuid_request,
							 sizeof(uuid_request)));
	assert(!t2_aks_copy_keybag_uuid_request_allowed(uuid_request, 15));
	assert(!t2_aks_copy_keybag_uuid_request_allowed(uuid_request, 17));
	put_le32(uuid_request, 1);
	assert(!t2_aks_copy_keybag_uuid_request_allowed(uuid_request,
							 sizeof(uuid_request)));
	put_le32(uuid_request, 0);
	put_le64(uuid_request + 4, 2);
	assert(!t2_aks_copy_keybag_uuid_request_allowed(uuid_request,
							 sizeof(uuid_request)));
	put_le64(uuid_request + 4, 1);
	put_le32(uuid_request + 12, 0);
	assert(!t2_aks_copy_keybag_uuid_request_allowed(uuid_request,
							 sizeof(uuid_request)));
	assert(!t2_aks_copy_keybag_uuid_request_allowed(NULL,
							 sizeof(uuid_request)));

	length = make_request(request, 5, 0);
	assert(length == 40);
	assert(t2_aks_verify_secret_v1_request_allowed(request, length));
	for (index = 0; index < length; index++)
		assert(!t2_aks_verify_secret_v1_request_allowed(request, index));
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length + 1));

	length = make_request(request, 5, 16);
	assert(length == 56);
	assert(t2_aks_verify_secret_v1_request_allowed(request, length));

	put_le32(request, 2);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));
	put_le32(request, 1);
	put_le64(request + 4, 2);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));
	put_le64(request + 4, 1);
	put_le32(request + 12, 0);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));

	length = make_request(request, 5, 0);
	request[25] = 1;
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));
	length = make_request(request, 5, 0);
	put_le32(request + 28, 1);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));
	length = make_request(request, 5, 0);
	put_le64(request + 32, 0x280);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, length));

	length = make_request(request, 1, 0);
	assert(t2_aks_verify_secret_v1_request_allowed(request, length));
	length = make_request(request, 128, 16);
	assert(t2_aks_verify_secret_v1_request_allowed(request, length));
	put_le32(request + 16, 129);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, 36));
	put_le32(request + 16, 0);
	assert(!t2_aks_verify_secret_v1_request_allowed(request, 36));
	assert(!t2_aks_verify_secret_v1_request_allowed(NULL, 36));
	return 0;
}
