/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef T2_AKS_PROTOCOL_H
#define T2_AKS_PROTOCOL_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 t2_aks_wire_u8;
typedef u32 t2_aks_wire_u32;
typedef u64 t2_aks_wire_u64;
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t t2_aks_wire_u8;
typedef uint32_t t2_aks_wire_u32;
typedef uint64_t t2_aks_wire_u64;
#endif

static inline t2_aks_wire_u32
t2_aks_wire_get_le32(const t2_aks_wire_u8 *value)
{
	return (t2_aks_wire_u32)value[0] |
	       ((t2_aks_wire_u32)value[1] << 8) |
	       ((t2_aks_wire_u32)value[2] << 16) |
	       ((t2_aks_wire_u32)value[3] << 24);
}

static inline t2_aks_wire_u64
t2_aks_wire_get_le64(const t2_aks_wire_u8 *value)
{
	return (t2_aks_wire_u64)t2_aks_wire_get_le32(value) |
	       ((t2_aks_wire_u64)t2_aks_wire_get_le32(value + 4) << 32);
}

/*
 * Raw operation 0x06 is the matching AppleKeyStore kext's read-only
 * copy_keybag_uuid IPC.  Linux permits only the proven session-1 request:
 * zero result placeholder, owning session, and one nonzero signed handle.
 */
static inline bool
t2_aks_copy_keybag_uuid_request_allowed(const t2_aks_wire_u8 *request,
					 size_t length)
{
	return request && length == 16 &&
	       t2_aks_wire_get_le32(request) == 0 &&
	       t2_aks_wire_get_le64(request + 4) == 1 &&
	       t2_aks_wire_get_le32(request + 12) != 0;
}

/*
 * Root-only operation 0x21 is intentionally narrower than the Apple ABI.
 * It accepts selector-42 plaintext verification with either the exact
 * 16-byte ACM external form or the zero-context stage-isolation diagnostic.
 */
static inline bool
t2_aks_verify_secret_v1_request_allowed(const t2_aks_wire_u8 *request,
					    size_t length)
{
	size_t password_length, padded_length, context_length, expected_length;
	t2_aks_wire_u64 options, session;
	t2_aks_wire_u32 handle;
	size_t offset;

	if (!request || length < 36 || t2_aks_wire_get_le32(request) != 1)
		return false;
	session = t2_aks_wire_get_le64(request + 4);
	handle = t2_aks_wire_get_le32(request + 12);
	if (session != 1 || handle == 0)
		return false;
	password_length = t2_aks_wire_get_le32(request + 16);
	if (!password_length || password_length > 128)
		return false;
	padded_length = (password_length + 3) & ~(size_t)3;
	if (length < 32 + padded_length)
		return false;
	for (offset = password_length; offset < padded_length; offset++) {
		if (request[20 + offset] != 0)
			return false;
	}
	context_length = t2_aks_wire_get_le32(request + 20 + padded_length);
	if (context_length != 0 && context_length != 16)
		return false;
	expected_length = 32 + padded_length + context_length;
	if (length != expected_length)
		return false;
	options = t2_aks_wire_get_le64(request + 24 + padded_length +
				       context_length);
	return options == 0x200;
}

#endif /* T2_AKS_PROTOCOL_H */
