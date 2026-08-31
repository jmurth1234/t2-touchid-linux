/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef T2_ACM_LIFECYCLE_H
#define T2_ACM_LIFECYCLE_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 t2_acm_wire_u8;
typedef u32 t2_acm_wire_u32;
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t t2_acm_wire_u8;
typedef uint32_t t2_acm_wire_u32;
#endif

#define T2_ACM_CONTEXT_SIZE 16
#define T2_ACM_POLICY_RESPONSE_SIZE 0x1000

enum t2_acm_context_preflight {
	T2_ACM_CONTEXT_ALLOW,
	T2_ACM_CONTEXT_BUSY,
	T2_ACM_CONTEXT_STALE,
	T2_ACM_CONTEXT_MATCH_REQUIRED,
	T2_ACM_CONTEXT_DENY,
};

enum t2_acm_reply_action {
	T2_ACM_REPLY_ACCEPT,
	T2_ACM_REPLY_REJECT,
	T2_ACM_REPLY_POISON,
	T2_ACM_REPLY_SET_CONTEXT,
	T2_ACM_REPLY_SET_CONTEXT_AND_REJECT,
	T2_ACM_REPLY_CLEAR_CONTEXT,
	T2_ACM_REPLY_CLEAR_CONTEXT_AND_REJECT,
};

static inline enum t2_acm_context_preflight
t2_acm_context_preflight(t2_acm_wire_u8 opcode, bool context_active)
{
	switch (opcode) {
	case 0x01:
	case 0x24:
		return context_active ? T2_ACM_CONTEXT_BUSY :
			T2_ACM_CONTEXT_ALLOW;
	case 0x02:
	case 0x03:
		return context_active ? T2_ACM_CONTEXT_MATCH_REQUIRED :
			T2_ACM_CONTEXT_STALE;
	default:
		return T2_ACM_CONTEXT_DENY;
	}
}

static inline bool
t2_acm_response_capacity_allowed(t2_acm_wire_u8 opcode,
				 t2_acm_wire_u32 capacity, bool has_buffer)
{
	switch (opcode) {
	case 0x01:
		return capacity == 17 && has_buffer;
	case 0x24:
		return capacity == 21 && has_buffer;
	case 0x02:
		return capacity == 0 && !has_buffer;
	case 0x03:
		return capacity == T2_ACM_POLICY_RESPONSE_SIZE && has_buffer;
	default:
		return false;
	}
}

static inline enum t2_acm_reply_action
t2_acm_reply_action(t2_acm_wire_u8 opcode, size_t response_length,
		    t2_acm_wire_u32 response_info)
{
	if (response_info)
		return T2_ACM_REPLY_ACCEPT;

	switch (opcode) {
	case 0x01:
	case 0x24: {
		size_t expected = opcode == 0x01 ? 17 : 21;

		if (response_length < T2_ACM_CONTEXT_SIZE)
			return T2_ACM_REPLY_POISON;
		return response_length == expected ? T2_ACM_REPLY_SET_CONTEXT :
			T2_ACM_REPLY_SET_CONTEXT_AND_REJECT;
	}
	case 0x02:
		return response_length == 0 ? T2_ACM_REPLY_CLEAR_CONTEXT :
			T2_ACM_REPLY_CLEAR_CONTEXT_AND_REJECT;
	case 0x03:
		return response_length >= sizeof(t2_acm_wire_u32) &&
		       response_length <= T2_ACM_POLICY_RESPONSE_SIZE ?
			T2_ACM_REPLY_ACCEPT : T2_ACM_REPLY_REJECT;
	default:
		return T2_ACM_REPLY_REJECT;
	}
}

#endif /* T2_ACM_LIFECYCLE_H */
