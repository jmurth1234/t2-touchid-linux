// SPDX-License-Identifier: GPL-2.0-only
#include "../src/t2_acm_lifecycle.h"

#include <assert.h>

int main(void)
{
	assert(t2_acm_context_preflight(0x24, false) ==
	       T2_ACM_CONTEXT_ALLOW);
	assert(t2_acm_context_preflight(0x24, true) ==
	       T2_ACM_CONTEXT_BUSY);
	assert(t2_acm_context_preflight(0x03, false) ==
	       T2_ACM_CONTEXT_STALE);
	assert(t2_acm_context_preflight(0x03, true) ==
	       T2_ACM_CONTEXT_MATCH_REQUIRED);
	assert(t2_acm_context_preflight(0x13, false) ==
	       T2_ACM_CONTEXT_STALE);
	assert(t2_acm_context_preflight(0x13, true) ==
	       T2_ACM_CONTEXT_MATCH_REQUIRED);
	assert(t2_acm_context_preflight(0xff, false) ==
	       T2_ACM_CONTEXT_DENY);

	assert(t2_acm_response_capacity_allowed(0x01, 17, true));
	assert(!t2_acm_response_capacity_allowed(0x01, 18, true));
	assert(t2_acm_response_capacity_allowed(0x24, 21, true));
	assert(!t2_acm_response_capacity_allowed(0x24, 21, false));
	assert(t2_acm_response_capacity_allowed(0x02, 0, false));
	assert(!t2_acm_response_capacity_allowed(0x02, 0, true));
	assert(t2_acm_response_capacity_allowed(0x13, 0, false));
	assert(!t2_acm_response_capacity_allowed(0x13, 16, true));
	assert(T2_ACM_POLICY_RESPONSE_SIZE == 0x1000);
	assert(t2_acm_response_capacity_allowed(
		0x03, T2_ACM_POLICY_RESPONSE_SIZE, true));
	assert(!t2_acm_response_capacity_allowed(0x03, 0x4000, true));

	assert(t2_acm_reply_action(0x24, 21, 0) ==
	       T2_ACM_REPLY_SET_CONTEXT);
	assert(t2_acm_reply_action(0x01, 17, 0) ==
	       T2_ACM_REPLY_SET_CONTEXT);
	assert(t2_acm_reply_action(0x24, 15, 0) ==
	       T2_ACM_REPLY_POISON);
	assert(t2_acm_reply_action(0x24, 20, 0) ==
	       T2_ACM_REPLY_SET_CONTEXT_AND_REJECT);
	assert(t2_acm_reply_action(0x02, 0, 0) ==
	       T2_ACM_REPLY_CLEAR_CONTEXT);
	assert(t2_acm_reply_action(0x02, 1, 0) ==
	       T2_ACM_REPLY_CLEAR_CONTEXT_AND_REJECT);
	assert(t2_acm_reply_action(0x13, 0, 0) ==
	       T2_ACM_REPLY_ACCEPT);
	assert(t2_acm_reply_action(0x13, 16, 0) ==
	       T2_ACM_REPLY_REJECT);
	assert(t2_acm_reply_action(0x03, 4, 0) ==
	       T2_ACM_REPLY_ACCEPT);
	assert(t2_acm_reply_action(0x03, 3, 0) ==
	       T2_ACM_REPLY_REJECT);
	assert(t2_acm_reply_action(0x03,
				   T2_ACM_POLICY_RESPONSE_SIZE + 1, 0) ==
	       T2_ACM_REPLY_REJECT);
	assert(t2_acm_reply_action(0x24, 0, 1) ==
	       T2_ACM_REPLY_ACCEPT);
	return 0;
}
