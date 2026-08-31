// SPDX-License-Identifier: GPL-2.0-only
/*
 * Staged Intel T2 SEP mailbox/OOL transport bring-up.
 *
 * The default mode maps BAR4 and reports status only.  Setting register_ool=1
 * explicitly enables bus mastering, allocates the two 16 KiB AppleKeyStore
 * endpoint-7 buffers, and registers them through SEP endpoint 0.  It does not
 * issue an AppleKeyStore operation.
 */

#include <linux/atomic.h>
#include <linux/bitfield.h>
#include <linux/capability.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include <linux/compat.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/hex.h>
#include <linux/io.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/unaligned.h>
#include <linux/uaccess.h>

#include "t2_acm_lifecycle.h"
#include "t2_aks_protocol.h"
#include "t2_sep_transport_uapi.h"

static_assert(sizeof(struct t2_acm_ioc_exchange) == 48);
static_assert(sizeof(struct t2_acm_ioc_info) == 16);
static_assert(sizeof(struct t2_aks_ioc_exchange) == 32);

#define T2_SEP_VENDOR_ID            0x106b
#define T2_SEP_DEVICE_ID            0x1802
#define T2_SEP_MAILBOX_BAR          4
#define T2_SEP_BAR_MIN_SIZE         0x10000

#define T2_SEP_INBOX_STATUS         0x0108
#define T2_SEP_OUTBOX_STATUS        0x010c
#define T2_SEP_INBOX_DATA           0x0810
#define T2_SEP_OUTBOX_DATA          0x0820
#define T2_SEP_INBOX_EMPTY          BIT(17)
#define T2_SEP_OUTBOX_FULL          BIT(16)

#define T2_SEP_ENDPOINT_MASK        GENMASK(4, 0)
#define T2_SEP_CONTROL_ENDPOINT     0
#define T2_SEP_AKS_ENDPOINT         7
#define T2_SEP_ACM_ENDPOINT         10
#define T2_SEP_CMSG_SET_OOL_IN      2
#define T2_SEP_CMSG_SET_OOL_OUT     3
#define T2_SEP_OOL_SIZE             0x4000
#define T2_SEP_DMA_BITS             44
#define T2_SEP_TIMEOUT_US           (5 * USEC_PER_SEC)
#define T2_SEP_AKS_GET_CAPABILITIES 0x4d
#define T2_SEP_AKS_HEADER_V1        1
#define T2_SEP_AKS_HEADER_V2        2
#define T2_SEP_AKS_HEADER_V1_SIZE   0x48
#define T2_SEP_AKS_HEADER_V2_SIZE   0x50
#define T2_SEP_AKS_V1_WIRE_SIZE     (sizeof(u32) + T2_SEP_AKS_HEADER_V1_SIZE)
#define T2_SEP_AKS_V2_WIRE_SIZE     (sizeof(u32) + T2_SEP_AKS_HEADER_V2_SIZE)
#define T2_SEP_AKS_CAP_REQ_SIZE     0x5c
#define T2_SEP_AKS_MAX_BODY_SIZE    (T2_SEP_OOL_SIZE - T2_SEP_AKS_V2_WIRE_SIZE)
#define T2_SEP_AKS_CDHASH_SIZE      20
#define T2_SEP_AKS_CDHASH_HEX_SIZE  (T2_SEP_AKS_CDHASH_SIZE * 2)

struct t2_sep_message {
	u32 word[4];
};

struct t2_sep_transport {
	struct pci_dev *pdev;
	void __iomem *bar;
	void *ool_in;
	dma_addr_t ool_in_dma;
	void *ool_out;
	dma_addr_t ool_out_dma;
	bool ool_in_registered;
	bool ool_out_registered;
	void *acm_ool_in;
	dma_addr_t acm_ool_in_dma;
	void *acm_ool_out;
	dma_addr_t acm_ool_out_dma;
	bool acm_ool_in_registered;
	bool acm_ool_out_registered;
	struct miscdevice aks_miscdev;
	struct miscdevice acm_miscdev;
	struct mutex exchange_lock;
	atomic_t acm_opened;
	u8 next_transaction;
	u64 acm_generation;
	bool acm_poisoned;
	bool acm_context_active;
	u8 acm_context[T2_ACM_CONTEXT_SIZE];
	bool misc_registered;
	bool acm_misc_registered;
};

static bool register_ool;
module_param(register_ool, bool, 0400);
MODULE_PARM_DESC(register_ool,
	"Register endpoint-7 coherent buffers with SEP (default: false)");

static bool probe_capabilities;
module_param(probe_capabilities, bool, 0400);
MODULE_PARM_DESC(probe_capabilities,
	"Issue one read-only AppleKeyStore capability query (default: false)");

static bool register_acm;
module_param(register_acm, bool, 0400);
MODULE_PARM_DESC(register_acm,
	"Register separate endpoint-10 ACM OOL buffers (default: false)");

static uint aks_platform_asid;
module_param(aks_platform_asid, uint, 0600);
MODULE_PARM_DESC(aks_platform_asid,
	"macOS audit-session ID stamped into verify-secret AKS headers (default: 0)");

static ulong aks_platform_proc_uniqueid;
module_param(aks_platform_proc_uniqueid, ulong, 0600);
MODULE_PARM_DESC(aks_platform_proc_uniqueid,
	"Synthetic process unique ID stamped into verify-secret AKS headers (default: 0)");

static char aks_platform_cdhash[T2_SEP_AKS_CDHASH_HEX_SIZE + 1];
module_param_string(aks_platform_cdhash, aks_platform_cdhash,
		    sizeof(aks_platform_cdhash), 0600);
MODULE_PARM_DESC(aks_platform_cdhash,
	"Optional 40-hex-character caller CDHash stamped into verify-secret AKS headers");

struct t2_aks_header_v1 {
	u8 digest[16];
	__le32 version;
	__le64 usec_time;
	__le32 flags;
	__le64 clock_id;
	u8 platform_data[0x20];
} __packed;

static_assert(sizeof(struct t2_aks_header_v1) == T2_SEP_AKS_HEADER_V1_SIZE);

struct t2_aks_header_v2 {
	struct t2_aks_header_v1 v1;
	__le64 calendar_seconds;
} __packed;

static_assert(sizeof(struct t2_aks_header_v2) == T2_SEP_AKS_HEADER_V2_SIZE);

static int t2_aks_stamp_verify_platform_data(struct t2_aks_header_v2 *header)
{
	u8 cdhash[T2_SEP_AKS_CDHASH_SIZE];
	size_t length;
	int ret;

	put_unaligned_le64(aks_platform_proc_uniqueid,
			     header->v1.platform_data);
	put_unaligned_le32(aks_platform_asid,
			     header->v1.platform_data + sizeof(__le64));

	length = strnlen(aks_platform_cdhash, sizeof(aks_platform_cdhash));
	if (!length)
		return 0;
	if (length != T2_SEP_AKS_CDHASH_HEX_SIZE)
		return -EINVAL;
	ret = hex2bin(cdhash, aks_platform_cdhash, sizeof(cdhash));
	if (ret)
		return ret;
	memcpy(header->v1.platform_data + sizeof(__le64) + sizeof(__le32),
	       cdhash, sizeof(cdhash));
	memzero_explicit(cdhash, sizeof(cdhash));
	return 0;
}

static int t2_sep_wait_outbox(struct t2_sep_transport *sep)
{
	unsigned int waited;

	for (waited = 0; waited < T2_SEP_TIMEOUT_US; waited += 100) {
		if (!(readl(sep->bar + T2_SEP_OUTBOX_STATUS) &
		      T2_SEP_OUTBOX_FULL))
			return 0;
		usleep_range(100, 200);
	}
	return -ETIMEDOUT;
}

static int t2_sep_send(struct t2_sep_transport *sep,
		       const struct t2_sep_message *message)
{
	int ret;

	ret = t2_sep_wait_outbox(sep);
	if (ret)
		return ret;

	/* AppleSEPIntelIOP posts the final word last; it is always zero. */
	writel(message->word[0], sep->bar + T2_SEP_OUTBOX_DATA + 0x0);
	writel(message->word[1], sep->bar + T2_SEP_OUTBOX_DATA + 0x4);
	writel(message->word[2], sep->bar + T2_SEP_OUTBOX_DATA + 0x8);
	writel(0, sep->bar + T2_SEP_OUTBOX_DATA + 0xc);
	return 0;
}

static int t2_sep_receive(struct t2_sep_transport *sep,
			  struct t2_sep_message *message)
{
	unsigned int waited;

	for (waited = 0; waited < T2_SEP_TIMEOUT_US; waited += 100) {
		if (!(readl(sep->bar + T2_SEP_INBOX_STATUS) &
		      T2_SEP_INBOX_EMPTY)) {
			message->word[0] = readl(sep->bar + T2_SEP_INBOX_DATA + 0x0);
			message->word[1] = readl(sep->bar + T2_SEP_INBOX_DATA + 0x4);
			message->word[2] = readl(sep->bar + T2_SEP_INBOX_DATA + 0x8);
			/* Reading the final word advances the hardware FIFO. */
			message->word[3] = readl(sep->bar + T2_SEP_INBOX_DATA + 0xc);
			return 0;
		}
		usleep_range(100, 200);
	}
	return -ETIMEDOUT;
}

static int t2_sep_control(struct t2_sep_transport *sep, u8 target_endpoint,
			  u8 opcode, u8 tag, dma_addr_t dma, size_t size)
{
	struct t2_sep_message request = { };
	struct t2_sep_message reply;
	unsigned int skipped = 0;
	u8 endpoint;
	int ret;

	if (!IS_ALIGNED(dma, SZ_4K) || dma >> T2_SEP_DMA_BITS || size > U32_MAX)
		return -ERANGE;

	/* EP0 wire layout: endpoint, tag, opcode, target endpoint. */
	request.word[0] = T2_SEP_CONTROL_ENDPOINT | (tag << 8) |
		(opcode << 16) | (target_endpoint << 24);
	request.word[1] = lower_32_bits(dma >> PAGE_SHIFT);
	request.word[2] = size;

	ret = t2_sep_send(sep, &request);
	if (ret)
		return ret;

	for (;;) {
		ret = t2_sep_receive(sep, &reply);
		if (ret)
			return ret;

		endpoint = FIELD_GET(T2_SEP_ENDPOINT_MASK, reply.word[0]);
		if (endpoint == T2_SEP_CONTROL_ENDPOINT &&
		    ((reply.word[0] >> 8) & 0xff) == tag)
			break;

		/* Do not expose asynchronous SEP payloads in the kernel log. */
		dev_dbg(&sep->pdev->dev,
			"queued unrelated mailbox message from endpoint %u\n",
			endpoint);
		if (++skipped == 32)
			return -EOVERFLOW;
	}

	if (reply.word[1]) {
		dev_err(&sep->pdev->dev,
			"control opcode %u returned SEP result %#x\n",
			opcode, reply.word[1]);
		return -EREMOTEIO;
	}
	return 0;
}

static int t2_aks_digest(void *message, size_t length)
{
	struct t2_aks_header_v1 *header = message + sizeof(__le32);
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 digest[SHA256_DIGEST_SIZE];
	u32 header_size;
	u32 version;
	int ret;

	if (length < sizeof(__le32) + sizeof(header->digest) + sizeof(header->version))
		return -EINVAL;
	header_size = get_unaligned_le32(message);
	version = le32_to_cpu(header->version);
	if ((version == T2_SEP_AKS_HEADER_V1 &&
	     header_size != T2_SEP_AKS_HEADER_V1_SIZE) ||
	    (version == T2_SEP_AKS_HEADER_V2 &&
	     header_size != T2_SEP_AKS_HEADER_V2_SIZE) ||
	    (version != T2_SEP_AKS_HEADER_V1 &&
	     version != T2_SEP_AKS_HEADER_V2) ||
	    length < sizeof(__le32) + header_size)
		return -EPROTO;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}
	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (!ret)
		ret = crypto_shash_update(desc, (u8 *)header + sizeof(header->digest),
					 header_size - sizeof(header->digest));
	if (!ret)
		ret = crypto_shash_update(desc,
					 message + sizeof(__le32) + header_size,
					 length - sizeof(__le32) - header_size);
	if (!ret)
		ret = crypto_shash_final(desc, digest);
	if (!ret)
		memcpy(header->digest, digest, sizeof(header->digest));

	memzero_explicit(digest, sizeof(digest));
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

static bool t2_aks_operation_allowed(u8 operation)
{
	switch (operation) {
	case 0x03: /* load_keybag */
	case 0x04: /* change_lock_state */
	case 0x0d: /* make_system_keybag */
	case 0x19: /* get_device_state */
	case 0x21: /* bounded verify_secret_v1, with optional ACM context */
	case T2_SEP_AKS_GET_CAPABILITIES:
		return true;
	default:
		return false;
	}
}

static int t2_aks_exchange_locked(struct t2_sep_transport *sep, u8 operation,
				  const void *request_body,
				  size_t request_body_length,
				  u8 **response_body,
				  size_t *response_body_length,
				  s8 *sep_status_out)
{
	struct t2_aks_header_v2 *header;
	struct t2_sep_message request = { };
	struct t2_sep_message reply;
	size_t request_length;
	u16 reply_length;
	s8 reply_status;
	u8 transaction;
	unsigned int skipped = 0;
	int ret;

	*sep_status_out = 0;
	if (!t2_aks_operation_allowed(operation))
		return -EACCES;
	if (operation == 0x21 &&
	    !t2_aks_verify_secret_v1_request_allowed(request_body,
						      request_body_length))
		return -EACCES;
	if (request_body_length > T2_SEP_AKS_MAX_BODY_SIZE)
		return -EMSGSIZE;

	request_length = T2_SEP_AKS_V2_WIRE_SIZE + request_body_length;
	memset(sep->ool_in, 0, T2_SEP_OOL_SIZE);
	memset(sep->ool_out, 0, T2_SEP_OOL_SIZE);
	put_unaligned_le32(T2_SEP_AKS_HEADER_V2_SIZE, sep->ool_in);
	header = sep->ool_in + sizeof(__le32);
	header->v1.version = cpu_to_le32(T2_SEP_AKS_HEADER_V2);
	header->v1.usec_time = cpu_to_le64(ktime_get_boottime_ns() /
					      NSEC_PER_USEC);
	header->calendar_seconds = cpu_to_le64(ktime_get_real_seconds());
	if (operation == 0x21) {
		ret = t2_aks_stamp_verify_platform_data(header);
		if (ret)
			return ret;
	}
	if (request_body_length)
		memcpy(sep->ool_in + T2_SEP_AKS_V2_WIRE_SIZE,
		       request_body, request_body_length);

	ret = t2_aks_digest(sep->ool_in, request_length);
	if (ret)
		return ret;

	transaction = ++sep->next_transaction;
	if (!transaction)
		transaction = ++sep->next_transaction;
	request.word[0] = T2_SEP_AKS_ENDPOINT | (operation << 8) |
		(transaction << 16);
	request.word[1] = request_length << 16;
	ret = t2_sep_send(sep, &request);
	if (ret)
		return ret;

	for (;;) {
		ret = t2_sep_receive(sep, &reply);
		if (ret)
			return ret;
		if ((reply.word[0] & 0xff) == T2_SEP_AKS_ENDPOINT &&
		    (((reply.word[0] >> 8) & 0xff) == (operation | 0x80)) &&
		    ((reply.word[0] >> 16) & 0xff) == transaction)
			break;
		if (++skipped == 32)
			return -EOVERFLOW;
	}

	/* EP7 reply: endpoint, operation|response, transaction, signed status. */
	reply_status = (s8)(reply.word[0] >> 24);
	if (reply_status) {
		*sep_status_out = reply_status;
		dev_err(&sep->pdev->dev,
			"AKS operation %#x returned SEP status %d (flags %#x)\n",
			operation, reply_status, reply.word[1] & 0xffff);
		return -EREMOTEIO;
	}
	reply_length = reply.word[1] >> 16;
	if (reply_length < T2_SEP_AKS_V2_WIRE_SIZE ||
	    reply_length > T2_SEP_OOL_SIZE) {
		dev_err(&sep->pdev->dev,
			"AKS operation %#x returned invalid envelope length %u (mailbox info %#x)\n",
			operation, reply_length, reply.word[1] & 0xffff);
		return -EPROTO;
	}
	if (get_unaligned_le32(sep->ool_out) != T2_SEP_AKS_HEADER_V2_SIZE ||
	    get_unaligned_le32(sep->ool_out + sizeof(__le32) + 0x10) !=
	    T2_SEP_AKS_HEADER_V2) {
		dev_err(&sep->pdev->dev,
			"AKS operation %#x returned invalid envelope metadata (size %#x version %#x)\n",
			operation, get_unaligned_le32(sep->ool_out),
			get_unaligned_le32(sep->ool_out + sizeof(__le32) + 0x10));
		return -EPROTO;
	}

	{
		u8 expected[16];

		memcpy(expected, sep->ool_out + sizeof(__le32), sizeof(expected));
		memset(sep->ool_out + sizeof(__le32), 0, sizeof(expected));
		ret = t2_aks_digest(sep->ool_out, reply_length);
		if (!ret && memcmp(expected,
				sep->ool_out + sizeof(__le32), sizeof(expected)))
			ret = -EBADMSG;
		memzero_explicit(expected, sizeof(expected));
	}
	if (ret)
		return ret;

	*response_body = sep->ool_out + T2_SEP_AKS_V2_WIRE_SIZE;
	*response_body_length = reply_length - T2_SEP_AKS_V2_WIRE_SIZE;
	return 0;
}

static long t2_aks_ioctl(struct file *file, unsigned int command,
			 unsigned long argument)
{
	struct miscdevice *misc = file->private_data;
	struct t2_sep_transport *sep = container_of(misc,
		struct t2_sep_transport, aks_miscdev);
	struct t2_aks_ioc_exchange exchange;
	void __user *user_argument = (void __user *)argument;
	void *request = NULL;
	u8 *response;
	size_t response_length;
	int ret;

	if (command != T2_AKS_IOC_EXCHANGE)
		return -ENOTTY;
	if (copy_from_user(&exchange, user_argument, sizeof(exchange)))
		return -EFAULT;
	if (exchange.sep_status ||
	    memchr_inv(exchange.reserved0, 0, sizeof(exchange.reserved0)))
		return -EINVAL;
	if (exchange.request_length > T2_SEP_AKS_MAX_BODY_SIZE ||
	    exchange.response_capacity > T2_SEP_AKS_MAX_BODY_SIZE)
		return -EMSGSIZE;
	if (exchange.operation == 0x21 &&
	    (exchange.response_capacity != 12 || !exchange.response))
		return -EACCES;
	if (exchange.request_length) {
		request = memdup_user(u64_to_user_ptr(exchange.request),
				      exchange.request_length);
		if (IS_ERR(request))
			return PTR_ERR(request);
	}

	ret = mutex_lock_interruptible(&sep->exchange_lock);
	if (ret)
		goto out_free;
	ret = t2_aks_exchange_locked(sep, exchange.operation, request,
				     exchange.request_length, &response,
				     &response_length, &exchange.sep_status);
	if (ret) {
		if (exchange.sep_status &&
		    copy_to_user(user_argument, &exchange, sizeof(exchange)))
			ret = -EFAULT;
		goto out_unlock;
	}
	if (response_length > exchange.response_capacity) {
		ret = -ENOSPC;
		goto out_set_length;
	}
	if (response_length && copy_to_user(u64_to_user_ptr(exchange.response),
					 response, response_length)) {
		ret = -EFAULT;
		goto out_unlock;
	}

out_set_length:
	exchange.response_length = response_length;
	if (copy_to_user(user_argument, &exchange, sizeof(exchange)))
		ret = -EFAULT;
out_unlock:
	mutex_unlock(&sep->exchange_lock);
out_free:
	if (request) {
		memzero_explicit(request, exchange.request_length);
		kfree(request);
	}
	return ret;
}

static const struct file_operations t2_aks_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = t2_aks_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static bool t2_acm_command_allowed(const u8 *request, size_t length)
{
	static const u8 prefix[] = { 'D', 'R', 'C', 'S' };

	if (length < 8 || memcmp(request, prefix, sizeof(prefix)) ||
	    request[5] != 0 || request[6] != 0 || request[7] != 1)
		return false;
	switch (request[4]) {
	case 0x01: /* legacy context create */
	case 0x24: /* context create with tracking */
		return length == 12; /* command header + appended effective UID */
	case 0x02: /* context destroy */
	case 0x13: /* externalize the active context */
		return length == 24; /* command header + 16-byte context */
	case 0x03: /* TouchIdEnrollment policy, empty parameter array */
		return length == 51 &&
			!memcmp(request + 24, "TouchIdEnrollment\0", 18) &&
			request[42] <= 1 &&
			!memchr_inv(request + 43, 0, 8);
	default:
		return false;
	}
}

static bool t2_acm_response_buffer_valid(const u8 *request,
					 u32 capacity, u64 response)
{
	return t2_acm_response_capacity_allowed(request[4], capacity,
						response != 0);
}

static void t2_acm_clear_context_locked(struct t2_sep_transport *sep)
{
	memzero_explicit(sep->acm_context, sizeof(sep->acm_context));
	sep->acm_context_active = false;
}

static void t2_acm_poison_locked(struct t2_sep_transport *sep)
{
	sep->acm_poisoned = true;
	if (!++sep->acm_generation)
		++sep->acm_generation;
	t2_acm_clear_context_locked(sep);
}

static int t2_acm_validate_context_locked(struct t2_sep_transport *sep,
					  const u8 *request)
{
	switch (t2_acm_context_preflight(request[4],
					 sep->acm_context_active)) {
	case T2_ACM_CONTEXT_ALLOW:
		return 0;
	case T2_ACM_CONTEXT_BUSY:
		return -EBUSY;
	case T2_ACM_CONTEXT_STALE:
		return -ESTALE;
	case T2_ACM_CONTEXT_MATCH_REQUIRED:
		return memcmp(request + 8, sep->acm_context,
			      sizeof(sep->acm_context)) ? -EACCES : 0;
	case T2_ACM_CONTEXT_DENY:
		return -EACCES;
	}
	return -EACCES;
}

static int t2_acm_record_reply_locked(struct t2_sep_transport *sep,
				      const u8 *request, const u8 *response,
				      size_t response_length, u32 response_info)
{
	switch (t2_acm_reply_action(request[4], response_length,
				   response_info)) {
	case T2_ACM_REPLY_ACCEPT:
		return 0;
	case T2_ACM_REPLY_REJECT:
		return -EPROTO;
	case T2_ACM_REPLY_POISON:
		/* SEP may have created a context whose handle is unavailable. */
		t2_acm_poison_locked(sep);
		return -EPROTO;
	case T2_ACM_REPLY_SET_CONTEXT:
		memcpy(sep->acm_context, response, sizeof(sep->acm_context));
		sep->acm_context_active = true;
		return 0;
	case T2_ACM_REPLY_SET_CONTEXT_AND_REJECT:
		memcpy(sep->acm_context, response, sizeof(sep->acm_context));
		sep->acm_context_active = true;
		return -EPROTO;
	case T2_ACM_REPLY_CLEAR_CONTEXT:
		t2_acm_clear_context_locked(sep);
		return 0;
	case T2_ACM_REPLY_CLEAR_CONTEXT_AND_REJECT:
		t2_acm_clear_context_locked(sep);
		return -EPROTO;
	}
	return -EPROTO;
}

static int t2_acm_exchange_locked(struct t2_sep_transport *sep,
				  u8 request_code, u32 request_info,
				  const void *request_body,
				  size_t request_body_length,
				  u8 **response_body,
				  size_t *response_body_length,
				  u32 *response_info)
{
	struct t2_sep_message request = { };
	struct t2_sep_message reply;
	unsigned int skipped = 0;
	u16 reply_length;
	int ret;

	if (request_code != 1 || request_info != 0 ||
	    request_body_length > T2_SEP_OOL_SIZE ||
	    !t2_acm_command_allowed(request_body, request_body_length))
		return -EACCES;

	memset(sep->acm_ool_in, 0, T2_SEP_OOL_SIZE);
	memset(sep->acm_ool_out, 0, T2_SEP_OOL_SIZE);
	memcpy(sep->acm_ool_in, request_body, request_body_length);
	request.word[0] = T2_SEP_ACM_ENDPOINT | (request_code << 8) |
		(request_body_length << 16);
	request.word[1] = request_info;
	ret = t2_sep_send(sep, &request);
	if (ret)
		return ret;

	for (;;) {
		ret = t2_sep_receive(sep, &reply);
		if (ret) {
			t2_acm_poison_locked(sep);
			return ret;
		}
		if ((reply.word[0] & 0xff) == T2_SEP_ACM_ENDPOINT &&
		    ((reply.word[0] >> 8) & 0xff) == request_code)
			break;
		if (++skipped == 32) {
			t2_acm_poison_locked(sep);
			return -EOVERFLOW;
		}
	}

	reply_length = reply.word[0] >> 16;
	if (reply_length > T2_SEP_OOL_SIZE) {
		t2_acm_poison_locked(sep);
		return -EPROTO;
	}
	*response_body = sep->acm_ool_out;
	*response_body_length = reply_length;
	*response_info = reply.word[1];
	return 0;
}

static long t2_acm_ioctl(struct file *file, unsigned int command,
			 unsigned long argument)
{
	struct miscdevice *misc = file->private_data;
	struct t2_sep_transport *sep = container_of(misc,
		struct t2_sep_transport, acm_miscdev);
	void __user *user_argument = (void __user *)argument;
	struct t2_acm_ioc_exchange exchange;
	struct t2_acm_ioc_info info = { };
	void *request = NULL;
	u8 *response = NULL;
	size_t response_length = 0;
	u32 response_info = 0;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (command == T2_ACM_IOC_GET_INFO) {
		ret = mutex_lock_interruptible(&sep->exchange_lock);
		if (ret)
			return ret;
		info.generation = sep->acm_generation;
		info.capacity = T2_SEP_OOL_SIZE;
		if (sep->acm_poisoned)
			info.flags |= T2_ACM_INFO_F_POISONED;
		mutex_unlock(&sep->exchange_lock);
		return copy_to_user(user_argument, &info, sizeof(info)) ?
			-EFAULT : 0;
	}
	if (command != T2_ACM_IOC_EXCHANGE)
		return -ENOTTY;
	if (copy_from_user(&exchange, user_argument, sizeof(exchange)))
		return -EFAULT;
	if (memchr_inv(exchange.reserved0, 0, sizeof(exchange.reserved0)) ||
	    !exchange.request_length ||
	    exchange.request_length > T2_SEP_OOL_SIZE ||
	    exchange.response_capacity > T2_SEP_OOL_SIZE || !exchange.request)
		return -EINVAL;
	request = memdup_user(u64_to_user_ptr(exchange.request),
			      exchange.request_length);
	if (IS_ERR(request))
		return PTR_ERR(request);
	if (!t2_acm_command_allowed(request, exchange.request_length) ||
	    !t2_acm_response_buffer_valid(request, exchange.response_capacity,
					  exchange.response)) {
		ret = -EACCES;
		goto out;
	}

	ret = mutex_lock_interruptible(&sep->exchange_lock);
	if (ret)
		goto out;
	if (exchange.generation != sep->acm_generation) {
		exchange.generation = sep->acm_generation;
		ret = -ESTALE;
		goto out_copy_exchange;
	}
	if (sep->acm_poisoned) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}
	ret = t2_acm_validate_context_locked(sep, request);
	if (ret)
		goto out_unlock;
	ret = t2_acm_exchange_locked(sep, exchange.request_code,
			exchange.request_info, request, exchange.request_length,
			&response, &response_length, &response_info);
	if (ret)
		goto out_unlock;
	exchange.response_length = response_length;
	exchange.response_info = response_info;
	ret = t2_acm_record_reply_locked(sep, request, response,
					 response_length, response_info);
	if (ret)
		goto out_copy_exchange;
	if (response_length > exchange.response_capacity) {
		ret = -ENOSPC;
		goto out_copy_exchange;
	}
	if (response_length && copy_to_user(u64_to_user_ptr(exchange.response),
					 response, response_length)) {
		ret = -EFAULT;
		goto out_unlock;
	}
out_copy_exchange:
	if (copy_to_user(user_argument, &exchange, sizeof(exchange)))
		ret = -EFAULT;
out_unlock:
	memzero_explicit(sep->acm_ool_in, T2_SEP_OOL_SIZE);
	memzero_explicit(sep->acm_ool_out, T2_SEP_OOL_SIZE);
	mutex_unlock(&sep->exchange_lock);
out:
	memzero_explicit(request, exchange.request_length);
	kfree(request);
	return ret;
}

static int t2_acm_open(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct t2_sep_transport *sep = container_of(misc,
		struct t2_sep_transport, acm_miscdev);
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (atomic_cmpxchg(&sep->acm_opened, 0, 1))
		return -EBUSY;
	ret = nonseekable_open(inode, file);
	if (ret)
		atomic_set(&sep->acm_opened, 0);
	return ret;
}

static int t2_acm_release(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct t2_sep_transport *sep = container_of(misc,
		struct t2_sep_transport, acm_miscdev);
	u8 request[8 + T2_ACM_CONTEXT_SIZE] = {
		'D', 'R', 'C', 'S', 0x02, 0, 0, 1,
	};
	u8 *response = NULL;
	size_t response_length = 0;
	u32 response_info = 0;
	int ret = 0;

	(void)inode;

	mutex_lock(&sep->exchange_lock);
	if (sep->acm_context_active && !sep->acm_poisoned) {
		memcpy(request + 8, sep->acm_context,
		       sizeof(sep->acm_context));
		ret = t2_acm_exchange_locked(sep, 1, 0, request,
					     sizeof(request), &response,
					     &response_length, &response_info);
		if (!ret && !response_info && !response_length)
			t2_acm_clear_context_locked(sep);
		else {
			dev_warn(&sep->pdev->dev,
				 "automatic ACM context cleanup failed; endpoint disabled until reboot\n");
			if (!sep->acm_poisoned)
				t2_acm_poison_locked(sep);
		}
	}
	memzero_explicit(sep->acm_ool_in, T2_SEP_OOL_SIZE);
	memzero_explicit(sep->acm_ool_out, T2_SEP_OOL_SIZE);
	mutex_unlock(&sep->exchange_lock);
	memzero_explicit(request, sizeof(request));
	atomic_set(&sep->acm_opened, 0);
	return 0;
}

static const struct file_operations t2_acm_fops = {
	.owner = THIS_MODULE,
	.open = t2_acm_open,
	.release = t2_acm_release,
	.unlocked_ioctl = t2_acm_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static int t2_aks_probe_capabilities(struct t2_sep_transport *sep)
{
	struct t2_aks_header_v1 *header;
	struct t2_sep_message request = { };
	struct t2_sep_message reply;
	u8 *payload;
	u16 reply_length;
	u8 transaction = 1;
	unsigned int skipped = 0;
	int ret;

	memset(sep->ool_in, 0, T2_SEP_OOL_SIZE);
	memset(sep->ool_out, 0, T2_SEP_OOL_SIZE);
	put_unaligned_le32(T2_SEP_AKS_HEADER_V1_SIZE, sep->ool_in);
	header = sep->ool_in + sizeof(__le32);
	header->version = cpu_to_le32(T2_SEP_AKS_HEADER_V1);
	header->usec_time = cpu_to_le64(ktime_get_boottime_ns() /
					   NSEC_PER_USEC);

	/* Request payload: result=0, selector=1, empty input blob. */
	payload = sep->ool_in + T2_SEP_AKS_V1_WIRE_SIZE;
	put_unaligned_le32(0, payload);
	put_unaligned_le64(1, payload + sizeof(__le32));
	put_unaligned_le32(0, payload + sizeof(__le32) + sizeof(__le64));
	ret = t2_aks_digest(sep->ool_in, T2_SEP_AKS_CAP_REQ_SIZE);
	if (ret)
		return ret;

	/* EP7 descriptor: endpoint, operation, transaction, OOL length at +6. */
	request.word[0] = T2_SEP_AKS_ENDPOINT |
		(T2_SEP_AKS_GET_CAPABILITIES << 8) | (transaction << 16);
	request.word[1] = T2_SEP_AKS_CAP_REQ_SIZE << 16;
	ret = t2_sep_send(sep, &request);
	if (ret)
		return ret;

	for (;;) {
		ret = t2_sep_receive(sep, &reply);
		if (ret)
			return ret;
		if ((reply.word[0] & 0xff) == T2_SEP_AKS_ENDPOINT &&
		    (((reply.word[0] >> 8) & 0x7f) ==
		     T2_SEP_AKS_GET_CAPABILITIES) &&
		    ((reply.word[0] >> 16) & 0xff) == transaction)
			break;
		if (++skipped == 32)
			return -EOVERFLOW;
	}

	reply_length = reply.word[1] >> 16;
	if (reply_length < T2_SEP_AKS_V1_WIRE_SIZE ||
	    reply_length > T2_SEP_OOL_SIZE)
		return -EPROTO;
	if (get_unaligned_le32(sep->ool_out) != T2_SEP_AKS_HEADER_V1_SIZE ||
	    get_unaligned_le32(sep->ool_out + sizeof(__le32) + 0x10) !=
	    T2_SEP_AKS_HEADER_V1)
		return -EPROTO;

	/* Recompute in a scratch copy so malformed replies never look valid. */
	{
		u8 expected[16];

		memcpy(expected, sep->ool_out + sizeof(__le32), sizeof(expected));
		memset(sep->ool_out + sizeof(__le32), 0, sizeof(expected));
		ret = t2_aks_digest(sep->ool_out, reply_length);
		if (!ret && memcmp(expected,
				sep->ool_out + sizeof(__le32), sizeof(expected)))
			ret = -EBADMSG;
		memzero_explicit(expected, sizeof(expected));
	}
	if (ret)
		return ret;
	if (reply_length < T2_SEP_AKS_CAP_REQ_SIZE)
		return -EPROTO;
	payload = sep->ool_out + T2_SEP_AKS_V1_WIRE_SIZE;
	if (get_unaligned_le32(payload)) {
		dev_warn(&sep->pdev->dev,
			 "AppleKeyStore capability query returned status %#x\n",
			 get_unaligned_le32(payload));
		return -EREMOTEIO;
	}

	dev_info(&sep->pdev->dev,
		 "AppleKeyStore capability reply passed integrity check: value=%#llx length=%u\n",
		 (unsigned long long)get_unaligned_le64(payload + sizeof(__le32)),
		 reply_length);
	return 0;
}

static void t2_sep_free_ool(struct t2_sep_transport *sep)
{
	if (sep->acm_ool_out)
		dma_free_coherent(&sep->pdev->dev, T2_SEP_OOL_SIZE,
				  sep->acm_ool_out, sep->acm_ool_out_dma);
	if (sep->acm_ool_in)
		dma_free_coherent(&sep->pdev->dev, T2_SEP_OOL_SIZE,
				  sep->acm_ool_in, sep->acm_ool_in_dma);
	if (sep->ool_out)
		dma_free_coherent(&sep->pdev->dev, T2_SEP_OOL_SIZE,
				  sep->ool_out, sep->ool_out_dma);
	if (sep->ool_in)
		dma_free_coherent(&sep->pdev->dev, T2_SEP_OOL_SIZE,
				  sep->ool_in, sep->ool_in_dma);
}

static int t2_sep_probe(struct pci_dev *pdev,
			const struct pci_device_id *id)
{
	struct t2_sep_transport *sep;
	u32 inbox, outbox;
	int ret;

	if (pci_resource_len(pdev, T2_SEP_MAILBOX_BAR) < T2_SEP_BAR_MIN_SIZE)
		return -ENODEV;

	ret = pcim_enable_device(pdev);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "cannot enable PCI function\n");

	ret = pcim_iomap_regions(pdev, BIT(T2_SEP_MAILBOX_BAR),
				 "t2_sep_transport");
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "cannot map BAR4\n");

	sep = devm_kzalloc(&pdev->dev, sizeof(*sep), GFP_KERNEL);
	if (!sep)
		return -ENOMEM;
	sep->pdev = pdev;
	sep->bar = pcim_iomap_table(pdev)[T2_SEP_MAILBOX_BAR];
	if (!sep->bar)
		return -ENODEV;
	mutex_init(&sep->exchange_lock);
	atomic_set(&sep->acm_opened, 0);
	pci_set_drvdata(pdev, sep);

	inbox = readl(sep->bar + T2_SEP_INBOX_STATUS);
	outbox = readl(sep->bar + T2_SEP_OUTBOX_STATUS);
	dev_info(&pdev->dev, "mailbox inbox=%#x empty=%u outbox=%#x full=%u\n",
		 inbox, !!(inbox & T2_SEP_INBOX_EMPTY),
		 outbox, !!(outbox & T2_SEP_OUTBOX_FULL));

	if (!register_ool) {
		dev_info(&pdev->dev,
			 "observation-only mode; no DMA allocation or MMIO writes\n");
		return 0;
	}

	ret = dma_set_mask_and_coherent(&pdev->dev,
					DMA_BIT_MASK(T2_SEP_DMA_BITS));
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "no usable 44-bit DMA mask\n");
	pci_set_master(pdev);

	sep->ool_in = dma_alloc_coherent(&pdev->dev, T2_SEP_OOL_SIZE,
					 &sep->ool_in_dma, GFP_KERNEL);
	if (!sep->ool_in)
		return -ENOMEM;
	sep->ool_out = dma_alloc_coherent(&pdev->dev, T2_SEP_OOL_SIZE,
					  &sep->ool_out_dma, GFP_KERNEL);
	if (!sep->ool_out) {
		ret = -ENOMEM;
		goto err_free_ool;
	}
	if (register_acm) {
		sep->acm_ool_in = dma_alloc_coherent(&pdev->dev,
			T2_SEP_OOL_SIZE, &sep->acm_ool_in_dma, GFP_KERNEL);
		if (!sep->acm_ool_in) {
			ret = -ENOMEM;
			goto err_free_ool;
		}
		sep->acm_ool_out = dma_alloc_coherent(&pdev->dev,
			T2_SEP_OOL_SIZE, &sep->acm_ool_out_dma, GFP_KERNEL);
		if (!sep->acm_ool_out) {
			ret = -ENOMEM;
			goto err_free_ool;
		}
	}

	ret = t2_sep_control(sep, T2_SEP_AKS_ENDPOINT,
			 T2_SEP_CMSG_SET_OOL_IN, 1,
				 sep->ool_in_dma, T2_SEP_OOL_SIZE);
	if (ret)
		goto err_free_ool;
	sep->ool_in_registered = true;
	ret = t2_sep_control(sep, T2_SEP_AKS_ENDPOINT,
			 T2_SEP_CMSG_SET_OOL_OUT, 2,
				 sep->ool_out_dma, T2_SEP_OOL_SIZE);
	if (ret) {
		/*
		 * SEP now retains ool_in_dma.  Never free or unload backing memory
		 * after a successful registration, even when the second control call
		 * fails.  A reboot clears the volatile SEP registration.
		 */
		dev_err(&pdev->dev,
			"OOL input registered but output registration failed; reboot before retry\n");
		__module_get(THIS_MODULE);
		return 0;
	}
	sep->ool_out_registered = true;
	if (register_acm) {
		ret = t2_sep_control(sep, T2_SEP_ACM_ENDPOINT,
				 T2_SEP_CMSG_SET_OOL_IN, 3,
				 sep->acm_ool_in_dma, T2_SEP_OOL_SIZE);
		if (ret) {
			dev_err(&pdev->dev,
				"endpoint-7 registered but ACM input registration failed; reboot before retry\n");
			__module_get(THIS_MODULE);
			return 0;
		}
		sep->acm_ool_in_registered = true;
		ret = t2_sep_control(sep, T2_SEP_ACM_ENDPOINT,
				 T2_SEP_CMSG_SET_OOL_OUT, 4,
				 sep->acm_ool_out_dma, T2_SEP_OOL_SIZE);
		if (ret) {
			dev_err(&pdev->dev,
				"ACM input registered but output registration failed; reboot before retry\n");
			__module_get(THIS_MODULE);
			return 0;
		}
		sep->acm_ool_out_registered = true;
		sep->acm_generation = 1;
	}
	/* SEP retains both DMA addresses, so prevent unsafe module removal. */
	__module_get(THIS_MODULE);

	dev_info(&pdev->dev,
		 "registered 16 KiB endpoint-7 OOL input/output buffers\n");
	if (probe_capabilities) {
		ret = t2_aks_probe_capabilities(sep);
		if (ret)
			dev_warn(&pdev->dev,
				 "read-only capability query failed: %d\n", ret);
		else
			sep->next_transaction = 1;
	}

	sep->aks_miscdev.minor = MISC_DYNAMIC_MINOR;
	sep->aks_miscdev.name = "t2-aks";
	sep->aks_miscdev.fops = &t2_aks_fops;
	sep->aks_miscdev.parent = &pdev->dev;
	sep->aks_miscdev.mode = 0600;
	ret = misc_register(&sep->aks_miscdev);
	if (ret)
		dev_warn(&pdev->dev,
			 "cannot register root-only AppleKeyStore exchange device: %d\n",
			 ret);
	else {
		sep->misc_registered = true;
		dev_info(&pdev->dev,
			 "root-only /dev/t2-aks exchange enabled for whitelisted operations\n");
	}
	if (register_acm) {
		sep->acm_miscdev.minor = MISC_DYNAMIC_MINOR;
		sep->acm_miscdev.name = "t2-acm";
		sep->acm_miscdev.fops = &t2_acm_fops;
		sep->acm_miscdev.parent = &pdev->dev;
		sep->acm_miscdev.mode = 0600;
		ret = misc_register(&sep->acm_miscdev);
		if (ret)
			dev_warn(&pdev->dev,
				 "cannot register root-only ACM exchange device: %d\n",
				 ret);
		else {
			sep->acm_misc_registered = true;
			dev_info(&pdev->dev,
				 "root-only generation-pinned /dev/t2-acm enabled\n");
		}
	}
	return 0;

err_free_ool:
	t2_sep_free_ool(sep);
	sep->ool_in = NULL;
	sep->ool_out = NULL;
	pci_clear_master(pdev);
	return ret;
}

static void t2_sep_remove(struct pci_dev *pdev)
{
	struct t2_sep_transport *sep = pci_get_drvdata(pdev);

	if (!sep || !register_ool)
		return;
	if (sep->misc_registered)
		misc_deregister(&sep->aks_miscdev);
	if (sep->acm_misc_registered)
		misc_deregister(&sep->acm_miscdev);
	if (sep->ool_in_registered || sep->ool_out_registered ||
	    sep->acm_ool_in_registered || sep->acm_ool_out_registered) {
		dev_warn(&pdev->dev,
			 "retaining SEP-registered DMA memory until reboot\n");
		return;
	}
	t2_sep_free_ool(sep);
	pci_clear_master(pdev);
}

static const struct pci_device_id t2_sep_ids[] = {
	{ PCI_DEVICE(T2_SEP_VENDOR_ID, T2_SEP_DEVICE_ID) },
	{ }
};
MODULE_DEVICE_TABLE(pci, t2_sep_ids);

static struct pci_driver t2_sep_driver = {
	.name = "t2_sep_transport",
	.id_table = t2_sep_ids,
	.probe = t2_sep_probe,
	.remove = t2_sep_remove,
};
module_pci_driver(t2_sep_driver);

MODULE_AUTHOR("T2 Touch ID Linux research project");
MODULE_DESCRIPTION("Staged Apple T2 SEP mailbox and OOL transport");
MODULE_LICENSE("GPL");
