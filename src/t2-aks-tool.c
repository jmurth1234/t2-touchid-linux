// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "t2_sep_transport_uapi.h"

static uint32_t get_le32(const unsigned char *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
	       (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t get_le64(const unsigned char *p)
{
	return (uint64_t)get_le32(p) | (uint64_t)get_le32(p + 4) << 32;
}

static void put_le32(unsigned char *p, uint32_t value)
{
	p[0] = value;
	p[1] = value >> 8;
	p[2] = value >> 16;
	p[3] = value >> 24;
}

static void put_le64(unsigned char *p, uint64_t value)
{
	put_le32(p, value);
	put_le32(p + 4, value >> 32);
}

static int capabilities(int fd)
{
	unsigned char request[16] = { 0 };
	unsigned char response[256] = { 0 };
	struct t2_aks_ioc_exchange exchange = {
		.operation = 0x4d,
		.request_length = sizeof(request),
		.response_capacity = sizeof(response),
		.request = (uintptr_t)request,
		.response = (uintptr_t)response,
	};
	uint32_t status;
	uint64_t value;

	request[4] = 1; /* selector qword = 1 */
	if (ioctl(fd, T2_AKS_IOC_EXCHANGE, &exchange) < 0) {
		perror("T2_AKS_IOC_EXCHANGE");
		return 1;
	}
	if (exchange.response_length < 16) {
		fprintf(stderr, "short capability response: %u bytes\n",
			exchange.response_length);
		return 1;
	}
	status = get_le32(response);
	value = get_le64(response + 4);
	if (status) {
		fprintf(stderr, "AppleKeyStore status: %#x\n", status);
		return 1;
	}
	printf("capabilities=%#llx response_length=%u\n",
	       (unsigned long long)value, exchange.response_length);
	return value == 2 ? 0 : 1;
}

static int load_keybag(int fd, const char *input_path, const char *session_text)
{
	unsigned char *request = NULL;
	unsigned char response[256] = { 0 };
	struct t2_aks_ioc_exchange exchange = {
		.operation = 0x03,
		.response_capacity = sizeof(response),
		.response = (uintptr_t)response,
	};
	long size;
	size_t padded_size = 0;
	uint32_t status;
	int32_t handle;
	FILE *input = NULL;
	unsigned long long session = 0;
	char *end = NULL;
	int ret = 1;

	if (session_text) {
		errno = 0;
		session = strtoull(session_text, &end, 0);
		if (errno || !end || *end) {
			fprintf(stderr, "invalid session: %s\n", session_text);
			goto out;
		}
	}

	input = fopen(input_path, "rb");
	if (!input) {
		perror("open keybag");
		goto out;
	}
	if (fseek(input, 0, SEEK_END) || (size = ftell(input)) < 0 ||
	    fseek(input, 0, SEEK_SET)) {
		perror("size keybag");
		goto out;
	}
	if (!size || size > 16000) {
		fprintf(stderr, "invalid keybag size: %ld\n", size);
		goto out;
	}
	padded_size = ((size_t)size + 3) & ~(size_t)3;
	request = calloc(1, 16 + padded_size);
	if (!request) {
		perror("allocate request");
		goto out;
	}
	/* result=0, session/context, then length-prefixed saved bag bytes. */
	put_le64(request + 4, session);
	put_le32(request + 12, (uint32_t)size);
	if (fread(request + 16, 1, (size_t)size, input) != (size_t)size) {
		perror("read keybag");
		goto out;
	}
	exchange.request_length = 16 + (uint32_t)padded_size;
	exchange.request = (uintptr_t)request;
	if (ioctl(fd, T2_AKS_IOC_EXCHANGE, &exchange) < 0) {
		perror("T2_AKS_IOC_EXCHANGE");
		goto out;
	}
	if (exchange.response_length < 8) {
		fprintf(stderr, "short load-keybag response: %u bytes\n",
			exchange.response_length);
		goto out;
	}
	status = get_le32(response);
	handle = (int32_t)get_le32(response + 4);
	printf("status=%#x handle=%d response_length=%u\n", status, handle,
	       exchange.response_length);
	ret = status ? 1 : 0;
out:
	if (request) {
		memset(request, 0, 16 + padded_size);
		free(request);
	}
	if (input)
		fclose(input);
	return ret;
}

static int parse_u64(const char *text, uint64_t *value)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(text, &end, 0);
	if (errno || !end || *end)
		return -1;
	*value = parsed;
	return 0;
}

static int parse_handle(const char *text, int32_t *value)
{
	char *end = NULL;
	long parsed;

	errno = 0;
	parsed = strtol(text, &end, 0);
	if (errno || !end || *end || !parsed || parsed < INT32_MIN ||
	    parsed > INT32_MAX)
		return -1;
	*value = (int32_t)parsed;
	return 0;
}

static int write_private_output(const char *path, const unsigned char *data,
				size_t length)
{
	int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
	size_t offset = 0;
	int output;

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
	output = open(path, flags, 0600);
	if (output < 0) {
		perror("open output");
		return -1;
	}
	while (offset < length) {
		ssize_t written = write(output, data + offset, length - offset);

		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0) {
			perror("write output");
			close(output);
			unlink(path);
			return -1;
		}
		offset += (size_t)written;
	}
	if (close(output)) {
		perror("close output");
		unlink(path);
		return -1;
	}
	return 0;
}

static int build_copy_keybag_uuid_request(uint64_t session, int32_t handle,
					  unsigned char request[16])
{
	if (session != 1 || !handle || !request)
		return -1;
	memset(request, 0, 16);
	put_le64(request + 4, session);
	put_le32(request + 12, (uint32_t)handle);
	return 0;
}

static int copy_keybag_uuid(int fd, const char *session_text,
			    const char *handle_text, const char *output_path)
{
	unsigned char request[16];
	unsigned char response[24] = { 0 };
	struct t2_aks_ioc_exchange exchange = {
		.operation = 0x06,
		.request_length = sizeof(request),
		.response_capacity = sizeof(response),
		.request = (uintptr_t)request,
		.response = (uintptr_t)response,
	};
	uint64_t session;
	int32_t handle;
	uint32_t status, blob_length;

	if (parse_u64(session_text, &session) ||
	    parse_handle(handle_text, &handle) ||
	    build_copy_keybag_uuid_request(session, handle, request)) {
		fprintf(stderr, "invalid copy-keybag-uuid target\n");
		return 2;
	}
	if (ioctl(fd, T2_AKS_IOC_EXCHANGE, &exchange) < 0) {
		if (exchange.sep_status == -3) {
			printf("present=false\n");
			return 3;
		}
		if (exchange.sep_status)
			fprintf(stderr, "copy-keybag-uuid: SEP status %d\n",
				exchange.sep_status);
		else
			perror("T2_AKS_IOC_EXCHANGE");
		return 1;
	}
	if (exchange.response_length != sizeof(response)) {
		fprintf(stderr, "invalid copy-keybag-uuid response length: %u\n",
			exchange.response_length);
		return 1;
	}
	status = get_le32(response);
	blob_length = get_le32(response + 4);
	if (status == (uint32_t)(int32_t)-3) {
		printf("present=false\n");
		return 3;
	}
	if (status || blob_length != 16) {
		fprintf(stderr,
			"invalid copy-keybag-uuid response: status=%#x blob_length=%u\n",
			status, blob_length);
		return 1;
	}
	if (!memcmp(response + 8, (unsigned char[16]) { 0 }, 16)) {
		fprintf(stderr, "copy-keybag-uuid returned a zero UUID\n");
		return 1;
	}
	if (write_private_output(output_path, response + 8, 16))
		return 1;
	printf("present=true uuid_length=16 response_length=%u\n",
	       exchange.response_length);
	return 0;
}

static int set_system_keybag(int fd, const char *session_text,
			     const char *handle_text, const char *special_text)
{
	unsigned char request[24] = { 0 };
	unsigned char response[64] = { 0 };
	struct t2_aks_ioc_exchange exchange = {
		.operation = 0x0d,
		.request_length = sizeof(request),
		.response_capacity = sizeof(response),
		.request = (uintptr_t)request,
		.response = (uintptr_t)response,
	};
	uint64_t session, handle;
	long special;
	char *end = NULL;

	if (parse_u64(session_text, &session) ||
	    parse_u64(handle_text, &handle) || handle > UINT32_MAX) {
		fprintf(stderr, "invalid session, handle, or special-bag value\n");
		return 2;
	}
	errno = 0;
	special = strtol(special_text, &end, 0);
	if (errno || !end || *end || special < INT32_MIN || special > INT32_MAX) {
		fprintf(stderr, "invalid special-bag value\n");
		return 2;
	}
	put_le64(request + 4, session);
	put_le32(request + 12, (uint32_t)handle);
	put_le32(request + 16, (uint32_t)(int32_t)special);
	/* The final empty blob is encoded as a zero length word at +20. */
	if (ioctl(fd, T2_AKS_IOC_EXCHANGE, &exchange) < 0) {
		perror("T2_AKS_IOC_EXCHANGE");
		return 1;
	}
	if (exchange.response_length < 4) {
		fprintf(stderr, "short set-system response: %u bytes\n",
			exchange.response_length);
		return 1;
	}
	printf("status=%#x response_length=%u\n", get_le32(response),
	       exchange.response_length);
	return get_le32(response) ? 1 : 0;
}

static int unlock_keybag(int fd, const char *session_text,
			 const char *handle_text, int password_stdin)
{
	unsigned char *request = NULL;
	unsigned char response[64] = { 0 };
	struct t2_aks_ioc_exchange exchange = {
		.operation = 0x04,
		.response_capacity = sizeof(response),
		.response = (uintptr_t)response,
	};
	struct termios old_term, noecho_term;
	uint64_t session;
	long handle;
	char *end = NULL;
	char secret[1024];
	size_t length, padded_length;
	int tty = -1, ret = 1;
	ssize_t got;

	memset(secret, 0, sizeof(secret));
	if (parse_u64(session_text, &session)) {
		fprintf(stderr, "invalid session or handle\n");
		return 2;
	}
	errno = 0;
	handle = strtol(handle_text, &end, 0);
	if (errno || !end || *end || handle < INT32_MIN || handle > INT32_MAX) {
		fprintf(stderr, "invalid session or handle\n");
		return 2;
	}
	if (password_stdin) {
		tty = STDIN_FILENO;
	} else {
		tty = open("/dev/tty", O_RDWR | O_CLOEXEC);
		if (tty < 0 || tcgetattr(tty, &old_term)) {
			perror("open controlling terminal");
			goto out;
		}
		noecho_term = old_term;
		noecho_term.c_lflag &= ~(ECHO);
		if (tcsetattr(tty, TCSAFLUSH, &noecho_term)) {
			perror("disable terminal echo");
			goto out;
		}
		if (write(tty, "macOS login password: ", 22) != 22) {
			perror("write prompt");
			tcsetattr(tty, TCSAFLUSH, &old_term);
			goto out;
		}
	}
	got = read(tty, secret, sizeof(secret) - 1);
	if (!password_stdin) {
		tcsetattr(tty, TCSAFLUSH, &old_term);
		if (write(tty, "\n", 1) != 1)
			perror("write newline");
	}
	if (got <= 0) {
		fprintf(stderr, "failed to read password\n");
		goto out;
	}
	length = strcspn(secret, "\r\n");
	if (!length) {
		fprintf(stderr, "empty password\n");
		goto out;
	}
	padded_length = (length + 3) & ~(size_t)3;
	request = calloc(1, 24 + padded_length);
	if (!request) {
		perror("allocate unlock request");
		goto out;
	}
	/* result, session, handle, lock-state=0 (unlock), then secret blob. */
	put_le64(request + 4, session);
	put_le32(request + 12, (uint32_t)(int32_t)handle);
	/* request + 16 remains the zero lock-state word. */
	put_le32(request + 20, (uint32_t)length);
	memcpy(request + 24, secret, length);
	exchange.request_length = 24 + (uint32_t)padded_length;
	exchange.request = (uintptr_t)request;
	if (ioctl(fd, T2_AKS_IOC_EXCHANGE, &exchange) < 0) {
		perror("T2_AKS_IOC_EXCHANGE");
		goto out;
	}
	if (exchange.response_length < 4) {
		fprintf(stderr, "short unlock response: %u bytes\n",
			exchange.response_length);
		goto out;
	}
	printf("status=%#x response_length=%u\n", get_le32(response),
	       exchange.response_length);
	ret = get_le32(response) ? 1 : 0;
out:
	if (request) {
		memset(request, 0, exchange.request_length);
		free(request);
	}
	memset(secret, 0, sizeof(secret));
	if (tty >= 0 && !password_stdin)
		close(tty);
	return ret;
}

static int build_verify_password_acm_request(uint64_t session, int32_t handle,
					     const unsigned char *secret,
					     size_t secret_length,
					     const unsigned char context[16],
					     unsigned char **request_out,
					     uint32_t *request_length_out)
{
	unsigned char *request;
	size_t context_length, padded_length, request_length;

	if (!secret || !secret_length || secret_length > 128 ||
	    !request_out || !request_length_out || !handle)
		return -1;
	context_length = context ? 16 : 0;
	padded_length = (secret_length + 3) & ~(size_t)3;
	request_length = 32 + padded_length + context_length;
	request = calloc(1, request_length);
	if (!request)
		return -1;
	put_le32(request, 1); /* verify-secret codec version */
	put_le64(request + 4, session);
	put_le32(request + 12, (uint32_t)handle);
	put_le32(request + 16, (uint32_t)secret_length);
	memcpy(request + 20, secret, secret_length);
	put_le32(request + 20 + padded_length, (uint32_t)context_length);
	if (context)
		memcpy(request + 24 + padded_length, context, context_length);
	/* Selector 42 always supplies plaintext-secret device option 0x200. */
	put_le64(request + 24 + padded_length + context_length, 0x200);
	*request_out = request;
	*request_length_out = (uint32_t)request_length;
	return 0;
}

static int read_password_input(char secret[129], size_t *length_out,
			       int password_stdin)
{
	struct termios old_term, noecho_term;
	ssize_t got;
	int input = STDIN_FILENO;
	int ret = -1;

	if (!password_stdin) {
		input = open("/dev/tty", O_RDWR | O_CLOEXEC);
		if (input < 0 || tcgetattr(input, &old_term)) {
			perror("open controlling terminal");
			goto out;
		}
		noecho_term = old_term;
		noecho_term.c_lflag &= ~ECHO;
		if (tcsetattr(input, TCSAFLUSH, &noecho_term)) {
			perror("disable terminal echo");
			goto out;
		}
		if (write(input, "macOS login password: ", 22) != 22) {
			perror("write prompt");
			(void)tcsetattr(input, TCSAFLUSH, &old_term);
			goto out;
		}
	}
	/* Keep the final byte zero so strcspn never reads past the buffer. */
	got = read(input, secret, 128);
	if (!password_stdin) {
		(void)tcsetattr(input, TCSAFLUSH, &old_term);
		if (write(input, "\n", 1) != 1)
			perror("write newline");
	}
	if (got <= 0) {
		fprintf(stderr, "failed to read password\n");
		goto out;
	}
	*length_out = strcspn(secret, "\r\n");
	if (!*length_out || *length_out > 128) {
		fprintf(stderr, "password length is outside 1..128 bytes\n");
		goto out;
	}
	ret = 0;
out:
	if (!password_stdin && input >= 0)
		close(input);
	return ret;
}

static int read_verify_password_inputs(unsigned char context[16],
				       char secret[129], size_t *length_out)
{
	ssize_t got = 0;

	for (size_t offset = 0; offset < 16;) {
		got = read(STDIN_FILENO, context + offset, 16 - offset);
		if (got < 0 && errno == EINTR)
			continue;
		if (got <= 0)
			break;
		offset += (size_t)got;
		if (offset == 16)
			got = 16;
	}
	if (got != 16) {
		fprintf(stderr, "expected exactly 16 context bytes on stdin\n");
		return -1;
	}
	return read_password_input(secret, length_out, 0);
}

static int exchange_verify_password_acm(int fd, uint64_t session,
					int32_t handle,
					const unsigned char *secret,
					size_t secret_length,
					const unsigned char context[16],
					const char *label)
{
	unsigned char response[12] = { 0 };
	unsigned char *request = NULL;
	struct t2_aks_ioc_exchange exchange = {
		.operation = 0x21,
		.response_capacity = sizeof(response),
		.response = (uintptr_t)response,
	};
	int ret = 1;

	if (build_verify_password_acm_request(session, handle, secret,
					      secret_length, context,
					      &request,
					      &exchange.request_length)) {
		fprintf(stderr, "%s: failed to allocate verify request\n", label);
		goto out;
	}
	exchange.request = (uintptr_t)request;
	if (ioctl(fd, T2_AKS_IOC_EXCHANGE, &exchange) < 0) {
		if (exchange.sep_status)
			fprintf(stderr, "%s: SEP status %d\n", label,
				exchange.sep_status);
		else
			fprintf(stderr, "%s: %s\n", label, strerror(errno));
		goto out;
	}
	if (exchange.response_length != sizeof(response) ||
	    get_le32(response) != 1) {
		fprintf(stderr, "%s: invalid verify-secret response\n", label);
		goto out;
	}
	printf("%s: status=0 response_length=%u\n", label,
	       exchange.response_length);
	ret = 0;
out:
	if (request) {
		memset(request, 0, exchange.request_length);
		free(request);
	}
	memset(response, 0, sizeof(response));
	return ret;
}

static int verify_password_acm(int fd, const char *session_text,
			       const char *handle_text)
{
	unsigned char context[16] = { 0 };
	char secret[129] = { 0 };
	char *end = NULL;
	uint64_t session;
	long handle;
	size_t length;
	int ret = 1;

	if (parse_u64(session_text, &session)) {
		fprintf(stderr, "invalid AKS session\n");
		return 2;
	}
	errno = 0;
	handle = strtol(handle_text, &end, 0);
	if (errno || !end || *end || !handle || handle < INT32_MIN ||
	    handle > INT32_MAX) {
		fprintf(stderr, "invalid keybag handle\n");
		return 2;
	}
	if (read_verify_password_inputs(context, secret, &length))
		goto out;
	ret = exchange_verify_password_acm(fd, session, (int32_t)handle,
					   (unsigned char *)secret, length,
					   context, "verify-password-acm");
out:
	memset(secret, 0, sizeof(secret));
	memset(context, 0, sizeof(context));
	return ret;
}

static int verify_password_only(int fd, const char *session_text,
				const char *handle_text, int password_stdin)
{
	char secret[129] = { 0 };
	char *end = NULL;
	uint64_t session;
	long handle;
	size_t length = 0;
	int ret = 1;

	if (parse_u64(session_text, &session) || !session) {
		fprintf(stderr, "invalid AKS session\n");
		return 2;
	}
	errno = 0;
	handle = strtol(handle_text, &end, 0);
	if (errno || !end || *end || !handle || handle < INT32_MIN ||
	    handle > INT32_MAX) {
		fprintf(stderr, "invalid keybag handle\n");
		return 2;
	}
	if (read_password_input(secret, &length, password_stdin))
		goto out;
	ret = exchange_verify_password_acm(fd, session, (int32_t)handle,
					   (unsigned char *)secret, length,
					   NULL, "verify-password-only");
out:
	memset(secret, 0, sizeof(secret));
	return ret;
}

static int verify_password_acm_matrix(int fd, const char *session_text,
				      const char *special_text,
				      const char *positive_text)
{
	unsigned char context[16] = { 0 };
	char secret[129] = { 0 };
	char *end = NULL;
	uint64_t session;
	long special, positive;
	size_t length = 0;
	int current_ret, special_ret, positive_ret;
	int ret = 1;

	if (parse_u64(session_text, &session)) {
		fprintf(stderr, "invalid AKS session\n");
		return 2;
	}
	errno = 0;
	special = strtol(special_text, &end, 0);
	if (errno || !end || *end || special >= 0 || special < INT32_MIN) {
		fprintf(stderr, "invalid negative special handle\n");
		return 2;
	}
	errno = 0;
	end = NULL;
	positive = strtol(positive_text, &end, 0);
	if (errno || !end || *end || positive <= 0 || positive > INT32_MAX) {
		fprintf(stderr, "invalid positive runtime handle\n");
		return 2;
	}
	if (read_verify_password_inputs(context, secret, &length))
		goto out;
	current_ret = exchange_verify_password_acm(
		fd, session, -3, (unsigned char *)secret, length,
		context, "current-handle/canonical-v1");
	if (!current_ret) {
		ret = 0;
		goto out;
	}
	special_ret = exchange_verify_password_acm(
		fd, session, (int32_t)special, (unsigned char *)secret, length,
		context, "special-handle/canonical-v1");
	if (!special_ret) {
		ret = 0;
		goto out;
	}
	positive_ret = exchange_verify_password_acm(
		fd, session, (int32_t)positive, (unsigned char *)secret, length,
		context, "positive-handle/canonical-v1");
	ret = positive_ret;
out:
	memset(secret, 0, sizeof(secret));
	memset(context, 0, sizeof(context));
	return ret;
}

static int build_get_device_state_v1_request(uint64_t session, int32_t handle,
					     uint32_t selector,
					     unsigned char request[24])
{
	if (!session || !handle || !request)
		return -1;
	memset(request, 0, 24);
	put_le32(request, 1); /* AKS codec version. */
	put_le64(request + 4, session);
	put_le32(request + 12, (uint32_t)handle);
	/* Empty v1 PFK-parameters blob: its zero length is at +16. */
	put_le32(request + 20, selector);
	return 0;
}

static int get_device_state_v1(int fd, const char *session_text,
			       const char *handle_text,
			       const char *selector_text,
			       const char *output_path)
{
	unsigned char request[24];
	unsigned char response[16300] = { 0 };
	struct t2_aks_ioc_exchange exchange = {
		.operation = 0x19,
		.request_length = sizeof(request),
		.response_capacity = sizeof(response),
		.request = (uintptr_t)request,
		.response = (uintptr_t)response,
	};
	uint64_t session;
	char *end = NULL;
	long handle;
	unsigned long selector;
	uint32_t codec_version, blob_length;

	if (parse_u64(session_text, &session) || !session) {
		fprintf(stderr, "invalid session: %s\n", session_text);
		return 2;
	}
	errno = 0;
	handle = strtol(handle_text, &end, 0);
	if (errno || !end || *end || !handle || handle < INT32_MIN ||
	    handle > INT32_MAX) {
		fprintf(stderr, "invalid handle: %s\n", handle_text);
		return 2;
	}
	errno = 0;
	end = NULL;
	selector = strtoul(selector_text, &end, 0);
	if (errno || !end || *end || selector > UINT32_MAX) {
		fprintf(stderr, "invalid selector: %s\n", selector_text);
		return 2;
	}
	if (build_get_device_state_v1_request(session, (int32_t)handle,
					      (uint32_t)selector, request)) {
		fprintf(stderr, "invalid get-device-state-v1 request\n");
		return 2;
	}
	if (ioctl(fd, T2_AKS_IOC_EXCHANGE, &exchange) < 0) {
		perror("T2_AKS_IOC_EXCHANGE");
		return 1;
	}
	if (exchange.response_length < 8) {
		fprintf(stderr, "short device-state-v1 response: %u bytes\n",
			exchange.response_length);
		return 1;
	}
	codec_version = get_le32(response);
	blob_length = get_le32(response + 4);
	if (codec_version != 1 || blob_length > sizeof(response) - 8 ||
	    exchange.response_length != 8 + ((blob_length + 3) & ~3U)) {
		fprintf(stderr,
			"invalid device-state-v1 response: codec_version=%u blob_length=%u response_length=%u\n",
			codec_version, blob_length,
			exchange.response_length);
		return 1;
	}
	if (write_private_output(output_path, response + 8, blob_length))
		return 1;
	printf("codec_version=1 blob_length=%u response_length=%u\n",
	       blob_length, exchange.response_length);
	return 0;
}

static int get_device_state(int fd, const char *handle_text,
			    const char *selector_text, const char *output_path)
{
	unsigned char request[20] = { 0 };
	unsigned char response[16300] = { 0 };
	struct t2_aks_ioc_exchange exchange = {
		.operation = 0x19,
		.request_length = sizeof(request),
		.response_capacity = sizeof(response),
		.request = (uintptr_t)request,
		.response = (uintptr_t)response,
	};
	char *end;
	long long handle;
	unsigned long selector;
	uint32_t status;
	uint32_t blob_length;

	errno = 0;
	handle = strtoll(handle_text, &end, 0);
	if (errno || *end) {
		fprintf(stderr, "invalid handle: %s\n", handle_text);
		return 2;
	}
	errno = 0;
	selector = strtoul(selector_text, &end, 0);
	if (errno || *end || selector > UINT32_MAX) {
		fprintf(stderr, "invalid selector: %s\n", selector_text);
		return 2;
	}
	put_le64(request + 4, (uint64_t)handle);
	put_le32(request + 12, selector);
	if (ioctl(fd, T2_AKS_IOC_EXCHANGE, &exchange) < 0) {
		perror("T2_AKS_IOC_EXCHANGE");
		return 1;
	}
	if (exchange.response_length < 8) {
		fprintf(stderr, "short device-state response: %u bytes\n",
			exchange.response_length);
		return 1;
	}
	status = get_le32(response);
	blob_length = get_le32(response + 4);
	if (status || blob_length > exchange.response_length - 8) {
		fprintf(stderr, "AppleKeyStore status=%#x blob_length=%u response_length=%u\n",
			status, blob_length, exchange.response_length);
		return 1;
	}
	if (write_private_output(output_path, response + 8, blob_length))
		return 1;
	printf("status=0 blob_length=%u response_length=%u\n", blob_length,
	       exchange.response_length);
	return 0;
}

int main(int argc, char **argv)
{
	int fd;
	int ret;

	if (!((argc == 2 && !strcmp(argv[1], "capabilities")) ||
	      ((argc == 3 || argc == 4) && !strcmp(argv[1], "load-keybag")) ||
	      (argc == 5 && !strcmp(argv[1], "set-system-keybag")) ||
	      (argc == 4 && (!strcmp(argv[1], "unlock-keybag") ||
	                     !strcmp(argv[1], "unlock-keybag-stdin"))) ||
	      (argc == 4 && !strcmp(argv[1], "verify-password-acm")) ||
	      (argc == 4 && (!strcmp(argv[1], "verify-password-only") ||
	                     !strcmp(argv[1], "verify-password-only-stdin"))) ||
	      (argc == 5 && !strcmp(argv[1], "verify-password-acm-matrix")) ||
	      (argc == 5 && !strcmp(argv[1], "copy-keybag-uuid")) ||
	      (argc == 5 && !strcmp(argv[1], "get-device-state")) ||
	      (argc == 6 && !strcmp(argv[1], "get-device-state-v1")))) {
		fprintf(stderr,
			"Usage: %s capabilities\n"
			"       %s load-keybag INPUT [SESSION]\n"
			"       %s set-system-keybag SESSION HANDLE SPECIAL\n"
			"       %s unlock-keybag SESSION HANDLE\n"
			"       %s unlock-keybag-stdin SESSION HANDLE\n"
			"       %s verify-password-acm SESSION HANDLE < CONTEXT_16_BYTES\n"
			"       %s verify-password-only SESSION HANDLE\n"
			"       %s verify-password-only-stdin SESSION HANDLE\n"
			"       %s verify-password-acm-matrix SESSION SPECIAL POSITIVE < CONTEXT_16_BYTES\n"
			"       %s copy-keybag-uuid SESSION HANDLE OUTPUT\n"
			"       %s get-device-state HANDLE SELECTOR OUTPUT\n"
			"       %s get-device-state-v1 SESSION HANDLE SELECTOR OUTPUT\n",
			argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0],
			argv[0], argv[0], argv[0], argv[0], argv[0]);
		return 2;
	}
	fd = open("/dev/t2-aks", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/t2-aks");
		return 1;
	}
	if (!strcmp(argv[1], "capabilities"))
		ret = capabilities(fd);
	else if (!strcmp(argv[1], "load-keybag"))
		ret = load_keybag(fd, argv[2], argc == 4 ? argv[3] : NULL);
	else if (!strcmp(argv[1], "set-system-keybag"))
		ret = set_system_keybag(fd, argv[2], argv[3], argv[4]);
	else if (!strcmp(argv[1], "unlock-keybag"))
		ret = unlock_keybag(fd, argv[2], argv[3], 0);
	else if (!strcmp(argv[1], "unlock-keybag-stdin"))
		ret = unlock_keybag(fd, argv[2], argv[3], 1);
	else if (!strcmp(argv[1], "verify-password-acm"))
		ret = verify_password_acm(fd, argv[2], argv[3]);
	else if (!strcmp(argv[1], "verify-password-only"))
		ret = verify_password_only(fd, argv[2], argv[3], 0);
	else if (!strcmp(argv[1], "verify-password-only-stdin"))
		ret = verify_password_only(fd, argv[2], argv[3], 1);
	else if (!strcmp(argv[1], "verify-password-acm-matrix"))
		ret = verify_password_acm_matrix(fd, argv[2], argv[3], argv[4]);
	else if (!strcmp(argv[1], "copy-keybag-uuid"))
		ret = copy_keybag_uuid(fd, argv[2], argv[3], argv[4]);
	else if (!strcmp(argv[1], "get-device-state-v1"))
		ret = get_device_state_v1(fd, argv[2], argv[3], argv[4], argv[5]);
	else
		ret = get_device_state(fd, argv[2], argv[3], argv[4]);
	close(fd);
	return ret;
}
