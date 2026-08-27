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
			 const char *handle_text)
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
	got = read(tty, secret, sizeof(secret) - 1);
	tcsetattr(tty, TCSAFLUSH, &old_term);
	(void)write(tty, "\n", 1);
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
	if (tty >= 0)
		close(tty);
	return ret;
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
	int output;
	ssize_t written;

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
	output = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		      0600);
	if (output < 0) {
		perror("open output");
		return 1;
	}
	written = write(output, response + 8, blob_length);
	if (written < 0 || (uint32_t)written != blob_length) {
		perror("write output");
		close(output);
		return 1;
	}
	close(output);
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
	      (argc == 4 && !strcmp(argv[1], "unlock-keybag")) ||
	      (argc == 5 && !strcmp(argv[1], "get-device-state")))) {
		fprintf(stderr,
			"Usage: %s capabilities\n"
			"       %s load-keybag INPUT [SESSION]\n"
			"       %s set-system-keybag SESSION HANDLE SPECIAL\n"
			"       %s unlock-keybag SESSION HANDLE\n"
			"       %s get-device-state HANDLE SELECTOR OUTPUT\n",
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
		ret = unlock_keybag(fd, argv[2], argv[3]);
	else
		ret = get_device_state(fd, argv[2], argv[3], argv[4]);
	close(fd);
	return ret;
}
