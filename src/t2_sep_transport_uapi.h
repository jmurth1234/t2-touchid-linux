/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef T2_SEP_TRANSPORT_UAPI_H
#define T2_SEP_TRANSPORT_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define T2_AKS_IOC_MAGIC 0xa7

struct t2_aks_ioc_exchange {
	__u8 operation;
	__u8 reserved0[3];
	__u32 request_length;
	__u32 response_capacity;
	__u32 response_length;
	__u64 request;
	__u64 response;
};

#define T2_AKS_IOC_EXCHANGE \
	_IOWR(T2_AKS_IOC_MAGIC, 0, struct t2_aks_ioc_exchange)

#endif
