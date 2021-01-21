// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	/*
	 * Use `sudo bpftool prog tracelog` to see it
	 */
	bpf_printk("ingress_ifindex: %u, rx_queue_index: %u\n",
		ctx->ingress_ifindex, ctx->rx_queue_index);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
