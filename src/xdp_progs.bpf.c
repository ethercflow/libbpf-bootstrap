// SPDX-License-Identifier: GPL-2.0
// Some code copied & modified based on
// https://github.com/xdp-project/xdp-tutorial
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_progs.h"

#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

#define AF_INET 2
#define AF_INET6 10
#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

#define NULL			       0
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */

#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMPV6_ECHO_REQUEST		128
#define ICMPV6_ECHO_REPLY		129
#define IPPROTO_ICMPV6		58	/* ICMPv6			*/
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN		*/

const volatile unsigned char targ_dst[ETH_ALEN] = { };
const volatile __u32 targ_ifindex = 0;

struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};

struct hdr_cursor {
	void *pos;
};

/*
 * Struct icmphdr_common represents the common part of the icmphdr and icmp6hdr
 * structures.
 */
struct icmphdr_common {
	__u8		type;
	__u8		code;
	__sum16	cksum;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDP_ACTION_MAX);
	__type(key, u32);
	__type(value, struct datarec);
} xdp_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, 256);
	__type(key, u32);
	__type(value, u32);
} tx_port SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, char [ETH_ALEN]);
	__type(value, char [ETH_ALEN]);
} redirect_params SEC(".maps");

static int xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct datarec *rec;
	__u64 bytes;

	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	bytes = data_end - data;
	rec->rx_bytes += bytes;
	rec->rx_packets++;

	return action;
}

static int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

SEC("xdp_pass")
int prog1(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, XDP_PASS);
}

SEC("xdp_drop")
int prog2(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, XDP_DROP);
}

SEC("xdp_abort")
int prog3(struct xdp_md *ctx)
{
	/* trigger xdp:xdp_exception */
	return xdp_stats_record_action(ctx, XDP_ABORTED);
}

static bool proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		h_proto == bpf_htons(ETH_P_8021AD));
}

static int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;
	__be16 h_proto;
	int vlid;

	if (!proto_is_vlan(eth->h_proto))
		return -1;

	vlh = (void *)(eth + 1);

	if ((void *)(vlh + 1) > data_end)
		return -1;

	vlid = bpf_ntohs(vlh->h_vlan_TCI);
	h_proto = vlh->h_vlan_encapsulated_proto;

	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
		return -1;

	eth = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if ((void *)(eth + 1) > data_end)
		return -1;

	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
	eth->h_proto = h_proto;

	return vlid;
}

static int vlan_tag_push(struct xdp_md *ctx, struct ethhdr *eth, int vlid)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;

	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))
		return -1;

	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;

	if ((void *)(eth + 1) > data_end)
		return -1;

	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

	vlh = (void *)(eth + 1);

	if ((void *)(vlh + 1) > data_end)
		return -1;

	vlh->h_vlan_TCI = bpf_htons(vlid);
	vlh->h_vlan_encapsulated_proto = eth->h_proto;

	eth->h_proto = bpf_htons(ETH_P_8021Q);
	return 0;
}

static int parse_ethhdr_vlan(struct hdr_cursor *nh,
			void *data_end,
			struct ethhdr **ethhdr,
			struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if ((void *)(vlh + 1) > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans)
			vlans->id[i] =
				bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK;
		vlh++;
	}

	nh->pos = vlh;
	return h_proto;
}

static int parse_ethhdr(struct hdr_cursor *nh,
			void *data_end,
			struct ethhdr **ethhdr)
{
	return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}

static int parse_ip6hdr(struct hdr_cursor *nh,
			void *data_end,
			struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;

	if ((void *)(ip6h + 1) > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	/* See https://en.wikipedia.org/wiki/IPv6_packet */
	return ip6h->nexthdr;
}

static int parse_iphdr(struct hdr_cursor *nh,
		void *data_end,
		struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if ((void *)(iph + 1) > data_end)
		return -1;

	/* See https://en.wikipedia.org/wiki/IPv4/#Header */
	hdrsize = iph->ihl * 4;
	if (hdrsize < (sizeof(*iph)))
		return -1;

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

static int parse_icmp6hdr(struct hdr_cursor *nh,
			void *data_end,
			struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;

	if ((void *)(icmp6h + 1) > data_end)
		return -1;

	nh->pos = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

static int parse_icmphdr(struct hdr_cursor *nh,
			void *data_end,
	struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = nh->pos;

	if ((void *)(icmph + 1) > data_end)
		return -1;

	nh->pos = icmph + 1;
	*icmphdr = icmph;

	return icmph->type;
}

static int parse_icmphdr_common(struct hdr_cursor *nh,
				void *data_end,
				struct icmphdr_common **icmphdr)
{
	struct icmphdr_common *h = nh->pos;

	if ((void *)(h + 1) > data_end)
		return -1;

	nh->pos = h + 1;
	*icmphdr = h;

	return h->type;
}

static int parse_udphdr(struct hdr_cursor *nh,
			void *data_end,
			struct udphdr **udphdr)
{
	struct udphdr *h = nh->pos;
	int len;

	if ((void *)(h + 1) > data_end)
		return -1;

	nh->pos = h + 1;
	*udphdr = h;

	/* See https://en.wikipedia.org/wiki/User_Datagram_Protocol\#UDP_Datagram_structure */
	len = bpf_ntohs(h->len) - sizeof(*h);
	if (len < 0)
		return -1;

	return len;
}

static int parse_tcphdr(struct hdr_cursor *nh,
			void *data_end,
			struct tcphdr **tcphdr)
{
	struct tcphdr *h = nh->pos;
	int len;

	if ((void *)(h + 1) > data_end)
		return -1;

	/* See https://en.wikipedia.org/wiki/Transmission_Control_Protocol\#TCP_segment_structure */
	len = h->doff * 4;

	if (len < sizeof(*h))
		return -1;

	if (nh->pos + len > data_end)
		return -1;

	nh->pos += len;
	*tcphdr = h;

	return len;
}

static void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	__be32 tmp = iphdr->saddr;

	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = tmp;
}

static void swap_src_dst_ipv6(struct ipv6hdr *ipv6)
{
	struct in6_addr tmp = ipv6->saddr;

	ipv6->saddr = ipv6->daddr;
	ipv6->daddr = tmp;
}

static void swap_src_dst_mac(struct ethhdr *eth)
{
	__u8 h_tmp[ETH_ALEN];

	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

static __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;

	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static __u16 icmp_checksum_diff(__u16 seed,
				struct icmphdr_common *icmphdr_new,
				struct icmphdr_common *icmphdr_old)
{
	__u32 csum, size = sizeof(struct icmphdr_common);

	csum = bpf_csum_diff((__be32 *)icmphdr_old, size,
			(__be32 *)icmphdr_new, size, seed);
	return csum_fold_helper(csum);
}

SEC("xdp_packet_parser")
int prog4(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;

	__u32 action = XDP_PASS;

	struct hdr_cursor nh;
	int nh_type;

	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		struct icmp6hdr *icmp6h;

		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

		if (bpf_ntohs(icmp6h->icmp6_dataun.u_echo.sequence) % 2 == 0)
			action = XDP_DROP;
	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
			action = XDP_DROP;
	}

out:
	return xdp_stats_record_action(ctx, action);
}


/*
* Use `t exec -- socat - 'udp6:[fc00:dead:cafe:1::1]:2000'` to test,
* and use `t tcpdump` to watch the result
*/
SEC("xdp_patch_ports")
int prog5(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	struct iphdr *iphdr;
	struct ethhdr *eth;

	__u32 action = XDP_PASS;

	struct hdr_cursor nh;
	int nh_type;

	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (nh_type == bpf_htons(ETH_P_IP))
		nh_type = parse_iphdr(&nh, data_end, &iphdr);
	else if (nh_type == bpf_htons(ETH_P_IPV6))
		nh_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	else
		goto out;

	if (nh_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
	} else if (nh_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
	}

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_vlan_swap")
int prog6(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor nh;
	struct ethhdr *eth;
	int nh_type;

	nh.pos = data;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_ABORTED;

	if (proto_is_vlan(nh_type))
		vlan_tag_pop(ctx, eth);
	else
		vlan_tag_push(ctx, eth, 1);

	return XDP_PASS;
}

SEC("xdp_icmp_echo")
int prog7(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct icmphdr_common icmphdr_old;
	struct icmphdr_common *icmphdr;
	__u16 echo_reply, old_csum;
	struct ipv6hdr *ipv6hdr;
	struct iphdr *iphdr;
	struct ethhdr *eth;
	int icmp_type;
	int eth_type;
	int ip_type;

	__u32 action = XDP_PASS;

	struct hdr_cursor nh;
	int nh_type;

	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	} else {
		action = XDP_ABORTED;
		goto out;
	}

	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO) {
		swap_src_dst_ipv4(iphdr);
		echo_reply = ICMP_ECHOREPLY;
	} else if (eth_type == bpf_htons(ETH_P_IPV6) &&
		icmp_type == ICMPV6_ECHO_REQUEST) {
		swap_src_dst_ipv6(ipv6hdr);
		echo_reply = ICMPV6_ECHO_REPLY;
	} else {
		goto out;
	}

	swap_src_dst_mac(eth);

	old_csum = icmphdr->cksum;
	icmphdr->cksum = 0;
	icmphdr_old = *icmphdr;
	icmphdr->type = echo_reply;
	icmphdr->cksum = icmp_checksum_diff(~old_csum, icmphdr, &icmphdr_old);

	action = XDP_TX;

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_redirect")
int prog8(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type, i;

	__u32 action = XDP_PASS;

	if (!targ_ifindex || !targ_dst[0]) {
		action = XDP_ABORTED;
		goto out;
	}

	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1) {
		action = XDP_ABORTED;
		goto out;
	}

	if (!eth)
		goto out;

	for (i = 0; i < ETH_ALEN; i++)
		eth->h_dest[i] = targ_dst[i];
	action = bpf_redirect(targ_ifindex, 0);

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_redirect_map")
int prog9(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	unsigned char *dst;
	int eth_type;

	__u32 action = XDP_PASS;

	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;


	dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
	if (!dst) {
		bpf_printk("not found\n");
		action = XDP_ABORTED;
		goto out;
	}

	__builtin_memcpy(eth->h_dest, dst, ETH_ALEN);
	action = bpf_redirect_map(&tx_port, 0, 0);

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_router")
int prog10(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ipv6hdr *ipv6hdr;
	struct iphdr *iphdr;
	struct ethhdr *eth;

	__u32 action = XDP_PASS;

	struct hdr_cursor nh;
	int nh_type, rc;

	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0) {
		bpf_printk("unknown ethhdr\n");
		action = XDP_ABORTED;
		goto out;
	}

	if (nh_type == bpf_htons(ETH_P_IP)) {
		parse_iphdr(&nh, data_end, &iphdr);

		if ((void *)(iphdr + 1) > data_end) {
			bpf_printk("iphdr is outside of the packet\n");
			action = XDP_ABORTED;
			goto out;
		}

		if (iphdr->ttl <= 1)
			goto out;

		fib_params.family = AF_INET;
		fib_params.tos = iphdr->tos;
		fib_params.l4_protocol = iphdr->protocol;
		fib_params.sport = 0;
		fib_params.dport = 0;
		fib_params.tot_len = bpf_ntohs(iphdr->tot_len);
		fib_params.ipv4_src = iphdr->saddr;
		fib_params.ipv4_dst = iphdr->daddr;
	} else if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *)fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *)fib_params.ipv6_dst;

		parse_ip6hdr(&nh, data_end, &ipv6hdr);

		if ((void *)(ipv6hdr + 1) > data_end) {
			bpf_printk("ipv6hdr is outside of the packet\n");
			action = XDP_ABORTED;
			goto out;
		}

		if (ipv6hdr->hop_limit <= 1)
			goto out;

		fib_params.family = AF_INET6;
		fib_params.flowinfo = *(__be32 *)ipv6hdr & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol = ipv6hdr->nexthdr;
		fib_params.sport = 0;
		fib_params.dport = 0;
		fib_params.tot_len = bpf_ntohs(ipv6hdr->payload_len);
		*src = ipv6hdr->saddr;
		*dst = ipv6hdr->daddr;
	} else {
		bpf_printk("unknown ip type\n");
		action = XDP_ABORTED;
		goto out;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:      /* lookup successful */
		if (nh_type == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iphdr);
		else if (nh_type == bpf_htons(ETH_P_IPV6))
			ipv6hdr->hop_limit--;

		__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
		bpf_printk("dest is blackholed\n");
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
		bpf_printk("dest is unreachable\n");
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		bpf_printk("dest not allowed\n");
		action = XDP_DROP;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
		bpf_printk("packet is not forwarded\n");
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
		bpf_printk("fwding is not enabled on ingress\n");
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
		bpf_printk("fwd requires encapsulation\n");
	case BPF_FIB_LKUP_RET_NO_NEIGH:	    /* no neighbor entry for nh */
		bpf_printk("no neighbor entry for nh\n");
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		bpf_printk("fragmentation required to fwd\n");
		break;
	}

out:
	return xdp_stats_record_action(ctx, action);
}

char LICENSE[] SEC("license") = "GPL";
