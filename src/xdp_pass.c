// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Some code copied & modified based on
// https://github.com/xdp-project/xdp-tutorial
/* Copyright (c) 2020 Wenbo Zhang */
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/resource.h>

#include <net/if.h>
#include <linux/if_link.h> /* XDP_FLAGS_* depend on kernel-headers installed */
#include <linux/if_xdp.h>
#include <linux/limits.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_pass.skel.h"

static struct env {
	char *ifname;
	int ifindex;
	__u32 xdp_flags;
	bool do_unload;
	bool verbose;
} env = {
	.ifindex = -1,
	.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
};

const char *argp_program_version = "xdp_pass 0.1";
const char *argp_program_bug_address = "<ethercflow@gmail.com>";
const char argp_program_doc[] =
"USAGE: xdp_pass [--help] [-d] [-f] [-s] [-u]\n\n";

static const struct argp_option opts[] = {
	{ "dev", 'd', "DEV", 0, "Operate on device <ifname>" },
	{ "force", 'f', NULL, 0,
	  "Force install, replacing existing program on interface" },
	{ "unload", 'u', NULL, 0, "Unload XDP program instead of loading" },
	{ "skb-mode", 's', NULL, 0,
	  "Install XDP prog in SKB (AKA generic) mode" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		if (strlen(arg) >= IF_NAMESIZE) {
			fprintf(stderr, "--dev name too long\n");
			argp_usage(state);
		}
		errno = 0;
		env.ifname = arg;
		env.ifindex = if_nametoindex(env.ifname);
		if (!env.ifindex) {
			fprintf(stderr, "--dev name unknonw err(%d): %s\n",
				errno, strerror(errno));
			argp_usage(state);
		}
		break;
	case 'f':
		env.xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
		break;
	case 's':
		env.xdp_flags &= ~XDP_FLAGS_MODES; /* Clear flags */
		env.xdp_flags |= XDP_FLAGS_SKB_MODE;
		break;
	case 'u':
		env.do_unload = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int xdp_link_detach(int ifindex, __u32 xdp_flags)
{
	int err;

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
			err, strerror(-err));
		return -1;
	}
	return 0;
}

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		/* Force mode didn't work, probably because a program of the
		 * opposite type is loaded. Let's unload that and try loading
		 * again.
		 */

		__u32 old_flags = xdp_flags;

		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ?
			XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}

	if (err < 0) {
		fprintf(stderr, "ERR: "
			"ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			fprintf(stderr, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct xdp_pass_bpf *skel;
	int fd, err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.ifindex == -1) {
		fprintf(stderr, "required option --dev missing\n");
		return 1;
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	if (env.do_unload) {
		err = xdp_link_detach(env.ifindex, env.xdp_flags);
		if (err < 0)
			fprintf(stderr, "failed dettach xdp to ifindex(%d)\n",
				env.ifindex);
		return err;
	}

	skel = xdp_pass_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open and load BPF skeleton\n");
		return 1;
	}

	fd = bpf_program__fd(skel->progs.xdp_prog);
	if (fd < 0) {
		fprintf(stderr, "failed to get xdp_prog's fd\n");
		goto cleanup;
	}

	err = xdp_link_attach(env.ifindex, env.xdp_flags, fd);
	if (err < 0) {
		fprintf(stderr, "failed attach xdp to ifindex(%d)\n",
			env.ifindex);
		goto cleanup;
	}

	err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "failed to get prog info: %s\n",
			strerror(errno));
		goto cleanup;
	}

	printf("Success: Loading "
	       "XDP prog name:%s(id:%d) on device:%s(ifindex:%d)\n",
	       info.name, info.id, env.ifname, env.ifindex);

cleanup:
	xdp_pass_bpf__destroy(skel);
	return err != 0;
}
