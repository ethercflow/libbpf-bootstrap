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

#include "xdp_progs.h"
#include "xdp_progs.skel.h"

static struct env {
	char *progsec;
	char *ifname;
	char *target;
	unsigned char dst[ETH_ALEN];
	unsigned char src[ETH_ALEN];
	int ifindex;
	int rifindex;
	__u32 xdp_flags;
	bool list;
	bool reuse_maps;
	bool do_unload;
	bool verbose;
} env = {
	.progsec = "xdp_pass",
	.ifindex = -1,
	.rifindex = -1,
	.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
};

const char *argp_program_version = "xdp_progs 0.1";
const char *argp_program_bug_address = "<ethercflow@gmail.com>";
const char argp_program_doc[] =
"USAGE: xdp_progs [--help] [-d DEV] [-F] [-L] [-m MAC] [-r REDIRECT-DEV] "
"[-R] [-s SRC-MAC] [-S] [-U]\n\n";

static const struct argp_option opts[] = {
	{ "dev", 'd', "DEV", 0, "Operate on device <ifname>" },
	{ "force", 'F', NULL, 0,
	  "Force install, replacing existing program on interface" },
	{ "list", 'l', NULL, 0, "List all progsec" },
	{ "progsec", 'p', "PROGSEC", 0,
	  "Load program in <section> of the ELF file" },
	{ "mac", 'm', "MAC", 0, "Destination MAC address of <redirect-dev>" },
	{ "redirect-dev", 'r', "REDIRECT-DEV", 0,
	  "Redirect to device <ifname>" },
	{ "reuse-maps", 'R', NULL, 0, "Reuse pinned maps" },
	{ "src-mac", 's', "SRC-MAC", 0, "Source MAC address of <dev>" },
	{ "skb-mode", 'S', NULL, 0,
	  "Install XDP prog in SKB (AKA generic) mode" },
	{ "unload", 'U', NULL, 0, "Unload XDP program instead of loading" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	char *mac, *tmp = NULL;
	int i = 0;

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
			fprintf(stderr, "--dev name unknown err(%d): %s\n",
				errno, strerror(errno));
			argp_usage(state);
		}
		break;
	case 'F':
		env.xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
		break;
	case 'L':
		env.list = true;
		break;
	case 'm':
		mac = strtok_r(arg, ":", &tmp);
		while (mac) {
			if (i >= ETH_ALEN) {
				fprintf(stderr, "unknown dst mac: %s\n", arg);
				argp_usage(state);
			}

			env.dst[i] = strtol(mac, NULL, 16);
			i++;
			mac = strtok_r(NULL, ":", &tmp);
		}
		if (i != ETH_ALEN) {
			fprintf(stderr, "unknown dst mac: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'p':
		env.progsec = arg;
		break;
	case 'r':
		if (strlen(arg) >= IF_NAMESIZE) {
			fprintf(stderr, "--target name too long\n");
			argp_usage(state);
		}
		errno = 0;
		env.target = arg;
		env.rifindex = if_nametoindex(env.target);
		if (!env.rifindex) {
			fprintf(stderr, "--target name unknown err(%d): %s\n",
				errno, strerror(errno));
			argp_usage(state);
		}
		break;
	case 'R':
		env.reuse_maps = true;
		break;
	case 's':
		mac = strtok_r(arg, ":", &tmp);
		while (mac) {
			if (i >= ETH_ALEN) {
				fprintf(stderr, "unknown src mac: %s\n", arg);
				argp_usage(state);
			}

			env.src[i] = strtol(mac, NULL, 16);
			i++;
			mac = strtok_r(NULL, ":", &tmp);
		}
		if (i != ETH_ALEN) {
			fprintf(stderr, "unknown src mac: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'S':
		env.xdp_flags &= ~XDP_FLAGS_MODES; /* Clear flags */
		env.xdp_flags |= XDP_FLAGS_SKB_MODE;
		break;
	case 'U':
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

static void list_avalid_progsecs(struct bpf_object *obj)
{
	struct bpf_program *pos;

	printf("BPF object (%s) listing avalid --prosec names\n",
		bpf_object__name(obj));

	bpf_object__for_each_program(pos, obj) {
		if (bpf_program__is_xdp(pos))
			printf(" %s\n", bpf_program__section_name(pos));
	}
}

static int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
	__u32 curr_prog_id;
	int err;

	err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
	if (err) {
		fprintf(stderr, "ERR: get link xdp id failed (err=%d): %s\n",
			-err, strerror(-err));
		return -1;
	}

	if (!curr_prog_id) {
		printf("INFO: %s() no curr XDP prog on ifindex:%d\n",
			__func__, ifindex);
		return -1;
	}

	if (expected_prog_id && curr_prog_id != expected_prog_id) {
		fprintf(stderr, "ERR: %s() "
			"expected prog ID(%d) no match(%d), not removing\n",
			__func__, expected_prog_id, curr_prog_id);
		return -1;
	}

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: %s() link set xdp failed (err=%d): %s\n",
			__func__, err, strerror(-err));
		return -1;
	}

	printf("INFO: %s() removed XDP prog ID:%d on ifindex:%d\n",
		__func__, curr_prog_id, ifindex);

	return 0;
}

static int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
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

static const char *pin_basedir = "/sys/fs/bpf";
static char pin_path[PATH_MAX];

static int pin_maps_in_bpf_object(struct bpf_object *obj)
{
	int err;

	if (snprintf(pin_path, PATH_MAX, "%s/%s/", pin_basedir, env.ifname) < 0) {
		fprintf(stderr, "failed to create map path\n");
		return -1;
	}

	if (access(pin_path, F_OK) != -1) {
		printf(" Unpinning prev maps in %s\n", pin_path);

		err = bpf_object__unpin_maps(obj, pin_path);
		if (err) {
			fprintf(stderr, "failed to unmap maps in %s\n",
				pin_path);
			return -1;
		}
	}

	printf("Pinning maps in %s\n", pin_path);

	err = bpf_object__pin_maps(obj, pin_path);
	if (err) {
		fprintf(stderr, "failed to pin maps in %s\n", pin_path);
		return -1;
	}

	return 0;
}

static int write_iface_params(int map_fd, unsigned char *src,
			unsigned char *dest)
{
	if (bpf_map_update_elem(map_fd, src, dest, 0) < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

	printf("forward: %02x:%02x:%02x:%02x:%02x:%02x -> "
		"%02x:%02x:%02x:%02x:%02x:%02x\n",
		src[0], src[1], src[2], src[3], src[4], src[5],
		dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]
	      );

	return 0;
}

static int open_bpf_map_file(const char *pin_dir,
			const char *mapname,
			struct bpf_map_info *info)
{
	char filename[PATH_MAX];
	int err, len, fd;
	__u32 info_len = sizeof(*info);

	len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
	if (len < 0) {
		fprintf(stderr, "ERR: constructing full mapname path\n");
		return -1;
	}

	fd = bpf_obj_get(filename);
	if (fd < 0) {
		fprintf(stderr,
			"WARN: Failed to open bpf map file:%s err(%d):%s\n",
			filename, errno, strerror(errno));
		return fd;
	}

	if (info) {
		err = bpf_obj_get_info_by_fd(fd, info, &info_len);
		if (err) {
			fprintf(stderr, "ERR: %s() can't get info - %s\n",
				__func__,  strerror(errno));
			return -1;
		}
	}

	return fd;
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
	struct xdp_progs_bpf *skel;
	struct bpf_program *prog;
	int fd, i, err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return 1;

	if (env.ifindex == -1 && !env.list) {
		fprintf(stderr, "required option --dev missing\n");
		return 1;
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	if (env.do_unload) {
		err = xdp_link_detach(env.ifindex, env.xdp_flags, 0);
		if (err < 0)
			fprintf(stderr, "failed dettach xdp to ifindex(%d)\n",
				env.ifindex);
		return 1;
	}

	skel = xdp_progs_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->targ_ifindex = env.rifindex;
	memmove(skel->rodata->targ_dst, env.dst, ETH_ALEN);

	err = xdp_progs_bpf__load(skel);
	if (err < 0) {
		fprintf(stderr, "failed to load BPF skeleton\n");
		return 1;
	}

	if (env.list) {
		list_avalid_progsecs(skel->obj);
		goto cleanup;
	}

	prog = bpf_object__find_program_by_title(skel->obj, env.progsec);
	if (!prog) {
		fprintf(stderr, "failed to find progsec: %s\n", env.progsec);
		goto cleanup;
	}

	fd = bpf_program__fd(prog);
	if (fd < 0) {
		fprintf(stderr, "failed to get progsec: %s's fd\n", env.progsec);
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

	if (!env.reuse_maps) {
		err = pin_maps_in_bpf_object(skel->obj);
		if (err) {
			fprintf(stderr, "failed to pin maps, "
				"detach xdp prog\n");
			err = xdp_link_detach(env.ifindex, env.xdp_flags, 0);
			if (err < 0) {
				fprintf(stderr,
					"failed dettach xdp to ifindex(%d)\n",
					env.ifindex);
				goto cleanup;
			}
		}
	}

	fd = open_bpf_map_file(pin_path, "tx_port", NULL);
	if (fd < 0) {
		fprintf(stderr, "failed to open tx_port map\n");
		goto cleanup;
	}

	if (env.ifindex != -1 && env.rifindex != -1) {
		i = 0;
		bpf_map_update_elem(fd, &i, &env.rifindex, 0);
		printf("Redirect from ifnum=%d to ifnum=%d\n",
			env.ifindex, env.rifindex);

		fd = open_bpf_map_file(pin_path, "redirect_params", NULL);
		if (write_iface_params(fd, env.src, env.dst)) {
			fprintf(stderr, "failed to write iface params\n");
			goto cleanup;
		}
	} else {
		for (i = 1; i < 256; i++)
			bpf_map_update_elem(fd, &i, &i, 0);
	}

	printf("Success: Loading "
	       "XDP prog name:%s(id:%d) on device:%s(ifindex:%d)\n",
	       info.name, info.id, env.ifname, env.ifindex);

cleanup:
	xdp_progs_bpf__destroy(skel);
	return err != 0;
}
