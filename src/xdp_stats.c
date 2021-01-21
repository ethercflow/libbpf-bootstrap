// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Wenbo Zhang */
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <locale.h>

#include <net/if.h>
#include <linux/if_link.h> /* XDP_FLAGS_* depend on kernel-headers installed */
#include <linux/if_xdp.h>
#include <linux/limits.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_progs.h"

static struct env {
	char *ifname;
	int ifindex;
	int interval;
	bool verbose;
} env = {
	.ifindex = -1,
	.interval = 2,
};

const char *argp_program_version = "xdp_stats 0.1";
const char *argp_program_bug_address = "<ethercflow@gmail.com>";
const char argp_program_doc[] =
"USAGE: xdp_stats [--help] [-d DEV] [interval]\n\n";

static const struct argp_option opts[] = {
	{ "dev", 'd', "DEV", 0, "Operate on device <ifname>" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
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
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(-1);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int check_map_fd_info(const struct bpf_map_info *info,
			const struct bpf_map_info *exp)
{
	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return -1;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return -1;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return -1;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return -1;
	}

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

struct record {
	__u64 timestamp;
	struct datarec total;
};

struct stats_record {
	struct record stats[XDP_ACTION_MAX];
};

static const char *pin_basedir = "/sys/fs/bpf";

void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
	if (bpf_map_lookup_elem(fd, &key, value) != 0)
		fprintf(stderr, "failed to lookup key: 0x%x\n", key);
}

void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i;

	if (bpf_map_lookup_elem(fd, &key, values) != 0) {
		fprintf(stderr, "failed to lookup key: 0x%x\n", key);
		return;
	}

	for (i = 0; i < nr_cpus; i++) {
		sum_pkts += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes = sum_bytes;
}

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_= ((double) period / NANOSEC_PER_SEC);
}

static const char *xdp_action_names[XDP_ACTION_MAX] = {
	[XDP_ABORTED]   = "XDP_ABORTED",
	[XDP_DROP]      = "XDP_DROP",
	[XDP_PASS]      = "XDP_PASS",
	[XDP_TX]        = "XDP_TX",
	[XDP_REDIRECT]  = "XDP_REDIRECT",
};

const char *action2str(__u32 action)
{
        if (action < XDP_ACTION_MAX)
                return xdp_action_names[action];
        return NULL;
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	__u64 packets, bytes;
	double period;
	double pps;		/* packets per sec */
	double bps;		/* bits per sec */
	int i;

	printf("%-12s\n", "XDP-action");

	for (i = 0; i < XDP_ACTION_MAX; i++) {
		char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
			" %'11lld Kbytes (%'6.0f Mbits/s)"
			" period:%f\n";
		const char *action = action2str(i);

		rec = &stats_rec->stats[i];
		prev = &stats_prev->stats[i];

		period = calc_period(rec, prev);
		if (period == 0)
			return;

		packets = rec->total.rx_packets - prev->total.rx_packets;
		pps = packets / period;

		bytes = rec->total.rx_bytes - prev->total.rx_bytes;
		bps = (bytes * 8) / period / 1000000;

		printf(fmt, action, rec->total.rx_packets, pps,
			rec->total.rx_bytes / 1000, bps,
			period);
	}
	printf("\n");
}

static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;

	rec->timestamp = gettime();

	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		map_get_value_array(fd, key, &value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		map_get_value_percpu_array(fd, key, &value);
		break;
	default:
		fprintf(stderr, "unknown map_types(%u)\n", map_type);
		return false;
		break;
	}

	rec->total.rx_packets = value.rx_packets;
	rec->total.rx_bytes = value.rx_bytes;
	return true;
}

static void stats_collect(int map_fd, __u32 map_type,
			struct stats_record *stats_rec)
{
	__u32 key;

	for (key = 0; key < XDP_ACTION_MAX; key++)
		map_collect(map_fd, map_type, key, &stats_rec->stats[key]);
}

static int stats_poll(const char *pin_dir, int map_fd, __u32 id,
		__u32 map_type, int interval)
{
	struct stats_record prev, record = {};
	struct bpf_map_info info = {};

	setlocale(LC_NUMERIC, "en_US");

	stats_collect(map_fd, map_type, &record);
	usleep(1000000/4);

	while (1) {
		prev = record;

		map_fd = open_bpf_map_file(pin_dir, "xdp_stats_map", &info);
		if (map_fd < 0) {
			return -1;
		} else if (id != info.id) {
			fprintf(stderr, "xdp_stats_map changed its ID, restarting\n");
			close(map_fd);
			return 0;
		}

		stats_collect(map_fd, map_type, &record);
		stats_print(&record, &prev);
		close(map_fd);
		sleep(interval);
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
	const struct bpf_map_info map_expect = {
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(struct datarec),
		.max_entries = XDP_ACTION_MAX,
	};
	struct bpf_map_info info;
	char pin_dir[PATH_MAX];
	int fd, err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return 1;
	if (env.ifindex == -1) {
		fprintf(stderr, "require option --dev missing\n");
		return 1;
	}

	if (snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, env.ifname) < 0) {
		fprintf(stderr, "failed to create pin dirname\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	for (; ;) {
		fd = open_bpf_map_file(pin_dir, "xdp_stats_map", &info);
		if (fd < 0)
			return 1;

		err = check_map_fd_info(&info, &map_expect);
		if (err) {
			fprintf(stderr, "map does not compatible\n");
			close(fd);
			return 1;
		}
		printf("\nCollecting stats from BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			" key_size:%d value_size:%d max_entries:%d\n",
			info.type, info.id, info.name,
			info.key_size, info.value_size, info.max_entries);

		err = stats_poll(pin_dir, fd, info.id, info.type, env.interval);
		close(fd);
		if (err < 0)
			break;
	}

	return err != 0;
}
