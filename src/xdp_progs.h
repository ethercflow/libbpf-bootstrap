#ifndef __XDP_PROGS_H
#define __XDP_PROGS_H

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

#endif /* __XDP_PROGS_H */
