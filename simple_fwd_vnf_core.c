/*
 * Copyright (c) 2021-2024 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_spinlock.h>

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>

#include <dpdk_utils.h>
#include <utils.h>

#include "simple_fwd_ft.h"
#include "simple_fwd_port.h"
#include "simple_fwd_vnf_core.h"

DOCA_LOG_REGISTER(SIMPLE_FWD_VNF : Core);

#define VNF_PKT_L2(M) rte_pktmbuf_mtod(M, uint8_t *) /* A marco that points to the start of the data in the mbuf */
#define VNF_PKT_LEN(M) rte_pktmbuf_pkt_len(M)	     /* A marco that returns the length of the packet */
#define VNF_RX_BURST_SIZE (32)			     /* Burst size of packets to read, RX burst read size */
#define NETFLOW_DUMP_INTERVAL_SEC (10)

#define NETFLOW_SRC_BUCKETS (1024)
#define NETFLOW_DST_BUCKETS (512)
#define NETFLOW_PROTO_BUCKETS (8)
#define NETFLOW_L4_BUCKETS (64)

/* Flag for forcing lcores to stop processing packets, and gracefully terminate the application */
static volatile bool force_quit;

struct netflow_l4_entry {
	uint16_t l4_value;
	uint64_t packets;
	uint64_t bytes;
	struct netflow_l4_entry *next;
};

struct netflow_proto_entry {
	uint8_t proto;
	struct netflow_l4_entry *l4_buckets[NETFLOW_L4_BUCKETS];
	struct netflow_proto_entry *next;
};

struct netflow_dst_entry {
	uint32_t dst_ip;
	struct netflow_proto_entry *proto_buckets[NETFLOW_PROTO_BUCKETS];
	struct netflow_dst_entry *next;
};

struct netflow_src_entry {
	uint32_t src_ip;
	struct netflow_dst_entry *dst_buckets[NETFLOW_DST_BUCKETS];
	struct netflow_src_entry *next;
};

struct netflow_table {
	struct netflow_src_entry *src_buckets[NETFLOW_SRC_BUCKETS];
};

static struct netflow_table *g_netflow_table;
static rte_spinlock_t g_netflow_lock = RTE_SPINLOCK_INITIALIZER;
static int g_netflow_ipc_pipe[2] = {-1, -1};
static pid_t g_netflow_dump_pid = -1;
static bool g_netflow_probe_started;

enum netflow_ipc_msg_type {
	NETFLOW_IPC_MSG_DUMP_BEGIN = 1,
	NETFLOW_IPC_MSG_RECORD = 2,
	NETFLOW_IPC_MSG_DUMP_END = 3,
	NETFLOW_IPC_MSG_SHUTDOWN = 4,
};

struct netflow_ipc_msg_header {
	uint32_t type;
	uint32_t length;
};

struct netflow_ipc_record {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint8_t proto;
	uint16_t l4_value;
	uint8_t reserved;
	uint64_t packets;
	uint64_t bytes;
};

/* Parameters used by each core */
struct vnf_per_core_params {
	int ports[NUM_OF_PORTS];  /* Ports identifiers */
	int queues[NUM_OF_PORTS]; /* Queue mapped for the core running */
	bool used;		  /* Whether the core is used or not */
};

/* per core parameters */
static struct vnf_per_core_params core_params_arr[RTE_MAX_LCORE];

static uint32_t
netflow_hash_u32(uint32_t value)
{
	value ^= value >> 16;
	value *= 0x7feb352dU;
	value ^= value >> 15;
	value *= 0x846ca68bU;
	value ^= value >> 16;
	return value;
}

static uint32_t
netflow_hash_u16(uint16_t value)
{
	return netflow_hash_u32((uint32_t)value);
}

static struct netflow_table *
netflow_table_create(void)
{
	return calloc(1, sizeof(struct netflow_table));
}

static void
netflow_table_free(struct netflow_table *table)
{
	uint32_t i, j, k, m;
	struct netflow_src_entry *src_entry;
	struct netflow_src_entry *src_next;

	if (table == NULL)
		return;

	for (i = 0; i < NETFLOW_SRC_BUCKETS; i++) {
		src_entry = table->src_buckets[i];
		while (src_entry != NULL) {
			struct netflow_dst_entry *dst_entry;

			src_next = src_entry->next;
			for (j = 0; j < NETFLOW_DST_BUCKETS; j++) {
				dst_entry = src_entry->dst_buckets[j];
				while (dst_entry != NULL) {
					struct netflow_proto_entry *proto_entry;
					struct netflow_dst_entry *dst_next = dst_entry->next;

					for (k = 0; k < NETFLOW_PROTO_BUCKETS; k++) {
						proto_entry = dst_entry->proto_buckets[k];
						while (proto_entry != NULL) {
							struct netflow_l4_entry *l4_entry;
							struct netflow_proto_entry *proto_next = proto_entry->next;

							for (m = 0; m < NETFLOW_L4_BUCKETS; m++) {
								l4_entry = proto_entry->l4_buckets[m];
								while (l4_entry != NULL) {
									struct netflow_l4_entry *l4_next = l4_entry->next;

									free(l4_entry);
									l4_entry = l4_next;
								}
							}

							free(proto_entry);
							proto_entry = proto_next;
						}
					}

					free(dst_entry);
					dst_entry = dst_next;
				}
			}

			free(src_entry);
			src_entry = src_next;
		}
	}

	free(table);
}

static struct netflow_src_entry *
netflow_get_or_create_src(struct netflow_table *table, uint32_t src_ip)
{
	uint32_t bucket = netflow_hash_u32(src_ip) % NETFLOW_SRC_BUCKETS;
	struct netflow_src_entry *entry = table->src_buckets[bucket];

	while (entry != NULL) {
		if (entry->src_ip == src_ip)
			return entry;
		entry = entry->next;
	}

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return NULL;

	entry->src_ip = src_ip;
	entry->next = table->src_buckets[bucket];
	table->src_buckets[bucket] = entry;
	return entry;
}

static struct netflow_dst_entry *
netflow_get_or_create_dst(struct netflow_src_entry *src_entry, uint32_t dst_ip)
{
	uint32_t bucket = netflow_hash_u32(dst_ip) % NETFLOW_DST_BUCKETS;
	struct netflow_dst_entry *entry = src_entry->dst_buckets[bucket];

	while (entry != NULL) {
		if (entry->dst_ip == dst_ip)
			return entry;
		entry = entry->next;
	}

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return NULL;

	entry->dst_ip = dst_ip;
	entry->next = src_entry->dst_buckets[bucket];
	src_entry->dst_buckets[bucket] = entry;
	return entry;
}

static struct netflow_proto_entry *
netflow_get_or_create_proto(struct netflow_dst_entry *dst_entry, uint8_t proto)
{
	uint32_t bucket = netflow_hash_u32((uint32_t)proto) % NETFLOW_PROTO_BUCKETS;
	struct netflow_proto_entry *entry = dst_entry->proto_buckets[bucket];

	while (entry != NULL) {
		if (entry->proto == proto)
			return entry;
		entry = entry->next;
	}

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return NULL;

	entry->proto = proto;
	entry->next = dst_entry->proto_buckets[bucket];
	dst_entry->proto_buckets[bucket] = entry;
	return entry;
}

static struct netflow_l4_entry *
netflow_get_or_create_l4(struct netflow_proto_entry *proto_entry, uint16_t l4_value)
{
	uint32_t bucket = netflow_hash_u16(l4_value) % NETFLOW_L4_BUCKETS;
	struct netflow_l4_entry *entry = proto_entry->l4_buckets[bucket];

	while (entry != NULL) {
		if (entry->l4_value == l4_value)
			return entry;
		entry = entry->next;
	}

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return NULL;

	entry->l4_value = l4_value;
	entry->next = proto_entry->l4_buckets[bucket];
	proto_entry->l4_buckets[bucket] = entry;
	return entry;
}

static void
netflow_probe_account_ipv4(uint32_t src_ip, uint32_t dst_ip, uint8_t proto, uint16_t l4_value, uint32_t bytes)
{
	struct netflow_src_entry *src_entry;
	struct netflow_dst_entry *dst_entry;
	struct netflow_proto_entry *proto_entry;
	struct netflow_l4_entry *l4_entry;

	rte_spinlock_lock(&g_netflow_lock);

	if (g_netflow_table == NULL) {
		g_netflow_table = netflow_table_create();
		if (g_netflow_table == NULL) {
			rte_spinlock_unlock(&g_netflow_lock);
			DOCA_LOG_ERR("Failed to allocate NetFlow table");
			return;
		}
	}

	src_entry = netflow_get_or_create_src(g_netflow_table, src_ip);
	if (src_entry == NULL)
		goto unlock;

	dst_entry = netflow_get_or_create_dst(src_entry, dst_ip);
	if (dst_entry == NULL)
		goto unlock;

	proto_entry = netflow_get_or_create_proto(dst_entry, proto);
	if (proto_entry == NULL)
		goto unlock;

	l4_entry = netflow_get_or_create_l4(proto_entry, l4_value);
	if (l4_entry == NULL)
		goto unlock;

	l4_entry->packets++;
	l4_entry->bytes += bytes;

unlock:
	rte_spinlock_unlock(&g_netflow_lock);
}

static int
netflow_extract_fields(struct rte_mbuf *mbuf, uint32_t *src_ip, uint32_t *dst_ip, uint8_t *proto, uint16_t *l4_value)
{
	uint32_t pkt_len;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	uint8_t *l4;
	uint16_t l3_len;

	pkt_len = rte_pktmbuf_pkt_len(mbuf);
	if (pkt_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))
		return -1;

	eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4)
		return -1;

	ipv4_hdr = (struct rte_ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct rte_ether_hdr));
	l3_len = (uint16_t)((ipv4_hdr->version_ihl & 0x0f) * 4);
	if (l3_len < sizeof(struct rte_ipv4_hdr))
		return -1;
	if (pkt_len < sizeof(struct rte_ether_hdr) + l3_len)
		return -1;

	*src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	*dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	*proto = ipv4_hdr->next_proto_id;

	l4 = (uint8_t *)ipv4_hdr + l3_len;
	if (*proto == DOCA_FLOW_PROTO_TCP) {
		struct rte_tcp_hdr *tcp_hdr;

		if (pkt_len < sizeof(struct rte_ether_hdr) + l3_len + sizeof(struct rte_tcp_hdr))
			return -1;
		tcp_hdr = (struct rte_tcp_hdr *)l4;
		*l4_value = rte_be_to_cpu_16(tcp_hdr->dst_port);
		return 0;
	}

	if (*proto == DOCA_FLOW_PROTO_UDP) {
		struct rte_udp_hdr *udp_hdr;

		if (pkt_len < sizeof(struct rte_ether_hdr) + l3_len + sizeof(struct rte_udp_hdr))
			return -1;
		udp_hdr = (struct rte_udp_hdr *)l4;
		*l4_value = rte_be_to_cpu_16(udp_hdr->dst_port);
		return 0;
	}

	if (*proto == IPPROTO_ICMP) {
		if (pkt_len < sizeof(struct rte_ether_hdr) + l3_len + 1)
			return -1;
		*l4_value = l4[0];
		return 0;
	}

	return -1;
}

static const char *
netflow_proto_to_name(uint8_t proto)
{
	switch (proto) {
	case DOCA_FLOW_PROTO_TCP:
		return "TCP";
	case DOCA_FLOW_PROTO_UDP:
		return "UDP";
	case IPPROTO_ICMP:
		return "ICMP";
	default:
		return "OTHER";
	}
}

static void
netflow_dump_table(struct netflow_table *table)
{
	uint32_t i, j, k, m;

	if (table == NULL)
		return;

	printf("\n===== NETFLOW PROBE DUMP =====\n");
	for (i = 0; i < NETFLOW_SRC_BUCKETS; i++) {
		struct netflow_src_entry *src_entry = table->src_buckets[i];

		while (src_entry != NULL) {
			for (j = 0; j < NETFLOW_DST_BUCKETS; j++) {
				struct netflow_dst_entry *dst_entry = src_entry->dst_buckets[j];

				while (dst_entry != NULL) {
					for (k = 0; k < NETFLOW_PROTO_BUCKETS; k++) {
						struct netflow_proto_entry *proto_entry = dst_entry->proto_buckets[k];

						while (proto_entry != NULL) {
							for (m = 0; m < NETFLOW_L4_BUCKETS; m++) {
								struct netflow_l4_entry *l4_entry = proto_entry->l4_buckets[m];

								while (l4_entry != NULL) {
									struct in_addr src_addr = {.s_addr = rte_cpu_to_be_32(src_entry->src_ip)};
									struct in_addr dst_addr = {.s_addr = rte_cpu_to_be_32(dst_entry->dst_ip)};
									char src_addr_str[INET_ADDRSTRLEN];
									char dst_addr_str[INET_ADDRSTRLEN];

									if (inet_ntop(AF_INET, &src_addr, src_addr_str, sizeof(src_addr_str)) == NULL)
										strncpy(src_addr_str, "invalid", sizeof(src_addr_str));
									if (inet_ntop(AF_INET, &dst_addr, dst_addr_str, sizeof(dst_addr_str)) == NULL)
										strncpy(dst_addr_str, "invalid", sizeof(dst_addr_str));
									src_addr_str[sizeof(src_addr_str) - 1] = '\0';
									dst_addr_str[sizeof(dst_addr_str) - 1] = '\0';

									printf("%s -> %s proto=%s(%u) l4=%u pkts=%" PRIu64 " bytes=%" PRIu64 "\n",
									       src_addr_str,
									       dst_addr_str,
									       netflow_proto_to_name(proto_entry->proto),
									       proto_entry->proto,
									       l4_entry->l4_value,
									       l4_entry->packets,
									       l4_entry->bytes);

									l4_entry = l4_entry->next;
								}
							}
							proto_entry = proto_entry->next;
						}
					}
					dst_entry = dst_entry->next;
				}
			}
			src_entry = src_entry->next;
		}
	}
	printf("===== END NETFLOW PROBE DUMP =====\n");
	fflush(stdout);
}

static void
netflow_probe_destroy(void)
{
	struct netflow_table *table;

	rte_spinlock_lock(&g_netflow_lock);
	table = g_netflow_table;
	g_netflow_table = NULL;
	rte_spinlock_unlock(&g_netflow_lock);

	netflow_table_free(table);
}

static void
netflow_dump_record_from_ipc(const struct netflow_ipc_record *record)
{
	struct in_addr src_addr = {.s_addr = rte_cpu_to_be_32(record->src_ip)};
	struct in_addr dst_addr = {.s_addr = rte_cpu_to_be_32(record->dst_ip)};
	char src_addr_str[INET_ADDRSTRLEN];
	char dst_addr_str[INET_ADDRSTRLEN];

	if (inet_ntop(AF_INET, &src_addr, src_addr_str, sizeof(src_addr_str)) == NULL)
		strncpy(src_addr_str, "invalid", sizeof(src_addr_str));
	if (inet_ntop(AF_INET, &dst_addr, dst_addr_str, sizeof(dst_addr_str)) == NULL)
		strncpy(dst_addr_str, "invalid", sizeof(dst_addr_str));
	src_addr_str[sizeof(src_addr_str) - 1] = '\0';
	dst_addr_str[sizeof(dst_addr_str) - 1] = '\0';

	printf("%s -> %s proto=%s(%u) l4=%u pkts=%" PRIu64 " bytes=%" PRIu64 "\n",
	       src_addr_str,
	       dst_addr_str,
	       netflow_proto_to_name(record->proto),
	       record->proto,
	       record->l4_value,
	       record->packets,
	       record->bytes);
}

static int
netflow_write_full(int fd, const void *buf, size_t len)
{
	const uint8_t *data = (const uint8_t *)buf;
	size_t sent = 0;

	while (sent < len) {
		ssize_t rc = write(fd, data + sent, len - sent);

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		sent += (size_t)rc;
	}

	return 0;
}

static int
netflow_read_full(int fd, void *buf, size_t len)
{
	uint8_t *data = (uint8_t *)buf;
	size_t read_len = 0;

	while (read_len < len) {
		ssize_t rc = read(fd, data + read_len, len - read_len);

		if (rc == 0)
			return -1;
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		read_len += (size_t)rc;
	}

	return 0;
}

static int
netflow_ipc_send(uint32_t type, const void *payload, uint32_t payload_len)
{
	struct netflow_ipc_msg_header hdr = {
		.type = type,
		.length = payload_len,
	};

	if (g_netflow_ipc_pipe[1] < 0)
		return -1;

	if (netflow_write_full(g_netflow_ipc_pipe[1], &hdr, sizeof(hdr)) != 0)
		return -1;
	if (payload_len == 0)
		return 0;

	return netflow_write_full(g_netflow_ipc_pipe[1], payload, payload_len);
}

static void
netflow_dump_child_loop(void)
{
	struct netflow_ipc_msg_header hdr;

	while (netflow_read_full(g_netflow_ipc_pipe[0], &hdr, sizeof(hdr)) == 0) {
		if (hdr.type == NETFLOW_IPC_MSG_DUMP_BEGIN) {
			printf("\n===== NETFLOW PROBE DUMP =====\n");
			continue;
		}

		if (hdr.type == NETFLOW_IPC_MSG_DUMP_END) {
			printf("===== END NETFLOW PROBE DUMP =====\n");
			fflush(stdout);
			continue;
		}

		if (hdr.type == NETFLOW_IPC_MSG_SHUTDOWN)
			break;

		if (hdr.type == NETFLOW_IPC_MSG_RECORD) {
			struct netflow_ipc_record record;

			if (hdr.length != sizeof(record))
				break;
			if (netflow_read_full(g_netflow_ipc_pipe[0], &record, sizeof(record)) != 0)
				break;
			netflow_dump_record_from_ipc(&record);
			continue;
		}

		if (hdr.length > 0) {
			char skip[256];
			uint32_t remaining = hdr.length;

			while (remaining > 0) {
				size_t chunk = remaining > sizeof(skip) ? sizeof(skip) : remaining;
				if (netflow_read_full(g_netflow_ipc_pipe[0], skip, chunk) != 0)
					break;
				remaining -= (uint32_t)chunk;
			}
		}
	}
}

static void
netflow_send_table_via_ipc(struct netflow_table *table)
{
	uint32_t i, j, k, m;

	if (table == NULL)
		return;

	if (netflow_ipc_send(NETFLOW_IPC_MSG_DUMP_BEGIN, NULL, 0) != 0)
		return;

	for (i = 0; i < NETFLOW_SRC_BUCKETS; i++) {
		struct netflow_src_entry *src_entry = table->src_buckets[i];

		while (src_entry != NULL) {
			for (j = 0; j < NETFLOW_DST_BUCKETS; j++) {
				struct netflow_dst_entry *dst_entry = src_entry->dst_buckets[j];

				while (dst_entry != NULL) {
					for (k = 0; k < NETFLOW_PROTO_BUCKETS; k++) {
						struct netflow_proto_entry *proto_entry = dst_entry->proto_buckets[k];

						while (proto_entry != NULL) {
							for (m = 0; m < NETFLOW_L4_BUCKETS; m++) {
								struct netflow_l4_entry *l4_entry = proto_entry->l4_buckets[m];

								while (l4_entry != NULL) {
									struct netflow_ipc_record record = {
										.src_ip = src_entry->src_ip,
										.dst_ip = dst_entry->dst_ip,
										.proto = proto_entry->proto,
										.l4_value = l4_entry->l4_value,
										.reserved = 0,
										.packets = l4_entry->packets,
										.bytes = l4_entry->bytes,
									};

									if (netflow_ipc_send(NETFLOW_IPC_MSG_RECORD, &record, sizeof(record)) != 0)
										return;
									l4_entry = l4_entry->next;
								}
							}
							proto_entry = proto_entry->next;
						}
					}
					dst_entry = dst_entry->next;
				}
			}
			src_entry = src_entry->next;
		}
	}

	(void)netflow_ipc_send(NETFLOW_IPC_MSG_DUMP_END, NULL, 0);
}

static void
netflow_probe_rotate_and_dump(void)
{
	struct netflow_table *new_table;
	struct netflow_table *snapshot;

	new_table = netflow_table_create();
	if (new_table == NULL) {
		DOCA_LOG_ERR("Failed to allocate new NetFlow table for rotation");
		return;
	}

	rte_spinlock_lock(&g_netflow_lock);
	snapshot = g_netflow_table;
	g_netflow_table = new_table;
	rte_spinlock_unlock(&g_netflow_lock);

	if (snapshot == NULL)
		return;

	if (g_netflow_probe_started)
		netflow_send_table_via_ipc(snapshot);
	else
		netflow_dump_table(snapshot);

	netflow_table_free(snapshot);
}

int
simple_fwd_netflow_probe_start(void)
{
	if (g_netflow_probe_started)
		return 0;

	if (pipe(g_netflow_ipc_pipe) != 0) {
		DOCA_LOG_ERR("Failed to create NetFlow IPC pipe: %s", strerror(errno));
		g_netflow_ipc_pipe[0] = -1;
		g_netflow_ipc_pipe[1] = -1;
		return -1;
	}

	g_netflow_dump_pid = fork();
	if (g_netflow_dump_pid < 0) {
		DOCA_LOG_ERR("Failed to fork NetFlow dump worker: %s", strerror(errno));
		close(g_netflow_ipc_pipe[0]);
		close(g_netflow_ipc_pipe[1]);
		g_netflow_ipc_pipe[0] = -1;
		g_netflow_ipc_pipe[1] = -1;
		return -1;
	}

	if (g_netflow_dump_pid == 0) {
		close(g_netflow_ipc_pipe[1]);
		g_netflow_ipc_pipe[1] = -1;
		netflow_dump_child_loop();
		if (g_netflow_ipc_pipe[0] >= 0)
			close(g_netflow_ipc_pipe[0]);
		_exit(EXIT_SUCCESS);
	}

	close(g_netflow_ipc_pipe[0]);
	g_netflow_ipc_pipe[0] = -1;
	g_netflow_probe_started = true;

	rte_spinlock_lock(&g_netflow_lock);
	if (g_netflow_table == NULL)
		g_netflow_table = netflow_table_create();
	rte_spinlock_unlock(&g_netflow_lock);

	if (g_netflow_table == NULL) {
		DOCA_LOG_ERR("Failed to allocate NetFlow active table");
		(void)netflow_ipc_send(NETFLOW_IPC_MSG_SHUTDOWN, NULL, 0);
		close(g_netflow_ipc_pipe[1]);
		g_netflow_ipc_pipe[1] = -1;
		(void)waitpid(g_netflow_dump_pid, NULL, 0);
		g_netflow_dump_pid = -1;
		g_netflow_probe_started = false;
		return -1;
	}

	return 0;
}

void
simple_fwd_netflow_probe_stop(void)
{
	if (!g_netflow_probe_started)
		return;

	netflow_probe_rotate_and_dump();
	(void)netflow_ipc_send(NETFLOW_IPC_MSG_SHUTDOWN, NULL, 0);

	if (g_netflow_ipc_pipe[1] >= 0) {
		close(g_netflow_ipc_pipe[1]);
		g_netflow_ipc_pipe[1] = -1;
	}

	if (g_netflow_dump_pid > 0) {
		(void)waitpid(g_netflow_dump_pid, NULL, 0);
		g_netflow_dump_pid = -1;
	}

	g_netflow_probe_started = false;
	netflow_probe_destroy();
}

/*
 * Adjust the mbuf pointer, to point on the packet's raw data
 *
 * @m [in]: DPDK structure represent the packet received
 * @pinfo [in]: packet info representation  in the application
 */
static void vnf_adjust_mbuf(struct rte_mbuf *m, struct simple_fwd_pkt_info *pinfo)
{
	int diff = pinfo->outer.l2 - VNF_PKT_L2(m);

	rte_pktmbuf_adj(m, diff);
}

/*
 * Process received packets, mainly retrieving packet's key, then checking if there is an entry found
 * matching the generated key, in the entries table.
 * If no entry found, the function will create and add new one.
 * In addition, this function handles aging as well
 *
 * @mbuf [in]: DPDK structure represent the packet received
 * @queue_id [in]: Queue ID
 * @vnf [in]: Holder for all functions pointers used by the application
 */
static void simple_fwd_process_offload(struct rte_mbuf *mbuf, uint16_t queue_id, struct app_vnf *vnf)
{
	struct simple_fwd_pkt_info pinfo;
	struct rte_ipv4_hdr *ipv4_hdr;
	uint8_t *src_ip, *dst_ip;

	memset(&pinfo, 0, sizeof(struct simple_fwd_pkt_info));
	if (simple_fwd_parse_packet(VNF_PKT_L2(mbuf), VNF_PKT_LEN(mbuf), &pinfo))
		return;
	pinfo.orig_data = mbuf;
	pinfo.orig_port_id = mbuf->port;
	pinfo.pipe_queue = queue_id;
	pinfo.rss_hash = mbuf->hash.rss;
	if (pinfo.outer.l3_type != IPV4)
		return;

	ipv4_hdr = (struct rte_ipv4_hdr *)pinfo.outer.l3;
	src_ip = (uint8_t *)&ipv4_hdr->src_addr;
	dst_ip = (uint8_t *)&ipv4_hdr->dst_addr;
	
	// DOCA_LOG_INFO("Packet seen on Port %u | Src IP: %u.%u.%u.%u -> Dst IP: %u.%u.%u.%u",
	//	      pinfo.orig_port_id,
	//	      src_ip[0], src_ip[1], src_ip[2], src_ip[3],
	//	      dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);

	vnf->vnf_process_pkt(&pinfo);
	vnf_adjust_mbuf(mbuf, &pinfo);
}

int simple_fwd_process_pkts(void *process_pkts_params)
{
	int result;
	uint64_t cur_tsc, last_tsc;
	uint64_t probe_last_tsc;
	uint64_t probe_interval_tsc;
	struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
	uint16_t j, nb_rx, queue_id;
	uint32_t port_id = 0, core_id = rte_lcore_id();
	struct vnf_per_core_params *params = &core_params_arr[core_id];
	struct simple_fwd_config *app_config = ((struct simple_fwd_process_pkts_params *)process_pkts_params)->cfg;
	struct app_vnf *vnf = ((struct simple_fwd_process_pkts_params *)process_pkts_params)->vnf;
	uint32_t src_ip, dst_ip;
	uint8_t proto;
	uint16_t l4_value;

	if (!params->used) {
		DOCA_LOG_DBG("Core %u nothing need to do", core_id);
		return 0;
	}
	DOCA_LOG_TRC("Core %u process queue %u start", core_id, params->queues[0]);
	last_tsc = rte_rdtsc();
	probe_last_tsc = last_tsc;
	probe_interval_tsc = NETFLOW_DUMP_INTERVAL_SEC * rte_get_timer_hz();

	while (!force_quit) {
		if (core_id == rte_get_main_lcore()) {
			cur_tsc = rte_rdtsc();
			if (cur_tsc > probe_last_tsc + probe_interval_tsc) {
				netflow_probe_rotate_and_dump();
				probe_last_tsc = cur_tsc;
			}

			if (cur_tsc > last_tsc + app_config->stats_timer) {
				result = vnf->vnf_dump_stats(0);
				if (result != 0)
					return result;
				last_tsc = cur_tsc;
			}
		}
		for (port_id = 0; port_id < NUM_OF_PORTS; port_id++) {
			queue_id = params->queues[port_id];
			nb_rx = rte_eth_rx_burst(port_id, queue_id, mbufs, VNF_RX_BURST_SIZE);
			for (j = 0; j < nb_rx; j++) {
				if (netflow_extract_fields(mbufs[j], &src_ip, &dst_ip, &proto, &l4_value) == 0)
					netflow_probe_account_ipv4(src_ip, dst_ip, proto, l4_value, VNF_PKT_LEN(mbufs[j]));

				if (app_config->hw_offload)
					simple_fwd_process_offload(mbufs[j], queue_id, vnf);
				if (app_config->rx_only)
					rte_pktmbuf_free(mbufs[j]);
				else
					rte_eth_tx_burst(port_id ^ 1, queue_id, &mbufs[j], 1);
			}
			if (app_config->age_thread)
				vnf->vnf_flow_age(port_id, queue_id);
		}
	}

	return 0;
}

void simple_fwd_process_pkts_stop(void)
{
	force_quit = true;
}

/*
 * Callback function for setting time stats dump
 *
 * @param [in]: time for dumping stats
 * @config [out]: application configuration for setting the time
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t stats_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;

	app_config->stats_timer = *(int *)param;
	DOCA_LOG_DBG("Set stats_timer:%lu", app_config->stats_timer);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting number of queues
 *
 * @param [in]: number of queues to set
 * @config [out]: application configuration for setting the number of queues
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t nr_queues_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;
	int nr_queues = *(int *)param;

	if (nr_queues < 2) {
		DOCA_LOG_ERR("Invalid nr_queues should >= 2");
		return DOCA_ERROR_INVALID_VALUE;
	}
	app_config->dpdk_cfg->port_config.nb_queues = nr_queues;
	app_config->dpdk_cfg->port_config.rss_support = 1;
	DOCA_LOG_DBG("Set nr_queues:%u", nr_queues);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting the "rx-only" mode, where the application only receives packets
 *
 * @param [in]: parameter indicates whther or not to set the "rx-only" mode
 * @config [out]: application configuration to set the "rx-only" mode
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t rx_only_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;

	app_config->rx_only = *(bool *)param ? 1 : 0;
	DOCA_LOG_DBG("Set rx_only:%u", app_config->rx_only);
	return DOCA_SUCCESS;
}

/*
 * Callback function for the HW offload
 *
 * @param [in]: parameter indicates whther or not to set the HW offload
 * @config [out]: application configuration to set the HW offload
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t hw_offload_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;

	app_config->hw_offload = *(bool *)param ? 1 : 0;
	DOCA_LOG_DBG("Set hw_offload:%u", app_config->hw_offload);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting the hairpin usage
 *
 * @param [in]: parameter indicates whther or not to use hairpin queues
 * @config [out]: application configuration to set hairpin usage
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t hairpinq_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;

	app_config->is_hairpin = *(bool *)param;
	DOCA_LOG_DBG("Set is_hairpin:%u", app_config->is_hairpin);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting dedicated thread for aging handling
 *
 * @param [in]: parameter indicates whther or not to use dedicated thread for aging
 * @config [out]: application configuration to set the usage of a dedicated thread for aged flows
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t age_thread_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;

	app_config->age_thread = *(bool *)param;
	DOCA_LOG_DBG("Set age_thread:%s", app_config->age_thread ? "true" : "false");
	return DOCA_SUCCESS;
}

/*
 * Registers all flags used by the application for DOCA argument parser, so that when parsing
 * it can be parsed accordingly
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t register_simple_fwd_params(void)
{
	doca_error_t result;
	struct doca_argp_param *stats_param, *nr_queues_param, *rx_only_param, *hw_offload_param;
	struct doca_argp_param *hairpinq_param, *age_thread_param;

	/* Create and register stats timer param */
	result = doca_argp_param_create(&stats_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(stats_param, "t");
	doca_argp_param_set_long_name(stats_param, "stats-timer");
	doca_argp_param_set_arguments(stats_param, "<time>");
	doca_argp_param_set_description(stats_param, "Set interval to dump stats information");
	doca_argp_param_set_callback(stats_param, stats_callback);
	doca_argp_param_set_type(stats_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(stats_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register queues number param */
	result = doca_argp_param_create(&nr_queues_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(nr_queues_param, "q");
	doca_argp_param_set_long_name(nr_queues_param, "nr-queues");
	doca_argp_param_set_arguments(nr_queues_param, "<num>");
	doca_argp_param_set_description(nr_queues_param, "Set queues number");
	doca_argp_param_set_callback(nr_queues_param, nr_queues_callback);
	doca_argp_param_set_type(nr_queues_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(nr_queues_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register RX only param */
	result = doca_argp_param_create(&rx_only_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(rx_only_param, "r");
	doca_argp_param_set_long_name(rx_only_param, "rx-only");
	doca_argp_param_set_description(rx_only_param, "Set rx only");
	doca_argp_param_set_callback(rx_only_param, rx_only_callback);
	doca_argp_param_set_type(rx_only_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(rx_only_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register HW offload param */
	result = doca_argp_param_create(&hw_offload_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(hw_offload_param, "o");
	doca_argp_param_set_long_name(hw_offload_param, "hw-offload");
	doca_argp_param_set_description(hw_offload_param, "Set PCI address of the RXP engine to use");
	doca_argp_param_set_callback(hw_offload_param, hw_offload_callback);
	doca_argp_param_set_type(hw_offload_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(hw_offload_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register hairpin queue param */
	result = doca_argp_param_create(&hairpinq_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(hairpinq_param, "hq");
	doca_argp_param_set_long_name(hairpinq_param, "hairpinq");
	doca_argp_param_set_description(hairpinq_param, "Set forwarding to hairpin queue");
	doca_argp_param_set_callback(hairpinq_param, hairpinq_callback);
	doca_argp_param_set_type(hairpinq_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(hairpinq_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register age thread param */
	result = doca_argp_param_create(&age_thread_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(age_thread_param, "a");
	doca_argp_param_set_long_name(age_thread_param, "age-thread");
	doca_argp_param_set_description(age_thread_param, "Start thread do aging");
	doca_argp_param_set_callback(age_thread_param, age_thread_callback);
	doca_argp_param_set_type(age_thread_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(age_thread_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Register version callback for DOCA SDK & RUNTIME */
	result = doca_argp_register_version_callback(sdk_version_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register version callback: %s", doca_error_get_descr(result));
		return result;
	}
	return DOCA_SUCCESS;
}

void simple_fwd_map_queue(uint16_t nb_queues)
{
	int i, queue_idx = 0;

	memset(core_params_arr, 0, sizeof(core_params_arr));
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (!rte_lcore_is_enabled(i))
			continue;
		core_params_arr[i].ports[0] = 0;
		core_params_arr[i].ports[1] = 1;
		core_params_arr[i].queues[0] = queue_idx;
		core_params_arr[i].queues[1] = queue_idx;
		core_params_arr[i].used = true;
		queue_idx++;
		if (queue_idx >= nb_queues)
			break;
	}
}

void simple_fwd_destroy(struct app_vnf *vnf)
{
	vnf->vnf_destroy();
}
