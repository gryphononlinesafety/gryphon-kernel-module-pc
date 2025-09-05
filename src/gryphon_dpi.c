/*
 * Copyright (C) 2025 GryphonConnect [ https://gryphonconnect.com/ ]
 * Author: Naveen Kumar Gutti <naveen@gryphonconnect.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/stat.h>
#include <linux/spinlock.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_ether.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
#include <linux/sctp.h>
#endif
#include <linux/udp.h>
#include <net/genetlink.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/hashtable.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include "gryphon_buffer_management.h"

#define GRY_MODULE_VERSION "01.0001.09"

#define PORTSCAN_ENABLED 1
#define GRYPHON_DEBUG_ENABLED 0
#define PARENT_PROC_DIR "gryphon"
#define PORTSCAN_PROC_DIR "portscan"
#define PORTSCAN_DEVICES_FILE "devices"

#define HASHTABLES_PROC_FILE "hashtable_name"
#define HASHTABLES_PRINT_FILE "hashtable_data"
#define PARENTAL_CONTROL_VERBOSE_FILE "pc_verbose"
#define PORTSCAN_VERBOSE_FILE "verbose"
#define VERBOSE_BUFFER_SIZE 8
#define PORTSCAN_DEVICES_BUFFER_SIZE 4096

#define PORTSCAN_TCP_NORMAL_THRESHOLD 25
#define NORMAL_PORTS_LENGTH 50
#define NO_OF_DEVICES 256
#define MULTICAST_PREFIX 0b00001110
#define CLASS_A_START 0xA000000
#define CLASS_A_END 0xAFFFFFF
#define CLASS_B_START 0xAC100000
#define CLASS_B_END 0xAC1FFFFF
#define CLASS_C_START 0xC0A80000
#define CLASS_C_END 0xC0A8FFFF

#define RAW_IP_LIST_LEN 100
#define MAX_MUSIC_IPS 5
#define ADD_RULE 0
#define RM_RULE 1
#define PAUSED 1
#define UNPAUSED 0

#define HASH_MAC(c) (unsigned int)(c[0]+c[1]+c[2]+c[3]+c[4]+c[5])
#define HASH(i) i
#define CLIENT_IP(x) (((x & 0x0000ffff) == 0x0000a8c0) || ((x & 0x000000ff) == 0x0000000a) || ((x & 0x0000f0ff) == 0x000010ac))?1:0

// Packet matching
#define HTTP_GET "\x47\x45\x54\x20\x2f"
#define HTTP_GET_LEN 5

#define TLS_TYPE_VER_LEN 3

#define LEN_NTOHS(data) \
         ntohs(*((unsigned short*)data))

#define PUFLAGS_VRSN    0x01
#define PUFLAGS_CID     0x08
#define PUFLAGS_MPTH    0x40
#define PUFLAGS_RSV     0x80

#define STUN_HDR_LEN                   20 /* STUN message header length */
#define MIN_HDR_LEN                     4
#define STUN_ID "\x21\x12\xa4\x42"
#define STUN_ID_LEN 4

#define GET_SHORT_INT(s, cp) { \
		unsigned char *pc = (unsigned char *)(cp); \
		(s) = ((unsigned short)pc[0] << 8) \
			| ((unsigned short)pc[1]) \
			; \
	}


#define GQUIC_MAGIC2	0x513032
#define GQUIC_MAGIC3	0x513033
#define GQUIC_MAGIC4	0x513034

#define QUIC_LPT_INITIAL 0x0
#define QUIC_LPT_0RTT       0x1
#define QUIC_LPT_HANDSHAKE  0x2
#define QUIC_LPT_RETRY      0x3

#if ENABLE_GRY_MARK
// GRYPHON PACKET MARK VALUE
#define GRY_MARK_VALUE 0x09
#endif

// HASH TABLES
static DEFINE_HASHTABLE(labnf_redirect_hash, 8);
static DEFINE_HASHTABLE(labnf_safe_mac_hash, 8);
static DEFINE_HASHTABLE(labnf_unsafe_ip_hash, 8);
static DEFINE_HASHTABLE(labnf_music_ip_hash, 8);
static DEFINE_HASHTABLE(labnf_apc_ip_hash, 8);
static DEFINE_HASHTABLE(labnf_apc_mac_hash, 8);
static DEFINE_HASHTABLE(labnf_safe_youtube_mac_hash, 8);
static DEFINE_HASHTABLE(labnf_unsafe_youtube_ip_hash, 8);
static DEFINE_HASHTABLE(labnf_apple_priv_hash, 8);
static DEFINE_HASHTABLE(labnf_apple_priv_mac_hash, 8);
static DEFINE_HASHTABLE(labnf_cloud_server_hash, 8);

// SPIN LOCKS
static DEFINE_SPINLOCK(labnf_redirect_lock);
static DEFINE_SPINLOCK(labnf_safe_mac_lock);
static DEFINE_SPINLOCK(labnf_unsafe_ip_lock);
static DEFINE_SPINLOCK(labnf_music_ip_lock);
static DEFINE_SPINLOCK(labnf_apc_ip_lock);
static DEFINE_SPINLOCK(labnf_apc_mac_lock);
static DEFINE_SPINLOCK(labnf_safe_youtube_mac_lock);
static DEFINE_SPINLOCK(labnf_unsafe_youtube_ip_lock);
static DEFINE_SPINLOCK(labnf_apple_priv_lock);
static DEFINE_SPINLOCK(labnf_cloud_server_lock);

#if PORTSCAN_ENABLED
static DEFINE_SPINLOCK(gry_lock);
#endif

// RW LOCKS
static rwlock_t genl_rwlock = __RW_LOCK_UNLOCKED(genl_rwlock);
static rwlock_t ss_rwlock = __RW_LOCK_UNLOCKED(ss_rwlock);

typedef struct raw_ip_list_{ 
	int len;
	int ip [RAW_IP_LIST_LEN];
	rwlock_t lock;
} raw_ip_list_;

typedef struct labnf_pack {
	int len;
	unsigned char databuff[ETH_FRAME_LEN];
	char if_name[16];
	unsigned int gso_length;
} labnf_pack;

typedef struct musicappiplist_t {
	int ipcount;
	int ipaddr[MAX_MUSIC_IPS];
} musicappiplist_t;

typedef struct {
	unsigned char mac[6];
	unsigned int fake_ip;
	unsigned int dns_ip;
	unsigned int dns_new_ip;
	unsigned int peer_ip;
	unsigned int source[40];
	unsigned int dest[40];
	unsigned int nport;
	struct hlist_node hnode;
	int new_flow[40];
	int flow_fail;
	int inet_pause;
	int inet_bedtime_music_allowed;
}redirect_;

typedef struct {
	unsigned char mac[6];
	int unsafe_ip;
	struct hlist_node hnode;
} safe_mac_ip_;

typedef struct {
	int music_ip;
	struct hlist_node hnode;
} musical_ip_;

typedef struct {
	int apc_ip;
	struct hlist_node hnode;
}apc_ip_;

typedef struct {
	unsigned char mac[6];
	struct hlist_node hnode;
}apc_mac_ip_;

typedef struct {
	uint32_t ipaddr;
	struct hlist_node hnode;
} apple_priv_ip_;

typedef struct {
	uint32_t ipaddr;
	struct hlist_node hnode;
} cloud_server_ip_;

typedef struct {
	unsigned char mac[ETH_ALEN];
	int action;
} apple_priv_mac_t;

typedef struct {
	apple_priv_mac_t data;
	struct hlist_node hnode;
} apple_priv_mac_;

enum {
	LABPM_ATTR_UNSPEC,
	LABPM_ATTR_DNAT,
	LABPM_ATTR_QUERY_IP,
	LABPM_ATTR_SEND_HNAME,
	LABPM_ATTR_INET_PAUSE,
	LABPM_ATTR_INET_UNPAUSE,
	LABPM_ATTR_RAW_IP_LIST,
	LABPM_ATTR_PACKETS,
	LABPM_ATTR_SSIP_LIST,
	LABPM_ATTR_SAFE_MAC,
	LABPM_ATTR_UNSAFE_IP,
	LABPM_ATTR_MUSIC_IP,
	LABPM_ATTR_INET_BEDTIME_PAUSE,
	LABPM_ATTR_FRAGMENT_TUPLE,
	LABPM_ATTR_APPLE_PRIV,
	LABPM_ATTR_APPLE_PRIV_MAC,
	LABPM_ATTR_CLOUD_SERVER,
	__LABPM_ATTR_MAX,
};
#define LABPM_ATTR_MAX (__LABPM_ATTR_MAX + 1)

enum labpm_cmd{
	LABPM_CMD_DNAT = 1,
	LABPM_CMD_QUERY_IP,
	LABPM_CMD_DNAT_SET_NEW_DNS,
	LABPM_CMD_FLUSH_TABLE,
	LABPM_CMD_SEND_HNAME,
	LABPM_CMD_INIT,
	LABPM_CMD_INET_PAUSE_UNPAUSE,
	LABPM_CMD_CLOSE,
	LABPM_CMD_RAW_IP_LIST,
	LABPM_CMD_WAKEUP_QUEUE,
	LABPM_CMD_PACKET,
	LABPM_CMD_SS_IP_LIST,
	LABPM_CMD_SAFE_MAC,
	LABPM_CMD_UNSAFE_IP,
	LABPM_CMD_APC_MAC,
	LABPM_CMD_MUSIC_IP_LIST,
	LABPM_CMD_APC_IP,
	LABPM_CMD_SAFE_YOUTUBE_MAC,
	LABPM_CMD_UNSAFE_YOUTUBE_IP,
	LABPM_CMD_FRAGMENT_TUPLE,
	LABPM_CMD_RA_INIT,
	LABPM_CMD_RA_CLOSE,
	LABPM_CMD_UDP_INIT,
	LABPM_CMD_APPLE_PRIV,
	LABPM_CMD_APPLE_PRIV_MAC,
	LABPM_CMD_CLOUD_SERVER,
	LABPM_CMD_MAX
};


static struct nla_policy labpm_genl_policy[__LABPM_ATTR_MAX + 1]  = {
	[LABPM_ATTR_DNAT] = {.type = NLA_NUL_STRING},
	[LABPM_ATTR_QUERY_IP] = {.type = NLA_NUL_STRING},
	[LABPM_ATTR_SEND_HNAME] = {.type = NLA_NUL_STRING},
	[LABPM_ATTR_INET_PAUSE] = {.type = NLA_NUL_STRING},
	[LABPM_ATTR_INET_UNPAUSE] = {.type = NLA_NUL_STRING},
	[LABPM_ATTR_RAW_IP_LIST] = {.type = NLA_UNSPEC, .len = sizeof(raw_ip_list_)},
	[LABPM_ATTR_PACKETS] = {.type = NLA_UNSPEC, .len = sizeof(labnf_pack)},
	[LABPM_ATTR_SSIP_LIST] = {.type = NLA_NUL_STRING},
	[LABPM_ATTR_SAFE_MAC] = {.type = NLA_NUL_STRING},
	[LABPM_ATTR_UNSAFE_IP] = {.type = NLA_NUL_STRING},
	[LABPM_ATTR_MUSIC_IP] = {.type = NLA_UNSPEC, .len = sizeof(musicappiplist_t)},
	[LABPM_ATTR_INET_BEDTIME_PAUSE] = {.type = NLA_NUL_STRING},
	[LABPM_ATTR_FRAGMENT_TUPLE] = {.len = sizeof(struct gry_fragment_tuple_payload_t)},
	[LABPM_ATTR_APPLE_PRIV] = {.type = NLA_U32},
	[LABPM_ATTR_CLOUD_SERVER] = {.type = NLA_U32},
	[LABPM_ATTR_APPLE_PRIV_MAC] = {.len = sizeof(apple_priv_mac_t)}
};

// create the labpm_genl_family structure
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
static struct genl_family labpm_genl_family;
#else
static struct genl_family labpm_genl_family = {
	.id = 0,
	.hdrsize = 0,
	.name = "LABPM_DNAT",
	.version = 1,
	.maxattr = LABPM_ATTR_MAX,
};
#endif

// create the traffic control genl_family structure
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
static struct genl_family gry_ra_genl_family;
#else
static struct genl_family gry_ra_genl_family = {
	.id = 0,
	.hdrsize = 0,
	.name = "GRY_TC",
	.version = 1,
	.maxattr = LABPM_ATTR_MAX,
};
#endif


struct genl_info *info = NULL;
struct genl_info *udp_info = NULL;
#if 0
struct genl_info *ra_info = NULL;
#endif

int safesearchIps[10];
int safesearchCount = 0;

#if PORTSCAN_ENABLED
static struct proc_dir_entry *parent_dir;
static struct proc_dir_entry *portscan_dir;
static struct proc_dir_entry *portscan_devices_file;
static struct proc_dir_entry *portscan_verbose_file;
#endif
#if GRYPHON_DEBUG_ENABLED
static struct proc_dir_entry *parental_control_verbose_file;
static struct proc_dir_entry *hashtables_verbose_file;
static struct proc_dir_entry *hashtables_print_file;
#endif

unsigned int portscan_verbose = 0;
unsigned int parental_control_verbose = 0;
unsigned int hashtable_name = 0;
char portscan_verbose_buffer[VERBOSE_BUFFER_SIZE] = {0};
char portscan_devices_buffer[PORTSCAN_DEVICES_BUFFER_SIZE] = {0};

char parental_control_verbose_buffer[VERBOSE_BUFFER_SIZE] = {0};

int port_ignore[] = {53, 67, 68, 80, 123, 443, 1900};

// structure to store the port count of tcp special scans
// XMAS, SYN or any TCP special scans we will increment the no of occurrances in port_count
struct tcp_special_data_t {
	unsigned char mac[6];
	int port_count;
};

typedef struct {
	int vpn_ip;
	struct hlist_node hnode;
} vpn_ip_;

// structure to store the tcp special scan nodes information
// node_count - will give the details about how many nodes are in the memory
// nodes - will be allocated NO_OF_DEVICES nodes to store the information statically to avoid defragmentation
// node_count will help in quick search rather than entire NO_OF_DEVICES iterations on every packet
struct tcp_special_nodes_t {
	int node_count;
	struct tcp_special_data_t *nodes;
};

// variable to store all the tcp special scans
struct tcp_special_nodes_t tcp_special_nodes;
// variable to store the copy tcp_special_scan data
struct tcp_special_nodes_t tcp_special_nodes_buf;

// structure used for normal scan detections
// mac - will store the mac address of the client
// ports - will store the unique ports
struct normal_port_scan_data_t{
	unsigned char mac[6];
	int port_count;
	int actual_port_count;
	unsigned short ports[NORMAL_PORTS_LENGTH];
};

// structure used for normal scan detection on all devices
// node_count - will give the details about how many nodes are in the memory
// nodes - will be allocated NO_OF_DEVICES macro length to avoid memory defragmentation on the fly
// node_count will help in quick search rather than entire NO_OF_DEVICES iterations on every packet
struct normal_port_scan_t {
	int node_count;
	struct normal_port_scan_data_t *nodes;
};

typedef struct {
    int len;
    char databuff[ETH_FRAME_LEN];
    char if_name[16];
} vpnnf_pack;

// variable to store the tcp normal scan data
struct normal_port_scan_t tcp_normal_scan;
// variable to store the copy of tcp_normal_scan data
struct normal_port_scan_t tcp_normal_scan_buf;

struct timer_list port_scan_timer;

// GSO capable
// This variable will confirm if the platform supports GSO or not
// Incase of GSO not supported, adding to RAB doesn't include the 
// GSO conditions. But still retransmissions will be checked
bool is_gso_capable;

// Variable for checking the fragmented tuple
struct gry_fragment_tuple_t *fragTuple;

#if PORTSCAN_ENABLED
// Initialize the data storage nodes and memset them to 0
void init_data_storage(void){
	tcp_special_nodes.node_count = 0;
	tcp_special_nodes.nodes = gry_safe_alloc( NO_OF_DEVICES * sizeof(struct tcp_special_data_t));
	memset(tcp_special_nodes.nodes, 0, NO_OF_DEVICES * sizeof(struct tcp_special_data_t));

	tcp_special_nodes_buf.node_count = 0;
	tcp_special_nodes_buf.nodes = gry_safe_alloc( NO_OF_DEVICES * sizeof(struct tcp_special_data_t));
	memset(tcp_special_nodes_buf.nodes, 0, NO_OF_DEVICES * sizeof(struct tcp_special_data_t));

	tcp_normal_scan.node_count = 0;
	tcp_normal_scan.nodes = gry_safe_alloc( NO_OF_DEVICES * sizeof(struct normal_port_scan_data_t));
	memset(tcp_normal_scan.nodes, 0, NO_OF_DEVICES * sizeof(struct normal_port_scan_data_t));

	tcp_normal_scan_buf.node_count = 0;
	tcp_normal_scan_buf.nodes = gry_safe_alloc( NO_OF_DEVICES * sizeof(struct normal_port_scan_data_t));
	memset(tcp_normal_scan_buf.nodes, 0, NO_OF_DEVICES * sizeof(struct normal_port_scan_data_t));

}

// reset data storage locations
void clear_data_storage(void){
	tcp_special_nodes.node_count = 0;
	memset(tcp_special_nodes.nodes, 0, NO_OF_DEVICES * sizeof(struct tcp_special_data_t));
	
	tcp_normal_scan.node_count = 0;
	memset(tcp_normal_scan.nodes, 0, NO_OF_DEVICES * sizeof(struct normal_port_scan_data_t));
}

// reset buffer storage locations
void clear_data_storage_buffer(void){
	tcp_special_nodes_buf.node_count = 0;
	memset(tcp_special_nodes_buf.nodes, 0, NO_OF_DEVICES * sizeof(struct tcp_special_data_t));
	
	tcp_normal_scan_buf.node_count = 0;
	memset(tcp_normal_scan_buf.nodes, 0, NO_OF_DEVICES * sizeof(struct normal_port_scan_data_t));
}

// free data storage locations
void free_data_storage(void){
	if(tcp_special_nodes.nodes){
		kfree(tcp_special_nodes.nodes);
	}

	if(tcp_normal_scan.nodes){
		kfree(tcp_normal_scan.nodes);
	}

	if(tcp_special_nodes_buf.nodes){
		kfree(tcp_special_nodes_buf.nodes);
	}
	
	if(tcp_normal_scan_buf.nodes){
		kfree(tcp_normal_scan_buf.nodes);
	}
}

void add_tcp_special_scan_to_store(unsigned char *mac, int len){
	int i = 0;
	struct tcp_special_data_t *tcp_data_ptr;

	if(tcp_special_nodes.node_count == 0){
		tcp_data_ptr = tcp_special_nodes.nodes;
		memcpy(tcp_data_ptr->mac, mac, len);
		tcp_data_ptr->port_count = 1;
		tcp_special_nodes.node_count += 1;
	} else {
		tcp_data_ptr = tcp_special_nodes.nodes;
		for(i = 0; i < tcp_special_nodes.node_count; i++){
			if(!memcmp((tcp_data_ptr+i)->mac, mac, len)){
				(tcp_data_ptr+i)->port_count += 1;
				// printk("gryphon: adding to current value: %pM6, %d\n", tcp_data_ptr->mac, tcp_data_ptr->port_count);
				return;
			}
		}
		if(tcp_special_nodes.node_count >= NO_OF_DEVICES){
			return;
		}
		tcp_data_ptr = (tcp_special_nodes.nodes + tcp_special_nodes.node_count);
		memcpy(tcp_data_ptr->mac, mac, len);
		tcp_data_ptr->port_count = 1;
		tcp_special_nodes.node_count += 1;
	}
}

void add_tcp_normal_scan_to_store(unsigned char *mac, int len, unsigned int port){
	int i = 0, j = 0;
	struct normal_port_scan_data_t *tcp_normal_ptr = NULL;
	if(tcp_normal_scan.node_count == 0) {
		// No nodes are present, so directly store on the first location
		tcp_normal_ptr = tcp_normal_scan.nodes;
		memcpy(tcp_normal_ptr->mac, mac, len);
		tcp_normal_ptr->ports[tcp_normal_ptr->port_count] = port;
		tcp_normal_ptr->port_count++;
		tcp_normal_scan.node_count++;
		tcp_normal_ptr->actual_port_count++;
	} else {
		tcp_normal_ptr = tcp_normal_scan.nodes;
		for(i=0; i<tcp_normal_scan.node_count; i++){
			if(!memcmp((tcp_normal_ptr+i)->mac, mac, len)){
				for(j=0; j<(tcp_normal_ptr+i)->port_count; j++){
					if((tcp_normal_ptr+i)->ports[j] ==  port){
						return;
					}
				}
				(tcp_normal_ptr+i)->ports[(tcp_normal_ptr+i)->port_count] = port;
				(tcp_normal_ptr+i)->port_count++;
				if((tcp_normal_ptr+i)->port_count >= NORMAL_PORTS_LENGTH){
					(tcp_normal_ptr+i)->port_count = 0;
				}
				(tcp_normal_ptr+i)->actual_port_count++;
				return;
			}
		}

		if(tcp_normal_scan.node_count >= NO_OF_DEVICES){
			printk("gryphon: no of devices exceeded to handle, ignoring\n");
			return;
		}
		tcp_normal_ptr = (tcp_normal_scan.nodes + tcp_normal_scan.node_count);
		memcpy(tcp_normal_ptr->mac, mac, len);
		tcp_normal_ptr->ports[tcp_normal_ptr->port_count] = port;
		tcp_normal_ptr->port_count++;
		if(tcp_normal_ptr->port_count >= NORMAL_PORTS_LENGTH){
			tcp_normal_ptr->port_count = 0;
		}
		tcp_normal_scan.node_count++;
		tcp_normal_ptr->actual_port_count++;
	}
}
#endif

static inline u32 pntoh24(const void *p)
{
    return (u32)*((const u8 *)(p)+0)<<16|
           (u32)*((const u8 *)(p)+1)<<8|
           (u32)*((const u8 *)(p)+2)<<0;
}

static inline u32 pntoh32(const void *p)
{
    return (u32)*((const u8 *)(p)+0)<<24|
           (u32)*((const u8 *)(p)+1)<<16|
           (u32)*((const u8 *)(p)+2)<<8|
           (u32)*((const u8 *)(p)+3)<<0;
}

/* Returns the QUIC draft version or 0 if not applicable. */
static inline int quic_draft_version(u32 version)
{
	/* IETF Draft versions */
	if ((version >> 8) == 0xff0000) {
		return (u8) version;
	}

	/* Facebook mvfst, based on draft -22. */
	if (version == 0xfaceb001) {
		return 22;
	}

	/* Facebook mvfst, based on draft -27. */
	if (version == 0xfaceb002 || version == 0xfaceb00e) {
		return 27;
	}

	/* GQUIC Q050, T050 and T051: they are not really based on any drafts,
	 * but we must return a sensible value */
	if (version == 0x51303530 ||
			version == 0x54303530 ||
			version == 0x54303531) {
		return 27;
	}

	/* https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-15
	   "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
	   forcing version negotiation to be exercised"
	   It is tricky to return a correct draft version: such number is primarly
	   used to select a proper salt (which depends on the version itself), but
	   we don't have a real version here! Let's hope that we need to handle
	   only latest drafts... */
	if ((version & 0x0F0F0F0F) == 0x0a0a0a0a) {
		return 29;
	}

	/* QUIC (final?) constants for v1 are defined in draft-33 */
	if (version == 0x00000001) {
		return 33;
	}

	/* GQUIC Q046 */
	if ( version == 0x51303436) {
		return 46;
	}
	return 0;
}

// Function responsible for storing the userspace application id for LABPM_DNAT
// into the kernel space for communication
static int labnf_set_labpm_portid(struct sk_buff *skb, struct genl_info *info_recv){
	printk("GRY_DPI_KERN: labnf_set_labpm_portid: init done\n");
	write_lock_bh(&genl_rwlock);
	info = gry_safe_alloc(sizeof(struct genl_info));
	if(!info){
		printk("GRY_DPI_KERN: Failed to allocate genl_info, labnf_set_labpm_portid\n");
		write_unlock_bh(&genl_rwlock);
		return 0;
	}
	memset(info, 0, sizeof(struct genl_info));
	memcpy(info, info_recv, sizeof(struct genl_info));
	printk("GRY_DPI_KERN: allocated genl_info labnf_set_labpm_portid\n");
	write_unlock_bh(&genl_rwlock);
	return 0;
}

// Function responsible for storing the userspace application id for LABPM_UDP
// into the kernel space for communication
static int labnf_set_labpm_udp_portid(struct sk_buff *skb, struct genl_info *info_recv){
	printk(KERN_INFO "GRY_DPI_KERN: labnf_set_labpm_udp_portid: init done\n");
	write_lock_bh(&genl_rwlock);
	udp_info = gry_safe_alloc(sizeof(struct genl_info));
	if(!udp_info){
		printk(KERN_ERR "GRY_DPI_KERN: Failed to allocate genl_info, labnf_set_labpm_udp_portid\n");
		write_unlock_bh(&genl_rwlock);
		return 0;
	} 
	memset(udp_info, 0, sizeof(struct genl_info));
	memcpy(udp_info, info_recv, sizeof(struct genl_info));
	printk("GRY_DPI_KERN: allocated genl_info labnf_set_labpm_portid_udp\n");
	write_unlock_bh(&genl_rwlock);
	return 0;
}

#if 0
// Function responsible for storing the userspace application id for GRY_TC
// into the kernel space for communication
static int labnf_set_ra_portid(struct sk_buff *skb, struct genl_info *info_recv){
	printk("GRY_DPI_KERN: labnf_set_ra_portid: init done\n");
	write_lock_bh(&genl_rwlock);
	ra_info = gry_safe_alloc(sizeof(struct genl_info));
	if(!ra_info){
		printk("GRY_DPI_KERN: failed to allocate genl_info, labnf_set_ra_portid\n");
		write_unlock_bh(&genl_rwlock);
		return 0;
	}
	memset(ra_info, 0, sizeof(struct genl_info));
	memcpy(ra_info, info_recv, sizeof(struct genl_info));
	printk("GRY_DPI_KERN: allocated genl_info labnf_set_ra_portid\n");
	write_unlock_bh(&genl_rwlock);
	return 0;
}
#endif


// Function responsible for controlling the pause, unpause and bedtime status of received MAC addresses
static int labnf_set_inet_pause_unpause(struct sk_buff *skb, struct genl_info *info_recv){
	struct nlattr *na;
	unsigned char mac[6] = {0};
	redirect_ *peer = NULL;
	int key1 = 0;
	int attr = 0;
	bool pexists = false;
	char buff[30] = {0};
	u32 bkt;
	int attr_len = 0;
	int scan_ret_val = 0;
	if(info_recv->attrs[LABPM_ATTR_INET_PAUSE] != NULL){
		na = info_recv->attrs[LABPM_ATTR_INET_PAUSE];
		attr_len = nla_len(na);
		if(attr_len >= sizeof(buff)){
			attr_len = sizeof(buff) - 1;
		}
		nla_memcpy(buff, na, attr_len);
		buff[attr_len] = '\0';
		scan_ret_val = sscanf(buff, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		attr = LABPM_ATTR_INET_PAUSE;
	} else if(info_recv->attrs[LABPM_ATTR_INET_UNPAUSE] != NULL){
		na = info_recv->attrs[LABPM_ATTR_INET_UNPAUSE];
		attr_len = nla_len(na);
		if(attr_len >= sizeof(buff)) {
			attr_len = sizeof(buff) - 1;
		}
		nla_memcpy(buff, na, attr_len);
		buff[attr_len] = '\0';
		scan_ret_val = sscanf(buff, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		attr = LABPM_ATTR_INET_UNPAUSE;
	} else if(info_recv->attrs[LABPM_ATTR_INET_BEDTIME_PAUSE] != NULL){
		na = info_recv->attrs[LABPM_ATTR_INET_BEDTIME_PAUSE];
		attr_len = nla_len(na);
		if(attr_len >= sizeof(buff)){
			attr_len = sizeof(buff) - 1;
		}
		nla_memcpy(buff, na, attr_len);
		buff[attr_len] = '\0';
		scan_ret_val = sscanf(buff, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		attr = LABPM_ATTR_INET_BEDTIME_PAUSE;
	} else {
		return 0;
	}
	if(scan_ret_val != 6){
		pr_err("GRY_DPI_KERN: incorrect MAC received: [%d]", scan_ret_val);
		return 0;
	}
	key1 = HASH_MAC(mac);
	spin_lock_bh(&labnf_redirect_lock);
	hash_for_each(labnf_redirect_hash, bkt, peer, hnode){
		if(memcmp(mac, peer->mac, ETH_ALEN) == 0){
			pexists = true;
			if(attr == LABPM_ATTR_INET_UNPAUSE){
				peer->inet_pause = 0;
				peer->inet_bedtime_music_allowed = 0;
			} else if(attr == LABPM_ATTR_INET_BEDTIME_PAUSE) {
				peer->inet_pause = 1;
				peer->inet_bedtime_music_allowed = 1;
			} else {
				peer->inet_pause = 1;
				peer->inet_bedtime_music_allowed = 0;
			}
		}
	}
	spin_unlock_bh(&labnf_redirect_lock);

	if(pexists == true){
		return 0;
	}
	if(attr == LABPM_ATTR_INET_PAUSE || attr == LABPM_ATTR_INET_BEDTIME_PAUSE){
		peer = gry_safe_alloc(sizeof(redirect_));
		if(peer == NULL){
			printk("GRY_DPI_KERN: Failed to allocate memory: LABPM_ATTR_INET_PAUSE, LABPM_ATTR_INET_BEDTIME_PAUSE\n");
			return 0;
		}
		memset(peer, 0, sizeof(redirect_));
		memcpy(peer->mac, mac, ETH_ALEN);
		peer->inet_pause = 1;
		if(attr == LABPM_ATTR_INET_BEDTIME_PAUSE){
			peer->inet_bedtime_music_allowed = 1;
		} else {
			peer->inet_bedtime_music_allowed = 0;
		}
		spin_lock_bh(&labnf_redirect_lock);
		hash_add(labnf_redirect_hash, &peer->hnode, key1);
		spin_unlock_bh(&labnf_redirect_lock);
	}
	return 0;
}

static int labnf_flush_table(struct sk_buff *skb, struct genl_info *info_rcv) {
	safe_mac_ip_ *peer;
	u32 bkt;
	struct hlist_node *tmp;
	struct hlist_node *tmp1;
	//if (info_rcv->attrs[LABPM_ATTR_UNSAFE_IP] != NULL) {
		spin_lock_bh(&labnf_unsafe_ip_lock);
		hash_for_each_safe(labnf_unsafe_ip_hash, bkt, tmp, peer, hnode){
				hash_del(&peer->hnode);
				kfree(peer);
		}
		spin_unlock_bh(&labnf_unsafe_ip_lock);
		
		spin_lock_bh(&labnf_unsafe_youtube_ip_lock);
		hash_for_each_safe(labnf_unsafe_youtube_ip_hash, bkt, tmp1, peer, hnode){
				hash_del(&peer->hnode);
				kfree(peer);
		}
		spin_unlock_bh(&labnf_unsafe_youtube_ip_lock);
		
	//}
	return 0;    
}

// Function responsible for clearing up the userspace application id - LABPM_DNAT
static int labnf_reset_labpm_portid(struct sk_buff *skb, struct genl_info *info_recv){
	write_lock_bh(&genl_rwlock);
	if(info != NULL){
		kfree(info);
		info = NULL;
		printk("GRY_DPI_KERN: nl_close_done\n");
	}
	if(udp_info != NULL){
		kfree(udp_info);
		udp_info = NULL;
		printk(KERN_INFO "GRY_DPI_KERN: nl_close_done udp\n");
	}
	write_unlock_bh(&genl_rwlock);
	return 0;
}

#if 0
// Function responsible for clearing up the userspace application id - GRY_TC
static int labnf_reset_ra_portid(struct sk_buff *skb, struct genl_info *info_recv){
	write_lock_bh(&genl_rwlock);
	if(ra_info != NULL){
		kfree(ra_info);
		printk("GRY_DPI_KERN: nl_close_done ra_info\n");
	}
	write_unlock_bh(&genl_rwlock);
	return 0;
}
#endif

// Function responsible for handling safesearch ips
static int labnf_allow_safesearch_ip(struct sk_buff *skb, struct genl_info *info_recv){
	struct nlattr *na = info_recv->attrs[1];
	char iplist[128] = {0};
	if(!info_recv->attrs[LABPM_ATTR_DNAT]){
		printk("GRY_DPI_KERN: failed allow_safesearch_ip\n");
		return -EINVAL;
	}
	nla_memcpy(iplist, na, 128);
	if(strlen(iplist) <= 0){
		printk("GRY_DPI_KERN: failed allow_safesearch_ip: no ips\n");
		return -EINVAL;
	}
	write_lock_bh(&ss_rwlock);

	sscanf(iplist, "%x,%x,%x,%x,%x",&safesearchIps[0],&safesearchIps[1],&safesearchIps[2],&safesearchIps[3],&safesearchIps[4]);
	safesearchCount = 5;
	write_unlock_bh(&ss_rwlock);
	return 0;
}

// Function responsible for adding or removing the mac address to safe search list
static int labnf_add_del_mac_to_safe_list(struct sk_buff *skb, struct genl_info *info_recv){
	struct nlattr *na = info_recv->attrs[LABPM_ATTR_DNAT];
	char rule[32] = {0};
	unsigned char mac[6] = {0};
	unsigned int action;
	safe_mac_ip_ *peer;
	int key;
	u32 bkt;
	struct hlist_node *tmp;

	if(!info_recv->attrs[LABPM_ATTR_DNAT]){
		printk("GRY_DPI_KERN: add_del_mac_to_safe_list: error\n");
		return -EINVAL;
	}
	
	nla_memcpy(rule, na, 32);
	sscanf(rule, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %u", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5], &action);
	key = HASH_MAC(mac);
	spin_lock_bh(&labnf_safe_mac_lock);
	if(action == ADD_RULE){
		hash_for_each(labnf_safe_mac_hash, bkt, peer, hnode){
			if(memcmp(mac, peer->mac, ETH_ALEN) == 0){
				spin_unlock_bh(&labnf_safe_mac_lock);
				return 0;
			}
		}
	} else if(action == RM_RULE){
		hash_for_each_safe(labnf_safe_mac_hash, bkt, tmp, peer, hnode){
			if(memcmp(mac, peer->mac, ETH_ALEN) == 0){
				hash_del(&peer->hnode);
				kfree(peer);
				spin_unlock_bh(&labnf_safe_mac_lock);
				return 0;
			}
		}
	} else {
		spin_unlock_bh(&labnf_safe_mac_lock);
		return 0;
	}
	spin_unlock_bh(&labnf_safe_mac_lock);

	peer = gry_safe_alloc(sizeof(safe_mac_ip_));
	if(!peer){
		return -ENOMEM;
	}
	memset(peer, 0, sizeof(safe_mac_ip_));
	memcpy(peer->mac, mac, 6);

	spin_lock_bh(&labnf_safe_mac_lock);
	hash_add(labnf_safe_mac_hash, &peer->hnode, key);
	spin_unlock_bh(&labnf_safe_mac_lock);
	return 0;
}

// Function responsible for adding ip address to unsafe ip list
static int labnf_add_ip_to_unsafe_list(struct sk_buff *skb, struct genl_info *info_recv){
	struct nlattr *na = info_recv->attrs[LABPM_ATTR_DNAT];
	char rule[32] = {0};
	safe_mac_ip_ *peer;
	int key;
	uint32_t unsafe_ip;
	int a,b,c,d;
	u32 bkt;
	if(!info_recv->attrs[LABPM_ATTR_DNAT]){
		printk("GRY_DPI_KERN: error labnf_add_ip_to_unsafe_list\n");
		return -EINVAL;
	}
	nla_memcpy(rule, na, 32);
	sscanf(rule, "%d.%d.%d.%d", &a, &b, &c, &d);
	unsafe_ip = htonl(a << 24 | b << 16 | c << 8 | d);
	key = HASH(unsafe_ip);

	spin_lock_bh(&labnf_unsafe_ip_lock);
	hash_for_each(labnf_unsafe_ip_hash, bkt, peer, hnode){
		if(peer->unsafe_ip == unsafe_ip){
			spin_unlock_bh(&labnf_unsafe_ip_lock);
			return 0;
		}
	}
	spin_unlock_bh(&labnf_unsafe_ip_lock);
	
	peer = gry_safe_alloc(sizeof(safe_mac_ip_));
	if(peer == NULL){
		return -ENOMEM;
	}
	memset(peer, 0, sizeof(safe_mac_ip_));
	peer->unsafe_ip = unsafe_ip;

	spin_lock_bh(&labnf_unsafe_ip_lock);
	hash_add(labnf_unsafe_ip_hash, &peer->hnode, key);
	spin_unlock_bh(&labnf_unsafe_ip_lock);
	return 0;
}

// Function responsible for adding ip address to apc list
static int labnf_add_ip_to_apc_list(struct sk_buff *skb, struct genl_info *info_rcv){
	struct nlattr *na = info_rcv->attrs[1];
	char rule[32] = {0};
	unsigned int apc[4] = {0};
	apc_ip_ *peer;
	int key;
	int apc_ip;
	u32 bkt;

	if(!info_rcv->attrs[1]) {
		printk("GRY_DPI_KERN: labnf_add_ip_to_apc_list: no attribute\n");
		return -EINVAL;
	}

	nla_memcpy(rule, na, 32);

	sscanf(rule, "%d.%d.%d.%d",&apc[3], &apc[2], &apc[1], &apc[0]);

	apc_ip = (apc[0] << 24) | (apc[1] << 16) | (apc[2] << 8) | apc[3];
	key = HASH(apc_ip);

	spin_lock_bh(&labnf_apc_ip_lock);
	hash_for_each(labnf_apc_ip_hash, bkt, peer, hnode){
		if (peer->apc_ip == apc_ip) {
			spin_unlock_bh(&labnf_apc_ip_lock);
			return 0;
		}
	}
	spin_unlock_bh(&labnf_apc_ip_lock);

	peer = gry_safe_alloc(sizeof(apc_ip_));
	if(peer == NULL)
		return -ENOMEM;
	memset(peer, 0, sizeof(apc_ip_));
	peer->apc_ip = apc_ip;

	spin_lock_bh(&labnf_apc_ip_lock);
	hash_add(labnf_apc_ip_hash, &peer->hnode, key);
	spin_unlock_bh(&labnf_apc_ip_lock);
	return 0;
}

static int labnf_add_del_mac_to_apc_list(struct sk_buff *skb, struct genl_info *info_rcv)
{
	struct nlattr *na = info_rcv->attrs[1];
	char rule[32] = {0};
	unsigned char mac[6] = {0};
	unsigned int action;
	apc_mac_ip_ *peer;
	int key;
	u32 bkt;
	struct hlist_node *tmp;

	if(!info_rcv->attrs[1]) {
		printk("GRY_DPI_KERN: add_del_to_apc_list: no attribute\n");
		return -EINVAL;
	}

	nla_memcpy(rule, na, 32);

	sscanf(rule, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %u", &mac[0], &mac[1],&mac[2], &mac[3], &mac[4], &mac[5], &action);

	key = HASH_MAC(mac);
	spin_lock_bh(&labnf_apc_mac_lock);
	if(action == ADD_RULE) {
		hash_for_each(labnf_apc_mac_hash, bkt, peer, hnode){
			if (memcmp(mac, peer->mac, ETH_ALEN) == 0) {
				spin_unlock_bh(&labnf_apc_mac_lock);
				return 0;
			}
		}

	} else if(action == RM_RULE) {
		hash_for_each_safe(labnf_apc_mac_hash, bkt, tmp, peer, hnode){
			if (memcmp(mac, peer->mac, ETH_ALEN) == 0) {
				hash_del(&peer->hnode);
				kfree(peer);
				spin_unlock_bh(&labnf_apc_mac_lock);
				return 0;
			}
		}
		spin_unlock_bh(&labnf_apc_mac_lock);
		return 0;

	} else {

		spin_unlock_bh(&labnf_apc_mac_lock);
		return 0;
	}

	spin_unlock_bh(&labnf_apc_mac_lock);

	peer = gry_safe_alloc(sizeof(apc_mac_ip_));
	if(peer == NULL)
		return -ENOMEM;
	memset(peer, 0, sizeof(apc_mac_ip_));
	memcpy(peer->mac, mac, 6);

	spin_lock_bh(&labnf_apc_mac_lock);
	hash_add(labnf_apc_mac_hash, &peer->hnode, key);
	spin_unlock_bh(&labnf_apc_mac_lock);
	return 0;
}

static int add_mip_into_hash(int ipaddr){

	int key = HASH(ipaddr);
	musical_ip_ *peer=NULL;

	peer = gry_safe_alloc(sizeof(musical_ip_));
	if(peer == NULL)
		return -ENOMEM;
	memset(peer, 0, sizeof(musical_ip_));
	peer->music_ip = ipaddr;
	spin_lock_bh(&labnf_music_ip_lock);
	hash_add(labnf_music_ip_hash, &peer->hnode, key);
	spin_unlock_bh(&labnf_music_ip_lock);
	return 0;
}

static int labnf_add_music_ip_list(struct sk_buff *skb, struct genl_info *info_rcv){
	bool ip_preset=false;
	struct musicappiplist_t musicappiplist = {0};
	struct nlattr *na = NULL;
	int key = 0;
	u32 bkt;
	int i = 0;
	int recv_len = 0;
	musical_ip_ *mpeer=NULL;

	if(!info_rcv->attrs[LABPM_ATTR_MUSIC_IP]) {
		return -EINVAL;
	}		
	recv_len = nla_len(info_rcv->attrs[LABPM_ATTR_MUSIC_IP]);
	if(recv_len != sizeof(struct musicappiplist_t)){
		printk("set music ip list failed: incorrect length\n");
		return 0;
	}

	na = info_rcv->attrs[LABPM_ATTR_MUSIC_IP];
	nla_memcpy(&musicappiplist, na, recv_len);

	for(i=0; i < musicappiplist.ipcount; i++){
		key = HASH(musicappiplist.ipaddr[i]);
		spin_lock_bh(&labnf_music_ip_lock);
		hash_for_each(labnf_music_ip_hash, bkt, mpeer, hnode){   
			if (mpeer->music_ip == musicappiplist.ipaddr[i]) {
				ip_preset=true;
			}
		}
		spin_unlock_bh(&labnf_music_ip_lock);	
		if(!ip_preset)
			add_mip_into_hash(musicappiplist.ipaddr[i]);	
	}
	return 0;
}

static int labnf_peer_inet_paused(char *mac, int ipaddr, int port){
	redirect_ *peer;
	u32 bkt;

	spin_lock_bh(&labnf_redirect_lock);
	hash_for_each(labnf_redirect_hash, bkt, peer, hnode){
		if(memcmp(peer->mac, mac, ETH_ALEN) == 0){
			if(peer->inet_pause == 1){
				if(peer->inet_bedtime_music_allowed == 0){
					// 0 - not allowed, 1 allowed
					spin_unlock_bh(&labnf_redirect_lock);
					return PAUSED;
				} else {
					musical_ip_ *mpeer;
					u32 musicBkt;
					spin_lock_bh(&labnf_music_ip_lock);
					hash_for_each(labnf_music_ip_hash, musicBkt, mpeer, hnode){
						if(mpeer->music_ip == ipaddr){
							spin_unlock_bh(&labnf_music_ip_lock);
							spin_unlock_bh(&labnf_redirect_lock);
							return UNPAUSED;
						}
					}

					if(port == 4070){
						spin_unlock_bh(&labnf_music_ip_lock);
						spin_unlock_bh(&labnf_redirect_lock);
						return UNPAUSED;
					}
					spin_unlock_bh(&labnf_music_ip_lock);
					spin_unlock_bh(&labnf_redirect_lock);
					return PAUSED;
				}
			}
		}
	}
	spin_unlock_bh(&labnf_redirect_lock);
	return UNPAUSED;
}

// packet processing functions
static int is_handshake_packet(struct tcphdr *tcph){
	if(tcph->urg == 0 && tcph->ack == 0 && tcph->psh == 0 && tcph->rst == 0 && tcph->syn == 1 && tcph->fin == 0){
		// syn packet
		return 1;
	}
	else if(tcph->urg == 0 && tcph->ack == 0 && tcph->psh == 0 && tcph->rst == 0 && tcph->syn == 0 && tcph->fin == 1){
		// fin packet
		return 1;
	}
	else if(tcph->urg == 0 && tcph->ack == 0 && tcph->psh == 0 && tcph->rst == 1 && tcph->syn == 0 && tcph->fin == 0){
		// reset packet
		return 1;
	}
	else if(tcph->urg == 0 && tcph->ack == 1 && tcph->psh == 0){
		// ack or syn/ack packet
		return 1;
	}
	return 0;
}

static int can_send_tcp_to_labrador(struct tcphdr *tcph, uint16_t dest_port, char *data, int len){
	if(dest_port == 80 && !memcmp(data, HTTP_GET, HTTP_GET_LEN)){
		// HTTP GET
		return 1;
	}
	else if(data[0] == 0x16 && data[5] == 0x01){
		if(dest_port == 443){
			// HTTPS CLIENT HELLO
			if(len < 1100)
				return 1;
			return 2;
		} else if(dest_port == 5228) {
			// CLIENT HELLO on Google Play Services
			return 2;
		} else if(dest_port == 5223 || dest_port == 5222 || dest_port == 5280 || dest_port == 5281 || dest_port == 5298){
			// XMPP SSL Kik app
			return 2;
		}
	} else if ((tcph->psh == 1) && (((data[0] == 0x45) && (data[1] == 0x44) && (data[2] == 0x00) && (data[3] == 0x01)) ||
				((data[0] == 0x00) && (data[1] == 0x00) && (data[2] == 0x04) && (data[3] == 0x08)) ||
				((data[0] == 0x50) && (data[1] == 0x4f) && (data[2] == 0x53) && (data[3] == 0x54) && (data[4] == 0x20) && (data[5] == 0x2f)))){
			// Whatsapp messages
			return 1;
	} else if(dest_port == 443 && data[0] == 0x14){
		int oth_len = LEN_NTOHS(data);
		data += TLS_TYPE_VER_LEN;
		if(len < oth_len){
			return 0;
		}
		data += 2;
		data += oth_len;
		if(data[0] == 0x16 && data[5] == 0x01){
			// Client hello in https
			if(len < 1100)
				return 1;
			return 2;
		}
	}
	return 0;
}

static inline int add_ip_to_unsafe_youtube_list(struct sk_buff *skb, struct genl_info *info_rcv)
{

	struct nlattr *na = info_rcv->attrs[LABPM_ATTR_DNAT];

	char rule[32] = {0};
	unsigned int ip_str[4] = {0};
	safe_mac_ip_ *peer;
	int key;
	int unsafe_youtube_ip=0;
	u32 bkt;

	if(info_rcv == NULL) {
		return -EINVAL;
	}

	if(!na) {
		return -EINVAL;
	}

	nla_memcpy(rule, na, 32);
	sscanf(rule, "%d.%d.%d.%d",&ip_str[3], &ip_str[2], &ip_str[1], &ip_str[0]);
	unsafe_youtube_ip = (ip_str[0] << 24) | (ip_str[1] << 16) | (ip_str[2] << 8) | ip_str[3];
	key = HASH(unsafe_youtube_ip);
	spin_lock_bh(&labnf_unsafe_youtube_ip_lock);
	hash_for_each(labnf_unsafe_youtube_ip_hash, bkt, peer, hnode){
		if (peer->unsafe_ip == unsafe_youtube_ip) {
			spin_unlock_bh(&labnf_unsafe_youtube_ip_lock);
			return 0;
		}
	}
	spin_unlock_bh(&labnf_unsafe_youtube_ip_lock);

	peer = gry_safe_alloc(sizeof(safe_mac_ip_));
	if(peer == NULL)
		return -ENOMEM;
	memset(peer, 0, sizeof(safe_mac_ip_));
	peer->unsafe_ip = unsafe_youtube_ip;

	spin_lock_bh(&labnf_unsafe_youtube_ip_lock);
	hash_add(labnf_unsafe_youtube_ip_hash, &peer->hnode, key);
	spin_unlock_bh(&labnf_unsafe_youtube_ip_lock);

	return 0;
}

static int labnf_is_unsafe_ip(uint32_t unsafe_ip)
{
	safe_mac_ip_ *peer;
	u32 bkt;

	spin_lock_bh(&labnf_unsafe_ip_lock);
	hash_for_each(labnf_unsafe_ip_hash, bkt, peer, hnode){
		if(peer->unsafe_ip == unsafe_ip){
			spin_unlock_bh(&labnf_unsafe_ip_lock);
			return 1;
		}
	}
	spin_unlock_bh(&labnf_unsafe_ip_lock);
	return 0;
}

static inline int labnf_is_unsafe_youtube_ip(int unsafe_youtube_ip)
{
        safe_mac_ip_ *peer;
        u32 bkt;

        spin_lock_bh(&labnf_unsafe_youtube_ip_lock);
        hash_for_each(labnf_unsafe_youtube_ip_hash, bkt, peer, hnode){
                if(peer->unsafe_ip == unsafe_youtube_ip){
                        spin_unlock_bh(&labnf_unsafe_youtube_ip_lock);
                        return 1;
                }
        }
        spin_unlock_bh(&labnf_unsafe_youtube_ip_lock);
        return 0;
}

static inline int add_del_mac_to_safe_youtube_list(struct sk_buff *skb, struct genl_info *info_rcv)
{
	struct nlattr *na = info_rcv->attrs[LABPM_ATTR_DNAT];
	char rule[32] = {0};
	unsigned char mac[6] = {0};
	unsigned int action;
	safe_mac_ip_ *peer;
	int key;
	u32 bkt;
	struct hlist_node *tmp;

	if(!info_rcv->attrs[LABPM_ATTR_DNAT]) {
		printk("no attribute\n");
		return -EINVAL;
	}

	nla_memcpy(rule, na, 32);

	sscanf(rule, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %u", &mac[0], &mac[1],&mac[2], &mac[3], &mac[4], &mac[5], &action);

	key = HASH_MAC(mac);
	spin_lock_bh(&labnf_safe_youtube_mac_lock);
	if(action == ADD_RULE) {
		hash_for_each(labnf_safe_youtube_mac_hash, bkt, peer, hnode){
			if (memcmp(mac, peer->mac, ETH_ALEN) == 0) {
				spin_unlock_bh(&labnf_safe_youtube_mac_lock);
				return 0;
			}
		}

	} else if(action == RM_RULE) {
		hash_for_each_safe(labnf_safe_youtube_mac_hash, bkt, tmp, peer, hnode){
			if (memcmp(mac, peer->mac, ETH_ALEN) == 0) {
				hash_del(&peer->hnode);
				kfree(peer);
				spin_unlock_bh(&labnf_safe_youtube_mac_lock);
				return 0;
			}
		}
		spin_unlock_bh(&labnf_safe_youtube_mac_lock);
		return 0;
	} else {

		spin_unlock_bh(&labnf_safe_youtube_mac_lock);
		return 0;
	}
	spin_unlock_bh(&labnf_safe_youtube_mac_lock);

	peer = gry_safe_alloc(sizeof(safe_mac_ip_));
	if(peer == NULL)
		return -ENOMEM;
	memset(peer, 0, sizeof(safe_mac_ip_));
	memcpy(peer->mac, mac, 6);

	spin_lock_bh(&labnf_safe_youtube_mac_lock);
	hash_add(labnf_safe_youtube_mac_hash, &peer->hnode, key);
	spin_unlock_bh(&labnf_safe_youtube_mac_lock);
	return 0;
}

static int labnf_is_safe_mac(char *mac)
{
	safe_mac_ip_ *peer;
	u32 bkt;
	spin_lock_bh(&labnf_safe_mac_lock);
	hash_for_each(labnf_safe_mac_hash, bkt, peer, hnode){
		if (memcmp(mac, peer->mac, ETH_ALEN) == 0){
			spin_unlock_bh(&labnf_safe_mac_lock);
			return 1;
		}
	}
	spin_unlock_bh(&labnf_safe_mac_lock);
	return 0;
}


static inline int labnf_is_safe_youtube_mac(char *mac) {

        safe_mac_ip_ *peer;
        u32 bkt;
        // First
        spin_lock_bh(&labnf_safe_youtube_mac_lock);
        hash_for_each(labnf_safe_youtube_mac_hash, bkt, peer, hnode){
                if (memcmp(mac, peer->mac, ETH_ALEN) == 0){
                        spin_unlock_bh(&labnf_safe_youtube_mac_lock);
                        return 1;
                }
        }
        spin_unlock_bh(&labnf_safe_youtube_mac_lock);
        return 0;
}

// NETLINK MSG ATTRIBUTES FOR SENDING THE PACKET INFORMATION TO APPLICATION LAYER
// THIS IS FOR DYNAMIC MTU SIZES
#define LABNF_PACKET_LEN 1
#define LABNF_IFNAME 2
#define LABNF_GSOLENGTH 3
#define LABNF_BUFFER 4

static int labnf_send_packet(struct sk_buff *skb, int len, char *dev_name, unsigned int gso_length, uint8_t protocol){
	struct sk_buff *msg;
	void *hdr;
	struct genl_info temp_info = {0};
	int cmd = LABPM_CMD_PACKET;
	int result = 0;
	write_lock_bh(&genl_rwlock);
	if(info == NULL){
		write_unlock_bh(&genl_rwlock);
		return -1;
	}
	if(protocol == IPPROTO_TCP){
		// info variable is the TCP genl_info using LABPM_DNAT
		memcpy(&temp_info, info, sizeof(struct genl_info));
	} else if(protocol == IPPROTO_UDP){
		// udp_info variable is the UDP genl_info using LABPM_UDP
		memcpy(&temp_info, udp_info, sizeof(struct genl_info));
	} else {
		// Incorrect protocol
		printk(KERN_ERR "GRY_DPI_KERN: labnf_send_packet: protocol error\n");
		write_unlock_bh(&genl_rwlock);
		return -1;
	}
	write_unlock_bh(&genl_rwlock);

	msg = nlmsg_new(NLMSG_GOODSIZE, gry_get_memory_alloc_type());
	if(!msg){
		return -1;
	}

	hdr = genlmsg_put(msg, temp_info.snd_portid, 0, &labpm_genl_family, 0, cmd);
	if(!hdr){
		nlmsg_free(msg);
		return -1;
	}

#if 0
	// Add the packet length from sk_buff
	if(nla_put_u32(msg, LABNF_PACKET_LEN, len)){
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -1;
	}
#endif
	
	// Add the interface name from sk_buff
	if(nla_put_string(msg, LABNF_IFNAME, dev_name)){
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -1;
	}

	// Add the gso_length parameter from sk_buff
	if(nla_put_u32(msg, LABNF_GSOLENGTH, gso_length)){
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -1;
	}
	
	// Add the packet buffer in binary format
	if(nla_put(msg, LABNF_BUFFER, len, skb->head + skb->mac_header)){
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -1;
	}
	//printk(KERN_INFO "GRY_LABNF_KERN: pack_length: %d, gso_length: %d\n", len, gso_length);

	genlmsg_end(msg, hdr);
	result = genlmsg_unicast(genl_info_net(&temp_info), msg, temp_info.snd_portid);
	if(result == -EAGAIN){
		return -1;
	}
	return 0;
}

static unsigned int gry_skb_gso_network_seglen(struct sk_buff *skb){
	const struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int hdr_len = 0;
	unsigned int thlen = 0;

       	hdr_len = skb_transport_header(skb) - skb_network_header(skb);

	if(skb->encapsulation){
		thlen = skb_inner_transport_header(skb) - skb_transport_header(skb);
		if (likely(shinfo->gso_type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6)))
			thlen += inner_tcp_hdrlen(skb);
	} 
	else if(likely(shinfo->gso_type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6))){
		thlen = tcp_hdrlen(skb);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	else if (unlikely(skb_is_gso_sctp(skb))) {
		thlen = sizeof(struct sctphdr);
	}
	else if (shinfo->gso_type & SKB_GSO_UDP_L4) {
		thlen = sizeof(struct udphdr);
	}
#endif
	return hdr_len + thlen + shinfo->gso_size;
}

static void labnf_parse_history(struct sk_buff *skb, uint8_t protocol){
	int pack_len = 0;
	struct iphdr *iph;
	iph = (struct iphdr*)skb_network_header(skb);
	pack_len = ntohs(iph->tot_len) + ETH_HLEN;

	if(protocol == IPPROTO_TCP && skb_is_gso(skb) == 1){
		// call GSO functions only if the protocol is TCP
		if(labnf_send_packet(skb, pack_len, skb->dev->name, gry_skb_gso_network_seglen(skb), protocol) < 0){
			if(labnf_send_packet(skb, pack_len, skb->dev->name, gry_skb_gso_network_seglen(skb), protocol) < 0){
				//printk(KERN_ERR "NETLINK_ERROR_RE_TX: [%u]\n", protocol);
			}
		}
	} else {
		// GSO functions are ignored in UDP Protocol or non GSO packets
		if(labnf_send_packet(skb, pack_len, skb->dev->name, 0, protocol) < 0){
			if(labnf_send_packet(skb, pack_len, skb->dev->name, 0, protocol) < 0){
				//printk(KERN_ERR "NETLINK_ERROR_RE_TX: [%u]\n", protocol);
			}
		}
	}

}

int can_send_udp_to_labrador(unsigned char *data,int len)
{
	/* We work on UDP only QUIC/GQUIC
	 * Have checks to verify if it is quic, then only pass it to labrador.
	 */
	u8 flags,long_packet_type;
	u32 version;

	if(len < 14) {
		return 0;
	}

	flags = data[0];
	long_packet_type = (flags & 0x30) >> 4;


	/* Check if long Packet is set */
	if((flags & PUFLAGS_RSV) == 0) {

		/* Could be GQUIC, check it. */
		if(flags & PUFLAGS_MPTH) {
			return 0;
		}

		/* Check if flags version is set */
		if((flags & PUFLAGS_VRSN) == 0) {
			return 0;
		}

		/* Connection ID is always set to "long" (8bytes) too */
		if((flags & PUFLAGS_CID) == 0){
			return 0;
		}

		/* Verify packet size  (Flag (1 byte) + Connection ID (8 bytes) + Version (4 bytes)) */
		version = pntoh24(data+9); /* Skip Flag (1 byte) + Dest Connection ID (8 bytes)) */
		if ( version == GQUIC_MAGIC2 || version == GQUIC_MAGIC3 || version == GQUIC_MAGIC4) {
			return 1;
		}

	} else {
		/* Could be QUIC long header */
		/* Verify packet size  (Flag (1 byte) + Version (4) + DCIL/SCIL (1) + Dest Connection ID (8 bytes)) */
		version = pntoh32(data+1);
		/* Check if the version is a QUIC version */
		if(quic_draft_version(version) == 46) {
			return 1;
		} else if(quic_draft_version(version) >= 11) {
                        /*Check if it is initial/ORTT/Handshake packet */
                        if((long_packet_type == QUIC_LPT_INITIAL) || (long_packet_type == QUIC_LPT_0RTT) || 
				( long_packet_type == QUIC_LPT_HANDSHAKE) || (long_packet_type == QUIC_LPT_RETRY)) {
				return 1;
			 }
		}
	}
  	return 0;
}

int isAUS(unsigned char *data,int len) {
	if((data[0] == 0x08) && (data[1]==0x00) && (data[2]==0x00) && (data[3]==0x00)){
		return 1;
	}
	return 0;
}


int isStunFram(unsigned char *stun,int captured_length) {

	unsigned short int msg_type =0;
	unsigned short int msg_len =0;
	if (captured_length < MIN_HDR_LEN) {
		return 0;
	}
	GET_SHORT_INT(msg_type,stun);
	GET_SHORT_INT(msg_len,stun+2);

	if(msg_len>captured_length) {
		return 0;
	}
	/* Normal STUN message */
	if (captured_length < STUN_HDR_LEN)
		return 0;

	if(memcmp(stun+4, STUN_ID, STUN_ID_LEN) != 0) { // stun Request
		return 0;
	}
	return 1;
}

#if PORTSCAN_ENABLED
static unsigned int gry_portscan_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	struct ethhdr *eth_h = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	int i = 0;
	bool s_valid = false;
	//bool d_valid = false;
	unsigned long saddr_h = 0;
	//unsigned long daddr_h = 0;

	if(!skb){
		return NF_ACCEPT;
	}
	// extract eth header
	eth_h = eth_hdr(skb);
	if(!eth_h)
		return NF_ACCEPT;

	// Process IPv4
	if(ntohs(eth_h->h_proto) == ETH_P_IP){
		// extract ipv4 header
		iph = (struct iphdr*)skb_network_header(skb);
		if(iph){
			//check for multicast addresses to ignore checking
			if( (iph->daddr >> 28)  == MULTICAST_PREFIX){
				return NF_ACCEPT;
			} else {
				if(iph->protocol == IPPROTO_TCP){
					saddr_h = ntohl(iph->saddr);
					//daddr_h = ntohl(iph->daddr);
					s_valid = (CLASS_A_START <= saddr_h && saddr_h < CLASS_A_END) ||
						       (CLASS_B_START <= saddr_h && saddr_h < CLASS_B_END) || 
						       (CLASS_C_START <= saddr_h && saddr_h < CLASS_C_END);

					if(s_valid) {
						// TCP packet
						tcph = (struct tcphdr*)((__u32*)iph + iph->ihl);
						if(tcph->syn){
							// only syn comparision for general detection
							// already checked that syn is enabled, then confirm other flags only
							if(!tcph->ack && !tcph->fin && !tcph->psh && !tcph->urg && !tcph->rst){
								for(i=0; i< sizeof(port_ignore)/sizeof(unsigned); i++){
									if(port_ignore[i] == htons(tcph->dest)){
										return NF_ACCEPT;
									}
								}
								spin_lock_bh(&gry_lock);
								add_tcp_normal_scan_to_store(eth_h->h_source, 6, htons(tcph->dest));
								spin_unlock_bh(&gry_lock);
							}

						} else {
							// not syn packet
							if(tcph->fin && tcph->urg && tcph->psh && !tcph->ack && !tcph->rst){
								// xmas signature checking
								spin_lock_bh(&gry_lock);
								add_tcp_special_scan_to_store(eth_h->h_source, 6);
								spin_unlock_bh(&gry_lock);
							} else if(!tcph->fin && !tcph->ack && !tcph->psh && !tcph->urg && !tcph->rst){
								// null signature checking
								spin_lock_bh(&gry_lock);
								add_tcp_special_scan_to_store(eth_h->h_source, 6);
								spin_unlock_bh(&gry_lock);
							}
						}
					}
				}
			}
		}
	}
	// If not ipv4 just send the packet
	return NF_ACCEPT;
}
#endif

static int is_apple_priv_ip_block_list(uint32_t sip, uint32_t dip){
	u32 bkt;
	apple_priv_ip_ *peer;

	spin_lock_bh(&labnf_apple_priv_lock);
	hash_for_each(labnf_apple_priv_hash, bkt, peer, hnode){
		if(peer->ipaddr == sip || peer->ipaddr == dip){
			spin_unlock_bh(&labnf_apple_priv_lock);
			return 1;
		}
	}
	spin_unlock_bh(&labnf_apple_priv_lock);
	return 0;
}

static int is_cloud_server_ip_allowed_list(uint32_t sip, uint32_t dip)
{
	u32 bkt;
	cloud_server_ip_ *peer;

	spin_lock_bh(&labnf_cloud_server_lock);
	hash_for_each(labnf_cloud_server_hash, bkt, peer, hnode){
		if(peer->ipaddr == sip || peer->ipaddr == dip){
			spin_unlock_bh(&labnf_cloud_server_lock);
			return 1;
		}
	}
	spin_unlock_bh(&labnf_cloud_server_lock);
	return 0;
}

static int cloud_server_allowed_list(struct sk_buff *skb, struct genl_info *info_recv)
{
	struct nlattr *na;
	uint32_t *ipaddr;
	if(!info_recv->attrs[LABPM_ATTR_CLOUD_SERVER]){
		printk(KERN_ERR "GRY_CLOUD_SERVER: invalid payload\n");
		return -1;
	}
	na = info_recv->attrs[LABPM_ATTR_CLOUD_SERVER];
	if(nla_len(na) != sizeof(uint32_t)){
		printk(KERN_ERR "GRY_CLOUD_SERVER: invalid size\n");
		return -1;
	}
	ipaddr = (uint32_t*)nla_data(na);
	{
		u32 bkt;
		cloud_server_ip_ *peer;
		//printk(KERN_INFO "GRY_CLOUD_SERVER: Recv: %u, %pI4\n", *ipaddr, ipaddr);
		spin_lock_bh(&labnf_cloud_server_lock);
		hash_for_each(labnf_cloud_server_hash, bkt, peer, hnode){
			if(peer->ipaddr == *ipaddr){
				spin_unlock_bh(&labnf_cloud_server_lock);
				return 0;
			}
		}
		spin_unlock_bh(&labnf_cloud_server_lock);

		peer = gry_safe_alloc(sizeof(cloud_server_ip_));
		if(peer == NULL)
			return -1;
		memset(peer, 0, sizeof(cloud_server_ip_));
		peer->ipaddr = *ipaddr;
		spin_lock_bh(&labnf_cloud_server_lock);
		hash_add(labnf_cloud_server_hash, &peer->hnode, *ipaddr);
		spin_unlock_bh(&labnf_cloud_server_lock);
	}
	return 0;
}

static int apple_priv_browse_block_list(struct sk_buff *skb, struct genl_info *info_recv){
	struct nlattr *na;
	uint32_t *ipaddr;
	if(!info_recv->attrs[LABPM_ATTR_APPLE_PRIV]){
		printk(KERN_ERR "GRY_APPLE_PRIV: invalid payload\n");
		return -1;
	}
	na = info_recv->attrs[LABPM_ATTR_APPLE_PRIV];
	if(nla_len(na) != sizeof(uint32_t)){
		printk(KERN_ERR "GRY_APPLE_PRIV: invalid size\n");
		return -1;
	}
	ipaddr = (uint32_t*)nla_data(na);
	{
		u32 bkt;
		apple_priv_ip_ *peer;
		//printk(KERN_INFO "GRY_APPLE_PRIV: Recv: %u, %pI4\n", *ipaddr, ipaddr);
		spin_lock_bh(&labnf_apple_priv_lock);
		hash_for_each(labnf_apple_priv_hash, bkt, peer, hnode){
			if(peer->ipaddr == *ipaddr){
				spin_unlock_bh(&labnf_apple_priv_lock);
				return 0;
			}
		}
		spin_unlock_bh(&labnf_apple_priv_lock);

		peer = gry_safe_alloc(sizeof(apple_priv_ip_));
		if(peer == NULL)
			return -1;
		memset(peer, 0, sizeof(apple_priv_ip_));
		peer->ipaddr = *ipaddr;
		spin_lock_bh(&labnf_apple_priv_lock);
		hash_add(labnf_apple_priv_hash, &peer->hnode, *ipaddr);
		spin_unlock_bh(&labnf_apple_priv_lock);
	}
	return 0;
}

static int is_apple_priv_browse_mac(char *mac){
	u32 bkt;
	apple_priv_mac_ *peer;
	spin_lock_bh(&labnf_apple_priv_lock);
	hash_for_each(labnf_apple_priv_mac_hash, bkt, peer, hnode){
		if(!memcmp(peer->data.mac, mac, ETH_ALEN)){
			spin_unlock_bh(&labnf_apple_priv_lock);
			return 1;
		}
	}
	spin_unlock_bh(&labnf_apple_priv_lock);
	return 0;
}

static int apple_priv_browse_mac_list(struct sk_buff *skb, struct genl_info *info_recv){
	struct nlattr *na;
	apple_priv_mac_t *apple_priv_mac;
	if(!info_recv->attrs[LABPM_ATTR_APPLE_PRIV_MAC]){
		printk(KERN_ERR "GRY_APPLE_PRIV: invalid LABPM_ATTR_APPLE_PRIV_MAC\n");
		return -1;
	}
	na = info_recv->attrs[LABPM_ATTR_APPLE_PRIV_MAC];
	if(nla_len(na) != sizeof(apple_priv_mac_t)){
		printk(KERN_ERR "GRY_APPLE_PRIV: invalid sizeof struct apple_priv_mac_\n");
		return -1;
	}
	apple_priv_mac = (apple_priv_mac_t*)nla_data(na);
	if(apple_priv_mac == NULL){
		printk(KERN_ERR "GRY_APPLE_PRIV: invalid data of struct apple_priv_mac\n");
		return -1;
	}
	//printk(KERN_INFO "GRY_APPLE_PRIV: MAC RECV: %pM6, %d\n", apple_priv_mac->mac, apple_priv_mac->action);
	if(apple_priv_mac->action == ADD_RULE){
		u32 bkt;
		apple_priv_mac_ *peer;
		spin_lock_bh(&labnf_apple_priv_lock);
		hash_for_each(labnf_apple_priv_mac_hash, bkt, peer, hnode){
			if(!memcmp(peer->data.mac, apple_priv_mac->mac, ETH_ALEN)){
				spin_unlock_bh(&labnf_apple_priv_lock);
				return 0;
			}
		}
		spin_unlock_bh(&labnf_apple_priv_lock);
		
		peer = (apple_priv_mac_*)gry_safe_alloc(sizeof(apple_priv_mac_));
		if(peer == NULL){
			printk(KERN_ERR "GRY_APPLE_PRIV: mac gry_safe_alloc failed\n");
			return -1;
		}
		memcpy(peer->data.mac, apple_priv_mac->mac, ETH_ALEN);
		spin_lock_bh(&labnf_apple_priv_lock);
		hash_add(labnf_apple_priv_mac_hash, &peer->hnode, HASH_MAC(peer->data.mac));
		spin_unlock_bh(&labnf_apple_priv_lock);
	} else if(apple_priv_mac->action == RM_RULE){
		u32 bkt;
		apple_priv_mac_ *peer;
		struct hlist_node *tmp;
		spin_lock_bh(&labnf_apple_priv_lock);
		hash_for_each_safe(labnf_apple_priv_mac_hash, bkt, tmp, peer, hnode){
			if(!memcmp(peer->data.mac, apple_priv_mac->mac, ETH_ALEN)){
				hash_del(&peer->hnode);
				kfree(peer);
				spin_unlock_bh(&labnf_apple_priv_lock);
				return 0;
			}
		}
		spin_unlock_bh(&labnf_apple_priv_lock);
	} else {
		printk(KERN_ERR "GRY_APPLE_PRIV: invalid action for apple_priv_mac\n");
		return -1;
	}
	return 0;
}

#if ENABLE_GRY_MARK
static void gry_mark_skb(struct sk_buff *skb){
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	ct = nf_ct_get(skb, &ctinfo);
	if(ct){
		ct->mark = GRY_MARK_VALUE;
	}
	skb->mark = GRY_MARK_VALUE;
}
#endif

static unsigned int gry_prerouting_packet_process_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	struct ethhdr *eth_h = NULL;
	struct iphdr *iph = NULL;
	int device_paused = 0;
	uint16_t src_port = 0;
	uint16_t dest_port = 0;
	char mac[ETH_ALEN] = {0};
	char *data = NULL;
	int idx = 0;
	int canSendResult = 0;
	int rabExists = 0;

	if(!skb)
		return NF_ACCEPT;

	// Application is not yet registered, so return without processing skb
	if(!info){
		return NF_ACCEPT;
	}

	// check the interface to listen
	if((skb->dev == NULL) || (strncmp(skb->dev->name, "br-", 3) != 0)){
#if ENABLE_GRY_MARK
		gry_mark_skb(skb);
#endif
		return NF_ACCEPT;
	}
	
	eth_h = eth_hdr(skb);
	if(!eth_h){
#if ENABLE_GRY_MARK
		gry_mark_skb(skb);
#endif
		return NF_ACCEPT;
	}

	memcpy(mac, eth_h->h_source, ETH_ALEN);

	iph = (struct iphdr*)skb_network_header(skb);
	if(!iph){
#if ENABLE_GRY_MARK
		gry_mark_skb(skb);
#endif
		return NF_ACCEPT;
	}

	if (iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP){
#if ENABLE_GRY_MARK
		gry_mark_skb(skb);
#endif
		return NF_ACCEPT;
	}

	if(CLIENT_IP(iph->daddr)){
#if ENABLE_GRY_MARK
		gry_mark_skb(skb);
#endif
		return NF_ACCEPT;
	}
	// If apple private mask ips, then drop the connections
	if(is_apple_priv_ip_block_list(iph->saddr, iph->daddr)){
		if(is_apple_priv_browse_mac(mac)){
			return NF_DROP;
		}
	}

	// If cloud server IP, then accept the connection.
	if(is_cloud_server_ip_allowed_list(iph->saddr, iph->daddr)){
#if ENABLE_GRY_MARK
		gry_mark_skb(skb);
#endif
		return NF_ACCEPT;
	}

	// clear the fragmented tuple memory
	memset(fragTuple, 0, sizeof(struct gry_fragment_tuple_t));
	
	// UDP Protocol
	if(iph->protocol == IPPROTO_UDP){
		struct udphdr *udph = NULL;
		int header = 0;

		if(udp_info == NULL){
#if ENABLE_GRY_MARK
			gry_mark_skb(skb);
#endif
			return NF_ACCEPT;
		}

		udph = (struct udphdr*)skb_transport_header(skb);
		header = iph->ihl * 4 + sizeof (struct udphdr);
		if(!udph){
#if ENABLE_GRY_MARK
			gry_mark_skb(skb);
#endif
			return NF_ACCEPT;
		}
		src_port = ntohs(udph->source);
		dest_port = ntohs(udph->dest);
		if(dest_port == 22 || dest_port == 53 || dest_port == 3000 || dest_port == 67 || dest_port == 123 || dest_port == 1900 || src_port == dest_port){
#if ENABLE_GRY_MARK
			gry_mark_skb(skb);
#endif
			return NF_ACCEPT;
		}

		// If the device is already paused 
		// NF_DROP all the packets
		device_paused = labnf_peer_inet_paused(mac, iph->daddr, dest_port);
		if(device_paused == PAUSED){
			return NF_DROP;
		}

		if(((ntohs(udph->dest) == 443) && (can_send_udp_to_labrador(skb->data + header, ntohs(udph->len))==1)) || (isStunFram(skb->data + header, ntohs(udph->len))==1) || (isAUS(skb->data + header, ntohs(udph->len))==1)){
			// check for safe ip
			read_lock_bh(&ss_rwlock);	
			for(idx=0;idx<safesearchCount;idx++) {
				if(iph->daddr==safesearchIps[idx]) {
					if(!device_paused){
						// if safe search ip and device is not paused
						read_unlock_bh(&ss_rwlock);
#if ENABLE_GRY_MARK
						gry_mark_skb(skb);
#endif
						return NF_ACCEPT;
					} else {
						read_unlock_bh(&ss_rwlock);
						return NF_DROP;
					}
				}
			}
			read_unlock_bh(&ss_rwlock);


			/* Check if it is a unsafe IP, and if mac is safe, allow */
			if(labnf_is_unsafe_ip(iph->daddr)) {
				if((strncmp(skb->dev->name, "homebound", strlen("homebound")) == 0)){ // homebound allow
#if ENABLE_GRY_MARK
					gry_mark_skb(skb);
#endif
					return NF_ACCEPT;
				}

				if(labnf_is_safe_mac(mac)) { // Allow if safe mac packet directly without sending lab
#if ENABLE_GRY_MARK
					gry_mark_skb(skb);
#endif
					return NF_ACCEPT;
				}	
			}

			/* Check if it is a unsafe IP, and if mac is safe, allow */
			if(labnf_is_unsafe_youtube_ip(iph->daddr)) {
				if((strncmp(skb->dev->name, "homebound", strlen("homebound")) == 0)){ // homebound allow
#if ENABLE_GRY_MARK
					gry_mark_skb(skb);
#endif
					return NF_ACCEPT;
				}
				#ifdef SSLPROXY_BUILD
				if(labnf_is_apc_mac(mac)) {  // Drop if udp quic packet if its apc client
					return NF_DROP;
				}
				#endif
				if(labnf_is_safe_youtube_mac(mac)){
#if ENABLE_GRY_MARK
					gry_mark_skb(skb);
#endif
					return NF_ACCEPT;
				}
			}
			labnf_parse_history(skb, IPPROTO_UDP);
			return NF_DROP;

		} else {
			if(device_paused == PAUSED){
				return NF_DROP;
			}
		}
	}

	// TCP Protocol
	if(iph->protocol == IPPROTO_TCP){
		struct tcphdr *tcph = NULL;
		bool is_gso = false;
		tcph = (struct tcphdr*)skb_transport_header(skb);
		if(!tcph){
#if ENABLE_GRY_MARK
			gry_mark_skb(skb);
#endif
			return NF_ACCEPT;
		}

		src_port = ntohs(tcph->source);
		dest_port = ntohs(tcph->dest);
		if(dest_port == 22 || dest_port == 53 || dest_port == 3000 || dest_port == 67 || dest_port == 123 || dest_port == 1900 || src_port == dest_port){
#if ENABLE_GRY_MARK
			gry_mark_skb(skb);
#endif
			return NF_ACCEPT;
		}

		if(is_handshake_packet(tcph) && ntohs(iph->tot_len) <= 57){
#if ENABLE_GRY_MARK
			gry_mark_skb(skb);
#endif
			return NF_ACCEPT;
		}

		if(ntohs(iph->tot_len) <= (iph->ihl * 4 + tcph->doff * 4)){
#if ENABLE_GRY_MARK
			gry_mark_skb(skb);
#endif
			return NF_ACCEPT;
		}
		// Check the pause flag here
		device_paused = labnf_peer_inet_paused(mac, iph->daddr, dest_port);

		is_gso = skb_is_gso(skb);
#if 0
		if(is_gso_capable == false && is_gso == true){
			is_gso_capable = is_gso;
		}
#endif

		data = skb->data + iph->ihl * 4 + tcph->doff * 4;
		canSendResult = can_send_tcp_to_labrador(tcph, dest_port, data, ntohs(iph->tot_len));
		//printk("data0: %02X, %02X 5[%02X]for %u", data[0], data[1], data[5], ntohs(tcph->source));
		// check if the packet is marked as fragmented from application layer
		fragTuple->saddr = iph->saddr;
		fragTuple->daddr = iph->daddr;
		fragTuple->sport = tcph->source;
		fragTuple->dport = tcph->dest;
		fragTuple->protocol = 6;
		if(canSendResult == 2){
			// This is a client hello, check if its a re-transmission
			// use the peek_tuple method to confirm if its a re-tramission
			if(gry_rab_peek_tuple_element(fragTuple) == 0){
				// mark the tuple exists in RAB
				// as we don't need to save it again in RAB,
				// and just forward to labrador
				rabExists = 1;
				//printk(KERN_INFO "GRY_RAB_PEEK: SIZE FOR re-tx ignore %u, %u, %u\n", fragTuple->daddr, ntohs(fragTuple->sport), ntohs(fragTuple->dport));
			}
		} else if(canSendResult == 0){
			// This is not client hello, so confirm if the same tuple is
			// present in the RAB. This is definitely not CLIHLO, so 2nd frame
			if(gry_rab_get_tuple_element(fragTuple) == 0){
				// tuple found in RAB, send to labrador
				//printk("GRY_RAB_GET: SIZE FOR 2nd packet: %u for %u, port[%u],[%u], skb_is_gso[%d], [%u]\n",ntohs(iph->tot_len), iph->daddr, ntohs(tcph->source), ntohs(tcph->dest), is_gso, gry_skb_gso_network_seglen(skb));
				labnf_parse_history(skb, IPPROTO_TCP);
				return NF_DROP;
			}
		}


		if(canSendResult != 0){
			read_lock_bh(&ss_rwlock);
			for(idx=0; idx < safesearchCount; idx++){
				if(iph->daddr == safesearchIps[idx]){
					if(!device_paused){
						// if safe search ip and device is not paused
						read_unlock_bh(&ss_rwlock);
#if ENABLE_GRY_MARK
						gry_mark_skb(skb);
#endif
						return NF_ACCEPT;
					} else {
						read_unlock_bh(&ss_rwlock);
						return NF_DROP;
					}
				}
			}
			read_unlock_bh(&ss_rwlock);		

			if(labnf_is_unsafe_ip(iph->daddr)){
				if(device_paused){
					return NF_DROP;
				}
				if(labnf_is_safe_mac(mac)){
#if ENABLE_GRY_MARK
					gry_mark_skb(skb);
#endif
					return NF_ACCEPT;
				}
			}

			/* Check if it is a unsafe youtube IP, and if mac is youtube safe, allow */
			if(labnf_is_unsafe_youtube_ip(iph->daddr)) {

				if(device_paused)
					return NF_DROP;

				if((strncmp(skb->dev->name, "homebound", strlen("homebound")) == 0)){ // homebound allow
#if ENABLE_GRY_MARK
					gry_mark_skb(skb);
#endif
					return NF_ACCEPT;
				}
				#ifdef SSLPROXY_BUILD
				if(labnf_is_apc_mac(mac)) {  // Drop if udp quic packet if its apc client
					return NF_DROP;
				}
				#endif
				if(labnf_is_safe_youtube_mac(mac)){
#if ENABLE_GRY_MARK
					gry_mark_skb(skb);
#endif
					return NF_ACCEPT;
				}
			}
			// Only save in RAB if the packet is original transmission and not retransmission
			// To store a GSO packet in RAB, verify with skb_is_gso() function incase of gso
			// capable and rabExists,should be 0. Incase of not gso capable, check only with
			// rabExists flag
#if 0
			if(is_gso_capable){
				if(is_gso && rabExists == 0){
					gry_rab_set_tuple_element(fragTuple);
					printk("GRY_RAB_SET: SIZE FOR add RAB: %u for %u, port[%u],[%u]\n",ntohs(iph->tot_len), iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));
				}
			} else {
				if(rabExists == 0){
					gry_rab_set_tuple_element(fragTuple);
					printk("GRY_RAB_SET: SIZE FOR add RAB: %u for %u, port[%u],[%u]\n",ntohs(iph->tot_len), iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));
				}
			}
#endif
			// canSendResult 2 means, len greater than 1100 and gso is 1
			if(canSendResult == 2 && rabExists == 0){
				gry_rab_set_tuple_element(fragTuple);
				//printk("GRY_RAB_SET: SIZE FOR add RAB: %u for %u, port[%u],[%u], gso[%u], gso_len[%u]\n",ntohs(iph->tot_len), iph->daddr, ntohs(tcph->source), ntohs(tcph->dest), is_gso, gry_skb_gso_network_seglen(skb));
			}
			//printk("SIZE FOR ip header for inskb2 for unknown: %u for %u, port[%u],[%u], skb_is_gso[%d], [%u]\n",ntohs(iph->tot_len), iph->daddr, ntohs(tcph->source), ntohs(tcph->dest), is_gso, gry_skb_gso_network_seglen(skb));
			labnf_parse_history(skb, IPPROTO_TCP);
			return NF_DROP;

		} else {
			if(device_paused == PAUSED){
				return NF_DROP;
			}
		}
	}
#if ENABLE_GRY_MARK
	gry_mark_skb(skb);
#endif
	return NF_ACCEPT;
}

/*
 * @details: Add the fragmented tuple information to RAB
 */
static int fragment_tuple_rab_action(struct sk_buff *skb, struct genl_info *recvinfo){
	struct nlattr *na;
	struct gry_fragment_tuple_payload_t *tuple_payload;
	struct gry_fragment_tuple_t *tuple;
	if(!recvinfo->attrs[LABPM_ATTR_FRAGMENT_TUPLE]){
		printk(KERN_ERR "GRY_DPI_KERN: FRAG_TUPLE_ATTR_NOT_FOUND\n");
		return -EINVAL;
	}
	
	na = recvinfo->attrs[LABPM_ATTR_FRAGMENT_TUPLE];
	if(nla_len(na) != sizeof(struct gry_fragment_tuple_payload_t)){
		printk(KERN_ERR "GRY_DPI_KERN: FRAG_TUPLE_ATTR_LEN_ERR\n");
		return -EINVAL;
	}
	
	tuple_payload = (struct gry_fragment_tuple_payload_t*)nla_data(na);
	printk(KERN_INFO "GRY_DPI_KERN: Recevied Fragment Tuple\n");
	switch(tuple_payload->cmd){
		case GRY_FRAG_CMD_SET:
			tuple = &(tuple_payload->tuple);
			gry_rab_set_tuple_element(tuple);
			printk(KERN_INFO "GRY_DPI_KERN: SET: %u, %u, %u, %u, %u\n", tuple->saddr, tuple->daddr, ntohs(tuple->sport), ntohs(tuple->dport), tuple->protocol);
			break;
		case GRY_FRAG_CMD_GET:
			tuple = &(tuple_payload->tuple);
			gry_rab_get_tuple_element(tuple);
			printk(KERN_INFO "GRY_DPI_KERN: GET: %u, %u, %u, %u, %u\n", tuple->saddr, tuple->daddr, ntohs(tuple->sport), ntohs(tuple->dport), tuple->protocol);
			break;
		case GRY_FRAG_CMD_PRINT:
			gry_rab_print_tuple_elements();
			break;
		case GRY_FRAG_CMD_CLEAR:
			gry_rab_clear_tuple_elements();
			break;
		case GRY_FRAG_CMD_DEL:
			tuple = &(tuple_payload->tuple);
			gry_rab_del_tuple_element(tuple);
			printk(KERN_INFO "GRY_DPI_KERN: DELETE: %u, %u, %u, %u, %u\n", tuple->saddr, tuple->daddr, ntohs(tuple->sport), ntohs(tuple->dport), tuple->protocol);
		default:
			break;
	}

	return 0;
}

static struct nf_hook_ops gry_prerouting_hook_ops = {
	.hook = gry_prerouting_packet_process_hook,
	.hooknum = NF_INET_FORWARD,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST
};

#if PORTSCAN_ENABLED
static struct nf_hook_ops gry_portscan_hook_ops = {
	.hook = gry_portscan_hook,
	.hooknum = NF_BR_PRE_ROUTING,
	.pf = PF_BRIDGE,
	.priority = NF_BR_PRI_FIRST,
};
#endif

// structure containing the generic netlink operations
static struct genl_ops labpm_genl_ops[] = {
	{
		.cmd = LABPM_CMD_INIT,
		.doit = labnf_set_labpm_portid,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_UDP_INIT,
		.doit = labnf_set_labpm_udp_portid,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif

	},
#if 0
	{
		.cmd = LABPM_CMD_RA_INIT,
		.doit = labnf_set_ra_portid,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
#endif
	{
		.cmd = LABPM_CMD_INET_PAUSE_UNPAUSE,
		.doit = labnf_set_inet_pause_unpause,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_CLOSE,
		.doit = labnf_reset_labpm_portid,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
#if 0
	{
		.cmd = LABPM_CMD_RA_CLOSE,
		.doit = labnf_reset_ra_portid,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
#endif
	{
		.cmd = LABPM_CMD_SS_IP_LIST,
		.doit = labnf_allow_safesearch_ip,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_SAFE_MAC,
		.doit = labnf_add_del_mac_to_safe_list,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_UNSAFE_IP,
		.doit = labnf_add_ip_to_unsafe_list,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_APC_IP,
		.doit = labnf_add_ip_to_apc_list,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{

		.cmd = LABPM_CMD_APC_MAC,
		.doit = labnf_add_del_mac_to_apc_list,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_MUSIC_IP_LIST,
		.doit = labnf_add_music_ip_list,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_FLUSH_TABLE,
		.doit = labnf_flush_table,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_SAFE_YOUTUBE_MAC,
		.doit = add_del_mac_to_safe_youtube_list,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif

	},
	{
		.cmd = LABPM_CMD_UNSAFE_YOUTUBE_IP,
		.doit = add_ip_to_unsafe_youtube_list,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_FRAGMENT_TUPLE,
		.doit = fragment_tuple_rab_action,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_APPLE_PRIV,
		.doit = apple_priv_browse_block_list,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_CLOUD_SERVER,
		.doit = cloud_server_allowed_list,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	},
	{
		.cmd = LABPM_CMD_APPLE_PRIV_MAC,
		.doit = apple_priv_browse_mac_list,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		.policy = labpm_genl_policy
#endif
	}
};

// function to register labpm_genl_family along with labpm_genl_ops
static int gry_register_labpm_genl_family(void){
	int result = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	memset(&labpm_genl_family, 0, sizeof(struct genl_family));
	labpm_genl_family.id = 0;
	labpm_genl_family.hdrsize = 0;
	strncpy(labpm_genl_family.name, "LABPM_DNAT", strlen("LABPM_DNAT"));
	labpm_genl_family.version = 1;
	labpm_genl_family.maxattr = LABPM_ATTR_MAX;
	labpm_genl_family.ops = labpm_genl_ops;
	labpm_genl_family.n_ops = sizeof(labpm_genl_ops) / sizeof(labpm_genl_ops[0]);
	labpm_genl_family.policy = labpm_genl_policy;
	result = genl_register_family(&labpm_genl_family);
#else
	result = genl_register_family_with_ops(&labpm_genl_family, labpm_genl_ops);
#endif
	return result;
}

static int gry_register_tc_genl_family(void){
	int result = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	memset(&gry_ra_genl_family, 0, sizeof(struct genl_family));
	gry_ra_genl_family.id = 0;
	gry_ra_genl_family.version = 1;
	strncpy(gry_ra_genl_family.name, "GRY_TC", strlen("GRY_TC"));
	gry_ra_genl_family.maxattr = LABPM_ATTR_MAX;
	gry_ra_genl_family.ops = labpm_genl_ops;
	gry_ra_genl_family.n_ops = sizeof(labpm_genl_ops) / sizeof(labpm_genl_ops[0]);
	gry_ra_genl_family.policy = labpm_genl_policy;
	result = genl_register_family(&gry_ra_genl_family);
#else
	result = genl_register_family_with_ops(&gry_ra_genl_family, labpm_genl_ops);
#endif
	return result;
}

#if PORTSCAN_ENABLED
ssize_t portscan_devices_read(struct file *filp, char *ubuf, size_t count, loff_t *ppos){
	int len = 0;
	int i = 0;
	struct tcp_special_data_t *data_ptr = NULL;
	struct normal_port_scan_data_t *tcp_normal_ptr = NULL;
	char mac[20];

	if(*ppos > 0 || count < PORTSCAN_DEVICES_BUFFER_SIZE)
		return 0;
	memset(portscan_devices_buffer, 0, sizeof(portscan_devices_buffer));
	spin_lock_bh(&gry_lock);
	// clean the buffer storage to copy
	clear_data_storage_buffer();

	// copy the tcp special nodes to buffer
	tcp_special_nodes_buf.node_count = tcp_special_nodes.node_count;
	memcpy(tcp_special_nodes_buf.nodes, tcp_special_nodes.nodes, NO_OF_DEVICES * sizeof(struct tcp_special_data_t));

	// copy the tcp normal nodes to buffer
	tcp_normal_scan_buf.node_count = tcp_normal_scan.node_count;
	memcpy(tcp_normal_scan_buf.nodes, tcp_normal_scan.nodes, NO_OF_DEVICES * sizeof(struct normal_port_scan_data_t));

	// clear the main memory location for processing
	clear_data_storage();

	spin_unlock_bh(&gry_lock);

	for(i = 0; i < tcp_special_nodes_buf.node_count; i++){
		data_ptr = (tcp_special_nodes_buf.nodes + i);
		memset(mac, 0, sizeof(mac));
		len += snprintf(mac, sizeof(mac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", data_ptr->mac[0], data_ptr->mac[1], data_ptr->mac[2], data_ptr->mac[3], data_ptr->mac[4], data_ptr->mac[5]);
		strcat(portscan_devices_buffer, mac);
	}

	// tcp normal scan nodes
	for(i=0; i< tcp_normal_scan_buf.node_count; i++){
		tcp_normal_ptr = (tcp_normal_scan_buf.nodes + i);
		if(tcp_normal_ptr->actual_port_count > PORTSCAN_TCP_NORMAL_THRESHOLD){
			tcp_normal_ptr = (tcp_normal_scan_buf.nodes + i);

			memset(mac, 0, sizeof(mac));
			len += snprintf(mac, sizeof(mac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", tcp_normal_ptr->mac[0], tcp_normal_ptr->mac[1], tcp_normal_ptr->mac[2], tcp_normal_ptr->mac[3], tcp_normal_ptr->mac[4], tcp_normal_ptr->mac[5]);
			strcat(portscan_devices_buffer, mac);
		}
	}

	if(len > 0){
		if(copy_to_user(ubuf, portscan_devices_buffer, len))
			return -EFAULT;
		*ppos = len;
	}
	return len;
}

ssize_t portscan_devices_write(struct file *filp, const char *ubuf, size_t count, loff_t *ppos){
	// Dont allow write operations on devices file
	return -1;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static struct proc_ops portscan_devices_fops = {
	.proc_read = portscan_devices_read,
	.proc_write = portscan_devices_write,
};
#else
static struct file_operations portscan_devices_fops = {
	.owner = THIS_MODULE,
	.read = portscan_devices_read,
	.write = portscan_devices_write,
};
#endif

ssize_t portscan_verbose_read(struct file *filp, char *ubuf, size_t count, loff_t *ppos){
	int len = 0;
	if(*ppos > 0 || count < VERBOSE_BUFFER_SIZE)
		return 0;
	len = snprintf(portscan_verbose_buffer, sizeof(portscan_verbose_buffer), "%d\n", portscan_verbose);
	if(copy_to_user(ubuf, portscan_verbose_buffer, len))
		return -EFAULT;
	*ppos = len;
	return len;
}

ssize_t portscan_verbose_write(struct file *filp, const char *ubuf, size_t count, loff_t *ppos){
	int len = 0;
	if(count > VERBOSE_BUFFER_SIZE){
		len = VERBOSE_BUFFER_SIZE;
	} else {
		len = count;
	}
	memset(portscan_verbose_buffer, 0, sizeof(portscan_verbose_buffer));
	if(copy_from_user(portscan_verbose_buffer, ubuf, len))
		return -EFAULT;

	// just check number with \n
	if(len != 2)
		return -1;

	if(!strncmp(portscan_verbose_buffer, "1", 1) || !strncmp(portscan_verbose_buffer, "0", 1)){
		if(kstrtouint(portscan_verbose_buffer, 0, &portscan_verbose) != 0){
			// if failed to parse the number, assign default to 0
			portscan_verbose = 0;
		}
		printk("gryphon: port scan verbose mode: %d\n", portscan_verbose);
	} else {
		printk("gryphon: incorrect verbose mode specified, allowed are only 1 or 0\n");
		return -1;
	}
	return len;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static struct proc_ops portscan_verbose_fops = {
	.proc_read = portscan_verbose_read,
	.proc_write = portscan_verbose_write,
};
#else
static struct file_operations portscan_verbose_fops = {
	.owner = THIS_MODULE,
	.read = portscan_verbose_read,
	.write = portscan_verbose_write,
};
#endif
#endif

#if GRYPHON_DEBUG_ENABLED 
/**
 * Parental control pre routing hook packet verbose mode proc read fileops
 */
ssize_t parental_control_verbose_read(struct file *filp, char *ubuf, size_t count, loff_t *ppos){
	int len = 0;
	if(*ppos > 0 || count < VERBOSE_BUFFER_SIZE)
		return 0;
	len = snprintf(parental_control_verbose_buffer, sizeof(parental_control_verbose_buffer), "%d\n", parental_control_verbose);
	if(copy_to_user(ubuf, parental_control_verbose_buffer, len))
		return -EFAULT;
	*ppos = len;
	return len;

}

/**
 * Parental control pre routing hook packet verbose mode proc write fileops
 */
ssize_t parental_control_verbose_write(struct file *filp, const char *ubuf, size_t count, loff_t *ppos){
	int len = 0;
	if(count > VERBOSE_BUFFER_SIZE){
		len = VERBOSE_BUFFER_SIZE;
	} else {
		len = count;
	}
	memset(parental_control_verbose_buffer, 0, sizeof(parental_control_verbose_buffer));
	if(copy_from_user(parental_control_verbose_buffer, ubuf, len))
		return -EFAULT;
	if(len != 2)
		return -1;
	if(!strncmp(parental_control_verbose_buffer, "1", 1) || !strncmp(parental_control_verbose_buffer, "0", 1)){
		if(kstrtouint(parental_control_verbose_buffer, 0, &parental_control_verbose) != 0){
			parental_control_verbose = 0;
		}
		printk("GRY_DPI_KERN: PC Verbose mode: %d\n", parental_control_verbose);
	} else {
		printk("GRY_DPI_KERN: PC Verbose mode incorrect only 1 and 0 are allowed\n");
		return -1;
	}
	return len;
}

/**
 * Parental control verbose proc fileops
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static struct proc_ops parental_control_verbose_fops = {
	.proc_read = parental_control_verbose_read,
	.proc_write = parental_control_verbose_write,
};
#else
static struct file_operations parental_control_verbose_fops = {
	.owner = THIS_MODULE,
	.read = parental_control_verbose_read,
	.write = parental_control_verbose_write,
};
#endif

/**
 * hashtable list verbose proc file read ops
 */
ssize_t hashtable_name_verbose_read(struct file *filp, char *ubuf, size_t count, loff_t *ppos){
	int len = 0;
	char helptext[1024] = {0};
	if(*ppos > 0 || count < VERBOSE_BUFFER_SIZE)
		return 0;
	len = snprintf(helptext, sizeof(helptext), "Use the following KEY to print the hashtable\n" \
			"KEY ---- HASHTABLE NAME\n" \
			"1-labnf_redirect_hash,\n" \
			"2-labnf_safe_mac_hash\n" \
			"3-labnf_unsafe_ip_hash\n" \
			"4-labnf_music_ip_hash\n" \
			"5-labnf_apc_ip_hash\n" \
			"6-labnf_apc_mac_hash\n");
	if(copy_to_user(ubuf, helptext, len))
		return -EFAULT;
	*ppos = len;
	return len;
}

/**
 * hashtable list verbose proc file write ops
 */
ssize_t hashtable_name_verbose_write(struct file *filp, const char *ubuf, size_t count, loff_t *ppos){
	int len = 0;
	char buffer[32] = {0};
	if(count > VERBOSE_BUFFER_SIZE){
		len = VERBOSE_BUFFER_SIZE;
	} else {
		len = count;
	}
	memset(buffer, 0, sizeof(buffer));
	if(copy_from_user(buffer, ubuf, len))
		return -EFAULT;
	if(kstrtouint(buffer, 0, &hashtable_name) != 0){
		printk("GRY_DPI_KERN: incorrect hashtable name\n");
		return -1;
	}
	printk("GRY_DPI_KERN: Hash table selected: %d\n", hashtable_name);
	if(hashtable_name < 1 && hashtable_name > 6){
		printk("GRY_DPI_KERN: incorrect hashtable name\n");
		return -1;
	}
	return len;

}

/**
 * Unsafe ips list proc file ops
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static struct proc_ops hashtables_fops = {
	.proc_read = hashtable_name_verbose_read,
	.proc_write = hashtable_name_verbose_write,
};
#else
static struct file_operations hashtables_fops = {
	.owner = THIS_MODULE,
	.read = hashtable_name_verbose_read,
	.write = hashtable_name_verbose_write,
};
#endif

ssize_t hashtable_print_read(struct file *filp, char *ubuf, size_t count, loff_t *ppos){
	int len = 0;
	char buffer[1024] = {0};
	u32 bkt;

	if(*ppos > 0 || count < VERBOSE_BUFFER_SIZE)
		return 0;

	printk("GRY_DPI_KERN: Current Hashtable being printed is: %d\n", hashtable_name);

	if(hashtable_name == 1){
		redirect_ *peer;
		char redirect_buffer[128] = {0};
		spin_lock_bh(&labnf_redirect_lock);
		hash_for_each(labnf_redirect_hash, bkt, peer, hnode){
			memset(redirect_buffer, 0, sizeof(redirect_buffer));
			len+=snprintf(redirect_buffer, sizeof(redirect_buffer), "%pM\n", peer->mac);
			strcat(buffer, redirect_buffer);
		}
		spin_unlock_bh(&labnf_redirect_lock);
	} 
	else if(hashtable_name == 2){

	}
	else if(hashtable_name == 3){
		safe_mac_ip_ *peer;
		char ip[32] = {0};
		len += snprintf(buffer, sizeof(buffer), "Printing labnf_unsafe_ip_hash\n");
		spin_lock_bh(&labnf_unsafe_ip_lock);
		hash_for_each(labnf_unsafe_ip_hash, bkt, peer, hnode){
			memset(ip, 0, sizeof(ip));
			len += snprintf(ip, sizeof(ip), "%pI4\n", &peer->unsafe_ip);
			strcat(buffer, ip);
		}
		spin_unlock_bh(&labnf_unsafe_ip_lock);
	}
	else if(hashtable_name == 4){

	}
	else if(hashtable_name == 5){

	}
	else if(hashtable_name == 6){

	}
	else {
		len = snprintf(buffer, sizeof(buffer), "Incorrect number mentioned, no hashtable present with that name\n");
	}
	if(copy_to_user(ubuf, buffer, len))
		return -EFAULT;

	*ppos = len;
	return len;
}

ssize_t hashtable_print_write(struct file *filp, const char *ubuf, size_t count, loff_t *ppos){
	return -1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static struct proc_ops hashtables_print_fops = {
	.proc_read = hashtable_print_read,
	.proc_write = hashtable_print_write,
};
#else
static struct file_operations hashtables_print_fops = {
	.owner = THIS_MODULE,
	.read = hashtable_print_read,
	.write = hashtable_print_write,
};
#endif
#endif

#if PORTSCAN_ENABLED
static int gryphon_init_proc_fs(void){
	parent_dir = proc_mkdir(PARENT_PROC_DIR, NULL);
	if(!parent_dir){
		goto cleanup;
	}

	portscan_dir = proc_mkdir(PORTSCAN_PROC_DIR, parent_dir);
	if(!portscan_dir){
		goto cleanup;
	}

	portscan_devices_file = proc_create(PORTSCAN_DEVICES_FILE, 0666, portscan_dir, &portscan_devices_fops);
	if(!portscan_devices_file){
		goto cleanup;
	}

	portscan_verbose_file = proc_create(PORTSCAN_VERBOSE_FILE, 0666, portscan_dir, &portscan_verbose_fops);
	if(!portscan_verbose_file){
		goto cleanup;
	}
#if GRYPHON_DEBUG_ENABLED
	parental_control_verbose_file = proc_create(PARENTAL_CONTROL_VERBOSE_FILE, 0666, parent_dir, &parental_control_verbose_fops);
	if(!parental_control_verbose_file){
		goto cleanup;
	}

	hashtables_verbose_file = proc_create(HASHTABLES_PROC_FILE, 0666, parent_dir, &hashtables_fops);
	if(!hashtables_verbose_file){
		goto cleanup;
	}

	hashtables_print_file = proc_create(HASHTABLES_PRINT_FILE, 0666, parent_dir, &hashtables_print_fops);
	if(!hashtables_print_file){
		goto cleanup;
	}
#endif

	return 0;

cleanup:
	if(portscan_devices_file)
		proc_remove(portscan_devices_file);
	if(portscan_verbose_file)
		proc_remove(portscan_verbose_file);
	if(portscan_dir)
		proc_remove(portscan_dir);
#if GRYPHON_DEBUG_ENABLED
	if(parental_control_verbose_file)
		proc_remove(parental_control_verbose_file);
	if(hashtables_verbose_file)
		proc_remove(hashtables_verbose_file);
	if(hashtables_print_file)
		proc_remove(hashtables_print_file);
#endif
	if(parent_dir)
		proc_remove(parent_dir);
	printk("gryphon: failed to create proc entries\n");
	return -1;
}
#endif 

#if PORTSCAN_ENABLED
static void gryphon_destroy_proc_fs(void){
	if(portscan_devices_file)
		proc_remove(portscan_devices_file);
	if(portscan_verbose_file)
		proc_remove(portscan_verbose_file);
	if(portscan_dir)
		proc_remove(portscan_dir);
	if(parent_dir)
		proc_remove(parent_dir);
	printk("gryphon: proc entries removed\n");
}
#endif

// Initialize the kernel module
static int __init parental_control_init(void){
	int ret_val;
	struct net *n;

	is_gso_capable = false;

	printk(KERN_INFO "GRY_DPI_KERN: inserting\n");
	printk(KERN_INFO "GRY_DPI_KERN: Version: %s\n", GRY_MODULE_VERSION);

	// Initialize the common variable for checking the fragmented tuple
	fragTuple = gry_safe_alloc(sizeof(struct gry_fragment_tuple_t));
	if(!fragTuple){
		printk(KERN_ERR "GRY_DPI_KERN: fragTuple malloc failed\n");
		return -1;
	}

	// invoke the timer for RAB
	gry_rab_timer_invoke();
	
#if PORTSCAN_ENABLED
	// initialize the data storage locations
	init_data_storage();

	// initialize the proc files
	ret_val = gryphon_init_proc_fs();
	if(ret_val < 0)
		goto cleanup;
#endif
	printk("GRY_DPI_KERN: Parental control module init success\n");
	for_each_net(n) {
		nf_register_net_hook(n, &gry_prerouting_hook_ops);
#if PORTSCAN_ENABLED
		nf_register_net_hook(n, &gry_portscan_hook_ops);
#endif
	}
	printk("GRY_DPI_KERN: hook register success\n");

	if(gry_register_labpm_genl_family() < 0){
		printk("GRY_DPI_KERN: genl_register_family failed\n");
		goto cleanup;
	}

	if(gry_register_tc_genl_family() < 0){
		printk("GRY_DPI_KERN: tc_genl_family failed\n");
		goto cleanup;
	}

	if(ret_val){
		printk("GRY_DPI_KERN: failed to register genl\n");
		goto cleanup;
	}
	return 0;

cleanup:
	return -1;
}

static void __exit parental_control_exit(void){
	struct net *n;

#if PORTSCAN_ENABLED
	// Free the data storage locations before exiting
	free_data_storage();

	// remove the proc entries
	 gryphon_destroy_proc_fs();
#endif

	for_each_net(n){
		nf_unregister_net_hook(n, &gry_prerouting_hook_ops);
#if PORTSCAN_ENABLED
		nf_unregister_net_hook(n, &gry_portscan_hook_ops);
#endif
	}
	genl_unregister_family(&labpm_genl_family);

	genl_unregister_family(&gry_ra_genl_family);

#if 0
	// Free the memory
	if(history_buffer){
		kfree(history_buffer);
	}

	if(packattr){
		kfree(packattr);
	}
#endif

	// destroy the timer for RAB
	gry_rab_timer_destroy();

	if(fragTuple){
		kfree(fragTuple);
	}
	printk("GRY_DPI_KERN: Parental control module exit success\n");
}

module_init(parental_control_init);
module_exit(parental_control_exit);

MODULE_AUTHOR("Naveen Kumar Gutti<naveen@gryphonconnect.com>");
MODULE_DESCRIPTION("Parental control module");
MODULE_LICENSE("GPL");
MODULE_VERSION(GRY_MODULE_VERSION);
