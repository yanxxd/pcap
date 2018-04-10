/*
 * pcap_engine.h
 *
 *  Created on: 2017年11月10日
 *      Author: yanxdd
 */

#ifndef PCAP_ENGINE_H_
#define PCAP_ENGINE_H_
#include <inttypes.h>
#include <utility>
#include <map>
#include <memory>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include "main.h"

#define MAX_HEADER_MAGIC_NUM_SIZE 32

typedef struct connection{
	//u_char		ip_p;                   /* protocol */
	uint32_t	ip_src;
    uint32_t	ip_dst;
    uint16_t	port_src;
    uint16_t	port_dst;
    bool operator<(const connection &right) const{
    	//if(ip_p < right.ip_p) return true;
    	//if(ip_p > right.ip_p) return false;
    	if(ip_src < right.ip_src) return true;
    	if(ip_src > right.ip_src) return false;
    	if(ip_dst < right.ip_dst) return true;
    	if(ip_dst > right.ip_dst) return false;
    	if(port_src < right.port_src) return true;
    	if(port_src > right.port_src) return false;
    	if(port_dst < right.port_dst) return true;
    	return false;
    }
} connection_t;

#define CONN_INFO_MAX_BUF_SIZE 16 << 20 //16M
typedef struct conn_info {
	unsigned char	*_buf;
	uint32_t		_size;
	uint32_t		_size_used;
    u_int64_t 		_f_offset;			//data stream offset.  buf <-> f_offset of connection_t
	uint32_t 		_off_magic_num;		//the first magic num offset in buf
	int				_type_index;		//index of the first magic num type    search_spec[_type_index]
	struct timeval 	_ts;				/* time stamp */
    conn_info(uint32_t size)
    {
		for (int i = 0; i < 32; ++i) {
			if (0 == (size >> i)) {
				_size = 2 << i;
				break;
			}
		}
    	_size_used = 0;
    	_f_offset = 0;
    	_buf = new unsigned char[_size];
    	_off_magic_num = 0;
    	_type_index = -1;
    	_ts = {0};
    }
    ~conn_info()
	{
    	delete []_buf;
	}
    void add_data(unsigned char	*data, int len){
    	memcpy(_buf + _size_used, data, len);
    	_size_used += len;
    	_f_offset += len;
    }
    bool expand_buf(uint32_t size)
    {
		for (int i = 0; i < 32; ++i) {
			if (0 == (size >> i)) {
				_size = 1 << i;
				break;
			}
		}
    	if (_size > CONN_INFO_MAX_BUF_SIZE)
    		return false;
    	unsigned char	*new_buf = new unsigned char[_size];
    	if(!new_buf) return false;
        memcpy(new_buf, _buf, _size_used);
    	delete []_buf;
    	_buf = new_buf;
		return true;
    }
    void set_magic_num(uint32_t off_magic_num = 0, int type_index = -1){
		_type_index = type_index;
		_off_magic_num = off_magic_num;
    }
    void retain_tail_data(uint32_t size){
    	if( _size_used > size){
    		memmove(_buf, _buf + _size_used - size, size);
    		_size_used = size;
    	}
    }
} conn_info_t;

typedef std::pair<connection_t, std::shared_ptr<conn_info_t> > session_t;
typedef std::map<connection_t, std::shared_ptr<conn_info_t> > sessions_t;

enum protos {
    TCP_PROTO = 6,
    UDP_PROTO = 17
    /* anything else that sits on top of ip (like icmp) will be dumped in full */
};

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* Destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* Source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        #if BYTE_ORDER == LITTLE_ENDIAN
                u_int   ip_hl:4,        /* header length */
                        ip_v:4;         /* version */
        #endif
        #if BYTE_ORDER == BIG_ENDIAN
                u_int   ip_v:4,         /* version */
                        ip_hl:4;        /* header length */
        #endif
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

/* TCP header */
struct sniff_tcp {
        u_short th_sport;                       /* source port */
        u_short th_dport;                       /* destination port */
        tcp_seq th_seq;                         /* sequence number */
        tcp_seq th_ack;                         /* acknowledgement number */
        #if BYTE_ORDER == LITTLE_ENDIAN
                u_int   th_x2:4,                /* (unused) */
                        th_off:4;               /* data offset */
        #endif
        #if BYTE_ORDER == BIG_ENDIAN
                u_int   th_off:4,               /* data offset */
                        th_x2:4;                /* (unused) */
        #endif
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                         /* window */
        u_short th_sum;                         /* checksum */
        u_short th_urp;                         /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
    u_short uh_sport;     /* source port */
    u_short uh_dport;     /* destination port */
    u_short uh_length;    /* message length */
    u_short uh_sum;       /* checksum */
};

void pcap_process_packet(const struct pcap_pkthdr *header, const u_char *packet, f_state *s);

int pcap_search_chunk(f_state *s, connection_t *conn, conn_info_t *ci);

#endif /* PCAP_ENGINE_H_ */
