/*
 * pcap_engine.c
 *
 *  Created on: 2017年11月10日
 *      Author: yanxdd
 */

#include "pcap_engine.h"

sessions_t g_sessions;

unsigned g_ethernet_size = 0;

static unsigned long int	g_num_packets = 0;    /* the running total of packets */
/*
https://linux.die.net/man/7/pcap-linktype
*/
int get_ethernet_size(int link_type)
{
    switch(link_type)
    {
    case 0:	//LINKTYPE_NULL:
        return -1;	//I'm not sure. maybe 4
    case 1:	//LINKTYPE_ETHERNET:
        return 14;	//sizeof(sniff_ethernet);	//14
    case 101:	//LINKTYPE_RAW:
    	return -1;	//I'm not sure. maybe 0
    case 104:	//LINKTYPE_C_HDLC:
    	return -1;	//I'm not sure. maybe 4
    default:
        return -1;
    }
    return -1;
}

void pcap_process_packet(const struct pcap_pkthdr *header, const u_char *packet, f_state *s)
{
    /* Define pointers for packet's attributes */
    struct sniff_ethernet *ethernet;  /* The ethernet header */
    struct sniff_ip *ip;              /* The IP header */
    struct sniff_tcp *tcp;            /* The TCP header */
    struct sniff_udp *udp;            /* The UDP header */
    uint8_t *payload;           /* The data */

    /* And define the size of the structures we're using */
    int size_ethernet = g_ethernet_size;// = sizeof(struct sniff_ethernet);
    int size_ip;
    int size_tcp;
    int size_udp = 8;  /* just trust me */

    size_t header_size, payload_size;
    connection_t conn;

    g_num_packets++;
#ifdef __DEUBG
	fprintf(stdout, "g_num_packets = %d\n", g_num_packets);
#endif

    if(header->len < g_ethernet_size + sizeof(sniff_ip) + sizeof(sniff_udp))
    	return;

    /* -- Define our packet's attributes -- */
    /* There is obviously a lot of unused potential here since we only want to dump */
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + size_ethernet);
    size_ip = ip->ip_hl << 2;
    tcp = (struct sniff_tcp*)(packet + size_ethernet + size_ip);
    size_tcp = tcp->th_off << 2;
    udp = (struct sniff_udp*)(packet + size_ethernet + size_ip);

    /* if it ain't IP, bail, hard */
    if (ethernet->ether_type != 0x08) /* I think 0x08 is IP, at least it looks that way */
        return;

    switch (ip->ip_p) {
    case TCP_PROTO:
        header_size = size_ethernet + size_ip + size_tcp;
        break;
    case UDP_PROTO:
        header_size = size_ethernet + size_ip + size_udp;
        break;
    default:
        return;          /* at this point, I only care about tcp and udp */
    }

    payload_size = header->len - header_size;
    if ((int)payload_size <= 0)
        return;
    payload = (uint8_t *)(packet + header_size);

    conn.ip_src = ip->ip_src.s_addr;
    conn.ip_dst = ip->ip_dst.s_addr;
    conn.port_src = tcp->th_sport;
    conn.port_dst = tcp->th_dport;

	sessions_t::iterator iter;
	std::shared_ptr<conn_info_t> ci;
    iter = g_sessions.find(conn);
	if (iter != g_sessions.end())
	{
		ci = iter->second;
		if(ci->_size_used + payload_size > ci->_size){
			if( !ci->expand_buf(ci->_size_used + payload_size) ){
				audit_msg(s, "expand_buf error! %s:%d->%s:%d require malloc size = %d\n",
						inet_ntoa(*(in_addr*)conn.ip_src), ntohs(conn.port_src), inet_ntoa(*(in_addr*)conn.ip_dst), ntohs(conn.port_dst),
						ci->_size_used + payload_size);
				g_sessions.erase(iter);
				//delete ci;
				return;
			}
		}
	}
	else
	{
		//ci = (conn_info_t *)new conn_info_t(payload_size);
		ci = std::make_shared<conn_info_t>(payload_size);
		if(!ci->_buf)
			return;
		ci->_ts.tv_sec = header->ts.tv_sec;
		ci->_ts.tv_usec = header->ts.tv_usec;
		g_sessions.insert(std::make_pair(conn, ci));
    }
	ci->add_data(payload, payload_size);

	if (pcap_search_chunk(s, &conn, ci.get()) < 0) {
		// no header magic num, data ...
		ci->_ts.tv_sec = header->ts.tv_sec;
		ci->_ts.tv_usec = header->ts.tv_usec;
		ci->retain_tail_data(MAX_HEADER_MAGIC_NUM_SIZE);
	} else {
		//have header magic num
		//getchar();
	}
	return;
}

int pcap_process_file(f_state *s)
{
	//printf("processing file\n");
	f_info	*i = (f_info *)malloc(sizeof(f_info));
	char	temp[PATH_MAX];
	char 	errbuf[PCAP_ERRBUF_SIZE]; /* Error buffer */
	struct bpf_program filter; /* hold compiled program */
	bpf_u_int32 mask; /* subnet mask */
	bpf_u_int32 net; /* ip */
	char filter_app[] = "tcp"; //don't use pcap_compile, handling this data yourself maybe be faster

	g_sessions.clear();

	if ((realpath(s->input_file, temp)) == NULL) {
		fprintf(stderr, "%s: %s\n", s->input_file, strerror(errno));
		return TRUE;
	}

	i->file_name = strdup(s->input_file);
	i->is_stdin = FALSE;
	//audit_start(s, i);

	pcap_t *handle = pcap_open_offline(i->file_name, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open file %s: %s\n", i->file_name, errbuf);
		return (2);
	}

	int link_type = pcap_datalink(handle);
    g_ethernet_size = get_ethernet_size(link_type);
    if(g_ethernet_size < 0){
		fprintf(stderr, "Couldn't recognize link type %d: %s\n", link_type, i->file_name);
    	pcap_close(handle);
		return (2);
    }

	/* Compile and apply the filter */
	if (pcap_compile(handle, &filter, filter_app, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_app, pcap_geterr(handle));
    	pcap_close(handle);
		return (2);
	}
	if (pcap_setfilter(handle, &filter) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_app, pcap_geterr(handle));
    	pcap_close(handle);
		return (2);
	}

	pcap_pkthdr *pkthdr;
	const unsigned char *pkt_data;
	int res;
    while((res = pcap_next_ex( handle, &pkthdr, &pkt_data)) >= 0){
        if(res == 0) //time out
            continue;
        //local_tv_sec = header->ts.tv_sec;
        //ltime=localtime(&local_tv_sec);
        //strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
        //printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
        pcap_process_packet(pkthdr, pkt_data, s);
    }

    if(res == -1){
    	fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(handle));
    }

	pcap_close(handle);
	return TRUE;
}


/********************************************************************************
 *Function: search_chunk
 *Description: Analyze the given chunk by running each defined search spec on it
 *Return: search index
 **********************************************************************************/
int pcap_search_chunk(f_state *s, connection_t *conn, conn_info_t* ci)
{
	unsigned char *buf = ci->_buf;
	u_int64_t chunk_size = ci->_size_used;
	u_int64_t f_offset = ci->_f_offset;
	u_int64_t c_offset = 0;	//foundat cunrent offset
	unsigned char *foundat = buf; //p
	unsigned char *current_pos = NULL;
	unsigned char *header_pos = NULL;
	unsigned char *newbuf = NULL;
	unsigned char *ind_ptr = NULL;
	u_int64_t current_buflen = chunk_size; //unprocessed part len of buf_used
	int tryBS[3] = { 4096, 1024, 512 };
	unsigned char *extractbuf = NULL;
	u_int64_t file_size = 0;
	s_spec *needle = NULL;
	int j = 0;
	int bs = 0;
	int rem = 0;
	int x = 0;
	int found_ind = FALSE;
	off_t saveme;
	//char comment[32];

	if(ci->_type_index >= 0)
		j = ci->_type_index;
	else j = 0;
	for (; j < s->num_builtin; j++) {
		needle = &search_spec[j];
		foundat = buf; /*reset the buffer for the next search spec*/
		if(ci->_type_index >= 0)
			foundat += ci->_off_magic_num;
#ifdef DEBUG
		printf("	SEARCHING FOR %s's\n", needle->suffix);
#endif
		bs = 0;
		current_buflen = chunk_size;
		while (foundat) {
			needle->written = FALSE;
			found_ind = FALSE;
			memset(needle->comment, 0, COMMENT_LENGTH - 1);
			if (chunk_size <= (foundat - buf)) {
#ifdef DEBUG
				printf("avoided seg fault in search_chunk()\n");
#endif
				foundat = NULL;
				break;
			}
			current_buflen = chunk_size - (foundat - buf);

			//if((foundat-buf)< 1 ) break;
#ifdef DEBUG
			//foundat_off=foundat;
			//buf_off=buf;
			//printf("current buf:=%llu (foundat-buf)=%llu \n", current_buflen, (u_int64_t) (foundat_off - buf_off));
#endif
			if (signal_caught == SIGTERM || signal_caught == SIGINT) {
				printf("Cleaning up.\n");
				signal_caught = 0;
			}

			if(ci->_type_index < 0){
				if (get_mode(s, mode_quick)) /*RUN QUICK SEARCH*/
				{
#ifdef DEBUG

					//printf("quick mode is on\n");
#endif

					/*Check if we are not on a block head, adjust if so*/
					rem = (foundat - buf) % s->block_size;
					if (rem != 0) {
						foundat += (s->block_size - rem);
					}

					if (memwildcardcmp(needle->header, foundat,
							needle->header_len, needle->case_sen) != 0) {

						/*No match, jump to the next block*/
						if (current_buflen > s->block_size) {
							foundat += s->block_size;
							continue;
						} else /*We are out of buffer lets go to the next search spec*/
						{
							foundat = NULL;
							break;
						}
					}

					header_pos = foundat;
				} else /**********RUN STANDARD SEARCH********************/
				{
					foundat = bm_search(needle->header, needle->header_len,
							foundat, current_buflen,//How much to search through
							needle->header_bm_table, needle->case_sen,//casesensative
							SEARCHTYPE_FORWARD);

					header_pos = foundat;
				}
			}

			if (foundat != NULL && foundat >= 0) /*We got something, run the appropriate heuristic to find the EOF*/
			{
				//now header is found.
				ci->set_magic_num(foundat - buf, j);
				current_buflen = chunk_size - (foundat - buf);

				if (get_mode(s, mode_ind_blk)) {
#ifdef DEBUG
					printf("ind blk detection on\n");
#endif

					//dumpInd(foundat+12*1024,1024);
					for (x = 0; x < 3; x++) {
						bs = tryBS[x];

						if (ind_block(foundat, current_buflen, bs)) {
							if (get_mode(s, mode_verbose)) {
								sprintf(needle->comment, " (IND BLK bs:=%d)", bs);
							}

							//dumpInd(foundat+12*bs,bs);
#ifdef DEBUG
							printf("performing mem move\n");
#endif
							if (current_buflen > 13 * bs)//Make sure we have enough buffer
									{
								if (!memmove(foundat + 12 * bs,
										foundat + 13 * bs,
										current_buflen - 13 * bs))
									break;

								found_ind = TRUE;
#ifdef DEBUG
								printf("performing mem move complete\n");
#endif
								ind_ptr = foundat + 12 * bs;
								current_buflen -= bs;
								chunk_size -= bs;
								break;
							}
						}

					}

				}

				c_offset = (foundat - buf);
				current_pos = foundat;

				/*Now lets analyze the file and see if we can determine its size*/

				// printf("c_offset=%llu %x %x %llx\n", c_offset,foundat,buf,c_offset);
				foundat = extract_file(s, c_offset, foundat, current_buflen, needle, f_offset, conn);
#ifdef DEBUG
				if (foundat == NULL)
				{
					printf("Foundat == NULL!!!\n");
				}
#endif
				if (get_mode(s, mode_write_all)) { //once found header, write file even if don't find footer
					if (needle->written == FALSE) {
						/*write every header we find*/
						if (current_buflen >= needle->max_len) {
							file_size = needle->max_len;
						} else {
							file_size = current_buflen;
						}

						sprintf(needle->comment, " (Header dump)");
						extractbuf = (unsigned char *) malloc(file_size * sizeof(char));
						memcpy(extractbuf, header_pos, file_size);
						write_to_disk(s, needle, file_size, extractbuf, c_offset + f_offset, conn);
						free(extractbuf);
					}
				} else if (!foundat) /*Should we search further?*/
				{
					/*We couldn't determine where the file ends, now lets check to see
					 * if we should try again
					 */
					if (current_buflen < needle->max_len) /*We need to bridge the gap*/
					{
						ci->set_magic_num(c_offset, j);
						return j;
					} else {
						foundat = header_pos; /*reset the foundat pointer to the location of the last header*/
						foundat += needle->header_len + 1; /*jump past the header*/
					}
				}
				if(foundat){
					ci->retain_tail_data(ci->_size_used - (foundat - buf));
				}
				ci->set_magic_num();
			}

			if (found_ind) {

				/*Put the ind blk back in, re-arrange the buffer so that the future blks names come out correct*/
#ifdef DEBUG
				printf("Replacing the ind block\n");
#endif
				/*This is slow, should we do this??????*/
				if (!memmove(ind_ptr + 1 * bs, ind_ptr, current_buflen - 13 * bs))
					break;
				memset(ind_ptr, 0, bs - 1);
				chunk_size += bs;
				memset(needle->comment, 0, COMMENT_LENGTH - 1);
			}
		}	//end while (foundat)
	} //end for (j = 0; j < s->num_builtin; j++)

	//bfind_header = false;
	ci->set_magic_num();
	return -1;
}
