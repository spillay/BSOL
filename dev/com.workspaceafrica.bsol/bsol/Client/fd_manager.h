#ifndef _VTUN_FD_MANAGER_H
#define _VTUN_FD_MANAGER_H

#include "../../config.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/mman.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#define QLEN 20000

#define SOCK_Q_MAX 70000
#ifndef VTUN_MAX_INT
#define VTUN_MAX_INT 2
#endif

#define BIND_REQ 0
#define BIND_REQ_ACK 1
#define PING_NEW_DATAPATH 2
#define PING_NEW_DATAPATH_REPLY 3
#define BIND_REQ_COMPLETE 4
#define PING_PORT_PROBE 5
#define MM 6
#define UNBIND_REQ 7
#define SWITCH_INFO 8
#define FD_INFO 9
int temp[VTUN_MAX_INT];
typedef union
{
    uint32_t value;
    char stamp[4];
} stamp32;

// For safe conversion of 16 bit unsigned int to char
typedef union
{
    uint16_t value;
    char stamp[2];
} stamp16;

//Payload inform peer about its state of scheduling
//w1, w2 can be helpful on deciding weights of
//different interfaces, for failsafe mode
//this represent random mixing to handle losses
//can be extended for network coding
typedef struct
{
    int state; // Interface is not being
    int lease; // time(msec), zero means until next switch info
    int id;    // an unique id which may be transmitted via multiple path
    int type; // 0 -> req ; 1 -> ack
    int master;
} switch_info;

typedef struct
{
    int index;
    int port;
} bind_link;

typedef struct
{
    int type;
    int tag;
}app_msg;

typedef struct
{
    int flag[VTUN_MAX_INT];
}fd_info;


typedef struct {
int type;
union{
	switch_info si;
	bind_link bl;
        app_msg am;
        fd_info fi;
	};
}ctrl_msg;

// Payload to be sent by Rx Side on LOSS
// fd := link with loss
// start := starting local sequence number
// len := number of lost packets
// stamp := timestamp of loss

typedef struct
{
    int fd;
    int start;
    int len;
    int stamp;
} loss_info_t;


// Payload to be sent by Rx Side on ACK
// start := starting local sequence number
// len := number of packets

typedef struct
{
    int gs;
    int l[VTUN_MAX_INT];
} ack_t;

// Payload to be sent by Rx Side on LINK
// last_rcvd := last received local sequence

typedef struct
{
    int last_rcvd;
} link_info_t;

// Context maintained for scheduling packets
typedef struct
{
    struct timespec ts;
    int gs_1;
    int ls_1[VTUN_MAX_INT];
    int unack_1[VTUN_MAX_INT];
    int state;
    uint64_t tag;
    int master;
} schedule_context;


// Structure to maintain Rx side
// state for reorder
typedef struct
{
    // expected global sequence
    int expected;
    // blocked one queue for packets by reorder logic
    int blocked;
    // blocking timeval instance
    struct timeval block_tv;
    // time out in case of loss for retransmission
    unsigned int loss_timeout;
    int last_reported;
    int final_loss;
    int block_loss;
} reorder_state;

// A structure to store packet
// buf :- Original packet buffer
// len:- length of packet
// fd:- associated file descriptor
// ls:- local sequence number
// tag:- timestamp

typedef struct
{
    char *buf;
    int len;
    int fd;
    int gs;
    int ls;
    struct timeval tv;
    int id;
    int Q;
    int dQ;
} my_pkt;


// A structure to store packet
// buf :- Original packet buffer
// len:- length of packet
// fd:- associated file descriptor
// time:- timestamp
typedef struct
{
    int fd;
    char *buf;
    int len;
    struct timeval time;
} my_pkt2;

// A Generic message type
typedef union
{
    loss_info_t loss_info;
    link_info_t link_info;
    ack_t ack;
} msg_t;

// Report Packets
typedef struct
{
    char tag; // 'V' to identify protocol
    char type; // to identify type of message
    msg_t info;
} report_pkt;

// Circular Queue of my_pkt2
typedef struct
{
    int start;
    int end;
    my_pkt2 at[QLEN];
} Q2;

// Circular Queue of my_pkt
typedef struct
{
    int start;
    int end;
    int fd;
    int lastrecvd;
    my_pkt at[QLEN];
} Q;

// Mux or Multiplexer Structure
typedef struct
{
    int c; // total number of packets
    int rto;
    int rtt;
    int srtt;
    int rttvar;
    struct timeval lastack_tv;
} Mux;

typedef struct
{
    char tag;
    int i;
    int stamp;
} probe_t;

#define VTUN_FD_MAYGONE 0x1

typedef struct
{
    loss_info_t li_tx;
    Q q;
    struct timeval last_tv;
    int pos;
    int lost;
    struct timeval lost_tv;
    /*NEW*/
    int wait_pos;
    int last_rcvd;
    int loss_flag;
    struct timeval loss_tv;
    unsigned long byte;
} rx_fd_state;

typedef struct
{
    int count;
    loss_info_t li_rx;
    Q q;
    int unack;
    int out_delay;
    struct timeval last_tv;
    int rto;
    /*NEW*/
    int ls;
    unsigned long byte;
} tx_fd_state;

typedef struct
{
    int fd;
    struct sockaddr_in saddr;
    struct sockaddr_in daddr;
    struct sockaddr_in caddr;
    rx_fd_state rx_fs;
    tx_fd_state tx_fs;
    int fd_flag;
    int tx_flag;
    int sock_q;
    int ifa_index;
    char *ifa_name;
    int idle_timer;
    int strict_timer;
    int rtt;
    int srtt;
    int rto;
    int rttvar;
    int test;
    int lost_count;
    int timeout_count;
    unsigned long int in_data;
    unsigned long int out_data;
    
} fd_state;

//fd_state fds[VTUN_MAX_INT];
fd_state* nextfd();
int fd_max();
fd_state* fetch_state(int fd);

#endif
