/*
 Copyright (C) 2014-2015 Stevens Institute of Tech, Hoboken NJ
 */

/*
 * $Id: netlib.c,v 1.11.2.2 2008/01/07 22:35:56 mtbishop Exp $
 */

#include "config.h"
//#include "spidernet_socks.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "netlib.h"

/*
 It selects highest priority interface in accordance to xml file
 */
int get_ctrl_index(struct vtun_host *host) {
	int i;

	for (i = 0; i < VTUN_MAX_INT; i++)
		if (host->fs[i].fd_flag == 1)
			return i;
	return 0;
}

void send_bind_req(struct vtun_host *host, int index) {
	ctrl_msg cm;
	bind_link bl;
	int i;
	int j;
	int opt;
	cm.type = BIND_REQ;
	bl.index = index;
	bl.port = 0;
	cm.bl = bl;
	j = get_ctrl_index(host);

	opt = sizeof(host->fs[j].daddr);

	sendfromto(host->ctrl, (char *) &cm, sizeof(cm), 0,
			(struct sockaddr *) &host->fs[j].saddr, opt,
			(struct sockaddr *) &host->fs[j].daddr, opt);
	host->fs[cm.bl.index].fd_flag = 0;
	vtun_syslog(LOG_ERR, "BIND REQ IS SENT %d", index);
	return;
}

void send_unbind_req(struct vtun_host *host, int index) {
	ctrl_msg cm;
	bind_link bl;
	int i;
	int j;
	int opt;
	cm.type = UNBIND_REQ;
	bl.index = index;
	bl.port = 0;
	cm.bl = bl;
	j = get_ctrl_index(host);

	opt = sizeof(host->fs[j].daddr);

	sendfromto(host->ctrl, (char *) &cm, sizeof(cm), 0,
			(struct sockaddr *) &host->fs[j].saddr, opt,
			(struct sockaddr *) &host->fs[j].daddr, opt);
	close(host->fs[index].fd);
	vtun_syslog(LOG_ERR, "UNBIND REQ IS SENT %d", index);
	return;
}
void send_flag_info(struct vtun_host *host, int ctrl) {
	ctrl_msg cm;
	fd_info my_info;
	int i;

	cm.type = FD_INFO;
	for (i = 0; i < VTUN_MAX_INT; i++) {
		my_info.flag[i] = host->fs[i].fd_flag;
	}
	cm.fi = my_info;
	i = sizeof(host->fs[ctrl].daddr);

	sendfromto(host->ctrl, (char *) &cm, sizeof(cm), 0,
			(struct sockaddr *) &host->fs[ctrl].saddr, i,
			(struct sockaddr *) &host->fs[ctrl].daddr, i);
	vtun_syslog(-1, "FLAG INFO IS SENT ");

}
int send_new_port(struct vtun_host *host, int i, int j, int ctrl_msg_type) {
	struct sockaddr_in saddr;
	short port;
	int s, opt;
	int buflen = 10;
	char buf[10];
	char ipstr[INET_ADDRSTRLEN];
	ctrl_msg cm;
	bind_link bl;

	vtun_syslog(LOG_ERR, "send_new_port creating socket for %d using %d", i, j);
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		vtun_syslog(LOG_ERR, "Can't create socket");
		return -1;
	}
	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(s, F_SETFL, O_NONBLOCK);

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(host->sport[i]);
	saddr.sin_addr.s_addr = inet_addr(host->saddr[i].ip);

	//vtun_syslog(LOG_ERR,"send_new_port bind to port");
	errno = 0;
	/*Bind a port*/
	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't bind to the socket");
		return -1;
	}

	opt = sizeof(saddr);

	//vtun_syslog(LOG_ERR,"send_new_port getsocknamei %s",strerror(errno));
	if (getsockname(s, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get socket name");
		return -1;
	}
	port = saddr.sin_port;

	opt = sizeof(host->fs[j].daddr);
	cm.type = ctrl_msg_type;
	bl.index = i;
	bl.port = port;
	cm.bl = bl;

	// vtun_syslog(LOG_ERR,"send_new_port sending");
	errno = 0;
	sendfromto(host->ctrl, (char *) &cm, sizeof(cm), 0,
			(struct sockaddr *) &host->fs[j].saddr, opt,
			(struct sockaddr *) &host->fs[j].daddr, opt);
	inet_ntop(AF_INET, &(host->fs[j].saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, "From %s:%d", ipstr,
			ntohs(host->fs[j].saddr.sin_port));
	inet_ntop(AF_INET, &(host->fs[j].daddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, "To %s:%d", ipstr, ntohs(host->fs[j].daddr.sin_port));
	vtun_syslog(LOG_ERR, "send_new_port returning %s", strerror(errno));

	return 1;
}

int fetch_control(struct vtun_host * host) {
	struct sockaddr_in saddr;
	short port;
	int s, opt;
	int buflen = 10;
	char buf[10];
	char ipstr[INET_ADDRSTRLEN];

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		vtun_syslog(LOG_ERR, "Can't create socket");
		return -1;
	}
	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(s, F_SETFL, O_NONBLOCK);

	/* Set local address and port */
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(host->ctrl_port);
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't bind to the socket");
		return -1;
	}

	opt = sizeof(saddr);
	if (getsockname(host->rmt_fd, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get socket name");
		return -1;
	}
	host->fs[0].saddr = saddr;

	if (getsockname(s, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get socket name");
		return -1;
	}

	/* if we are not just binding port number then we are server*/
	if (host->role == 1) {
		vtun_syslog(LOG_INFO, "udp_ctrl_session for server");

		/* Write port of the new UDP socket */
		port = saddr.sin_port;
		if (write_n(host->rmt_fd, (char *) &port, sizeof(short)) < 0) {
			vtun_syslog(LOG_ERR, "Can't write port number");
			return -1;
		}

		vtun_syslog(LOG_INFO, "Waiting for UDP ACK 1, wrote port %d", port);
		opt = sizeof(saddr);
		while (recvfrom(s, (char *) &port, sizeof(short), 0,
				(struct sockaddr *) &saddr, &opt) <= 0)
			;
		vtun_syslog(LOG_INFO, "UDP ACK 1 from  %s:%d",
				inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));

		host->fs[0].daddr.sin_family = saddr.sin_family;
		host->fs[0].daddr.sin_port = saddr.sin_port;
		host->fs[0].daddr.sin_addr.s_addr = saddr.sin_addr.s_addr;

		inet_ntop(AF_INET, &(host->fs[0].daddr.sin_addr), ipstr,
				INET_ADDRSTRLEN);
		vtun_syslog(LOG_INFO, "%s:%d", ipstr,
				ntohs(host->fs[0].daddr.sin_port));

		//sendto(s,(char *)&port,sizeof(short),0,(struct sockaddr *)&saddr,opt);
		errno = 0;
		sendfromto(s, (char *) &port, sizeof(short), 0,
				(struct sockaddr *) &host->fs[0].saddr, opt,
				(struct sockaddr *) &saddr, opt);

		vtun_syslog(LOG_INFO, "FINAL ACK SENT 1 %s", strerror(errno));
		inet_ntop(AF_INET, &(saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
		vtun_syslog(LOG_INFO, "%s:%d", ipstr, ntohs(saddr.sin_port));
		host->ctrl_port = ntohs(saddr.sin_port);

	} else {

		//vtun_syslog(LOG_INFO,"udp_session for client 1");
		/* Read port of the other's end UDP socket */
		if (readn_t(host->rmt_fd, (char *) &port, sizeof(short), host->timeout)
				< 0) {
			vtun_syslog(LOG_ERR, "Can't read port number %s", strerror(errno));
			return -1;
		}
		vtun_syslog(LOG_INFO, "Recieved port %d info from server 1", port);
		opt = sizeof(saddr);
		if (getpeername(host->rmt_fd, (struct sockaddr *) &saddr, &opt)) {
			vtun_syslog(LOG_ERR, "Can't get peer name");
			return -1;
		}

		saddr.sin_port = port;

		inet_ntop(AF_INET, &(saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
		vtun_syslog(LOG_INFO, "%s:%d", ipstr, ntohs(saddr.sin_port));
		inet_ntop(AF_INET, &(host->fs[0].saddr.sin_addr), ipstr,
				INET_ADDRSTRLEN);
		vtun_syslog(LOG_INFO, "%s:%d", ipstr,
				ntohs(host->fs[0].saddr.sin_port));
		errno = 0;
		sendfromto(s, (char *) &port, sizeof(short), 0,
				(struct sockaddr *) &host->fs[0].saddr, opt,
				(struct sockaddr *) &saddr, opt);
		vtun_syslog(LOG_INFO, "Sent ACK on UDP 1 :%s", strerror(errno));
		host->fs[0].daddr = saddr;
		while (recvfrom(s, (char *) &port, sizeof(short), 0,
				(struct sockaddr *) &saddr, &opt) <= 0)
			;
		vtun_syslog(LOG_INFO, "Connected & Recived final ACK 1");
		inet_ntop(AF_INET, &(saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
		vtun_syslog(LOG_INFO, "%s:%d", ipstr, ntohs(saddr.sin_port));
		host->ctrl_port = ntohs(saddr.sin_port);

	}
	return s;
}

int fetch_server_data(struct vtun_host *host, int i, int j) {
	struct sockaddr_in saddr;
	short port;
	int s, opt;
	int buflen = 10;
	char buf[10];
	char ipstr[INET_ADDRSTRLEN];
	opt = sizeof(saddr);
	vtun_syslog(LOG_ERR, "Wait for response from client on Control");
	/*Wait for response from client on Control*/
	while (recvfrom(host->ctrl, (char *) &port, sizeof(short), 0,
			(struct sockaddr *) &saddr, &opt) <= 0)
		;

	inet_ntop(AF_INET, &(saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, "recvfrom %s:%d", ipstr, ntohs(saddr.sin_port));

	/*Open a UDP socket*/
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		vtun_syslog(LOG_ERR, "Can't create socket");
		return -1;
	}
	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(s, F_SETFL, O_NONBLOCK);

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(host->sport[i]);
	vtun_syslog(LOG_INFO, "trying to bind");
	vtun_syslog(LOG_INFO, "%d %s", i, host->saddr[i].ip);
	saddr.sin_addr.s_addr = inet_addr(host->saddr[i].ip);
	vtun_syslog(LOG_ERR, "Binding with %s", host->saddr[i].ip);
	/*Bind a port*/
	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't bind to the socket");
		host->fs[i].fd_flag = 0;
		return -1;
	}
	host->fs[i].saddr = saddr;
	inet_ntop(AF_INET, &(host->fs[i].saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, "saddr %s:%d", ipstr, ntohs(saddr.sin_port));
	opt = sizeof(saddr);

	if (getsockname(s, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get socket name");
		return -1;
	}
	port = saddr.sin_port;

	vtun_syslog(LOG_ERR, "Send port number to Client on Control");
	/*Send port number to Client on Control*/
	opt = sizeof(host->fs[j].daddr);
	saddr = host->fs[j].daddr;
	saddr.sin_port = htons(host->ctrl_port);
	inet_ntop(AF_INET, &(saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, "%s:%d", ipstr, ntohs(saddr.sin_port));

	inet_ntop(AF_INET, &(host->fs[j].saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, "%s:%d", ipstr, ntohs(host->fs[j].saddr.sin_port));
	errno = 0;
	sendfromto(host->ctrl, (char *) &port, sizeof(short), 0,
			(struct sockaddr *) &host->fs[j].saddr, opt,
			(struct sockaddr *) &saddr, opt);

	/*Wait for PING on new Data Path*/
	vtun_syslog(LOG_ERR, "Wait for PING on new Control Path %s port %d",
			strerror(errno), port);
	while (recvfrom(s, (char *) &port, sizeof(short), 0,
			(struct sockaddr *) &saddr, &opt) <= 0)
		;
	host->fs[i].daddr = saddr;
	if (connect(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't connect socket");
		return -1;
	}
	host->fs[i].fd_flag = 1;
	host->fs[i].fd = s;
	port = 0;
	errno = 0;
	vtun_syslog(LOG_ERR, "Sent PONG on new Control Path");
	write_n(host->fs[i].fd, (char*) &port, sizeof(short));
	vtun_syslog(LOG_ERR, "WAIT PONG on new Control Path %s", strerror(errno));

	while (readn_t(host->fs[i].fd, (char*) &port, sizeof(short), host->timeout)
			< 0)
		;
	vtun_syslog(LOG_ERR, "%s", strerror(errno));
	/*SEND END_OF_REG*/
	return 0;
}
int fetch_client_data(struct vtun_host *host, int i, int j) {
	struct sockaddr_in saddr;
	short port;
	int s, opt;
	int buflen = 10;
	char buf[10];
	char ipstr[INET_ADDRSTRLEN];

	/*Open a UDP socket*/
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		vtun_syslog(LOG_ERR, "Can't create socket");
		return -1;
	}
	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(s, F_SETFL, O_NONBLOCK);

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(host->sport[i]);
	saddr.sin_addr.s_addr = inet_addr(host->saddr[i].ip);

	vtun_syslog(LOG_ERR, "Binding with %s", host->saddr[i].ip);
	/*Bind a port*/
	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't bind to the socket");
		return -1;
	}
	host->fs[i].saddr = saddr;
	opt = sizeof(saddr);

	if (getsockname(s, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get socket name");
		return -1;
	}
	port = saddr.sin_port;

	/*Send port number to Server on Control*/
	opt = sizeof(host->fs[j].daddr);
	saddr.sin_port = htons(host->ctrl_port);
	inet_ntop(AF_INET, &(saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, "%s:%d", ipstr, ntohs(saddr.sin_port));

	inet_ntop(AF_INET, &(host->fs[j].saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, "%s:%d", ipstr, ntohs(host->fs[j].saddr.sin_port));
	inet_ntop(AF_INET, &(host->fs[j].daddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, "%s:%d", ipstr, ntohs(host->fs[j].daddr.sin_port));
	errno = 0;
	sendfromto(host->ctrl, (char *) &port, sizeof(short), 0,
			(struct sockaddr*) &host->fs[j].saddr, opt,
			(struct sockaddr *) &host->fs[j].daddr, opt);
	vtun_syslog(LOG_ERR, "Send port number to Server on Control %s",
			strerror(errno));
	/*Wait for response from server on Control*/
	while (recvfrom(host->ctrl, (char *) &port, sizeof(short), 0,
			(struct sockaddr *) &saddr, &opt) <= 0){

		vtun_syslog(LOG_ERR, "waiting for response");
	}


	//saddr.sin_port = htons(port);
	saddr.sin_port = port;
	opt = sizeof(saddr);
	/*Send PING on new Data Path*/
	inet_ntop(AF_INET, &(saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, "%s:%d", ipstr, ntohs(saddr.sin_port));
	errno = 0;
	vtun_syslog(LOG_ERR, "Send PING on new Control Paths");
	sendto(s, (char *) &port, sizeof(short), 0, (struct sockaddr *) &saddr,
			opt);
	vtun_syslog(LOG_ERR, "Wait PONG on new Control Path %s", strerror(errno));
	/*Wait for PONG on new Data Path*/
	while (recvfrom(s, (char *) &port, sizeof(short), 0,
			(struct sockaddr *) &saddr, &opt) <= 0)
		;
	host->fs[i].daddr = saddr;
	host->fs[i].daddr.sin_port = htons(host->ctrl_port);
	if (connect(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't connect socket");
		return -1;
	}
	host->fs[i].fd_flag = 1;
	host->fs[i].fd = s;
	port = 0;
	vtun_syslog(LOG_ERR, "Sent PONG on new Control Path");
	errno = 0;
	write_n(host->fs[i].fd, (char*) &port, sizeof(short));
	vtun_syslog(LOG_ERR, "%s", strerror(errno));
	/*SEND END_OF_REG*/
	return 0;
}

/* Connect with timeout */
int connect_t(int s, struct sockaddr *svr, time_t timeout) {
#if defined(SPIDERNET_SOCKS) && SPIDERNET_SOCKS == 2
	/* Some SOCKS implementations don't support
	 * non blocking connect */
	return connect(s,svr,sizeof(struct sockaddr));
#else
	int sock_flags;
	fd_set fdset;
	struct timeval tv;

	tv.tv_usec = 0;
	tv.tv_sec = timeout;

	sock_flags = fcntl(s, F_GETFL);
	if (fcntl(s, F_SETFL, O_NONBLOCK) < 0)
		return -1;

	if (connect(s, svr, sizeof(struct sockaddr)) < 0 && errno != EINPROGRESS)
		return -1;

	FD_ZERO(&fdset);
	FD_SET(s, &fdset);
	if (select(s + 1, NULL, &fdset, NULL, timeout ? &tv : NULL) > 0) {
		int l = sizeof(errno);
		errno = 0;
		getsockopt(s, SOL_SOCKET, SO_ERROR, &errno, &l);
	} else
		errno = ETIMEDOUT;

	fcntl(s, F_SETFL, sock_flags);

	if ( errno)
		return -1;

	return 0;
#endif
}

/* Get interface address */
unsigned long getifaddr(char * ifname) {
	struct sockaddr_in addr;
	struct ifreq ifr;
	int s;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return -1;

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		close(s);
		return -1;
	}
	close(s);

	addr = *((struct sockaddr_in *) &ifr.ifr_addr);

	return addr.sin_addr.s_addr;
}

/*
 * Establish UDP session with host connected to fd(socket).
 * Returns connected UDP socket or -1 on error.
 */
int udp_session(struct vtun_host *host) {
	struct sockaddr_in saddr;
	short port;
	int s, opt;
	int buflen = 10;
	char buf[10];
	char ipstr[INET_ADDRSTRLEN];
	vtun_syslog(LOG_INFO, "UDP connection initialized %d,%d", host->rmt_fd,
			host->rmt_fd2);
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		vtun_syslog(LOG_ERR, "Can't create socket");
		return -1;
	}
	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(s, F_SETFL, O_NONBLOCK);

	/* Set local address and port */
	local_addr(&saddr, host, 1);
	saddr.sin_port = htons(host->sport[0]);
	saddr.sin_addr.s_addr = inet_addr(host->saddr[0].ip);
	errno = 0;
	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't bind to the socket %s (%s:%d)",
				strerror(errno), host->saddr[0].ip, host->sport[0]);
		return -1;
	}

	opt = sizeof(saddr);
	if (getsockname(s, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get socket name");
		return -1;
	}
	host->fs[0].saddr = saddr;
	/* if we are not just binding port number then we are server*/
	if (host->role == 1) {
		vtun_syslog(LOG_INFO, "udp_session for server 1");
		/* Write port of the new UDP socket */
		port = saddr.sin_port;
		if (write_n(host->rmt_fd, (char *) &port, sizeof(short)) < 0) {
			vtun_syslog(LOG_ERR, "Can't write port number");
			return -1;
		}
		vtun_syslog(LOG_INFO, "Waiting for UDP ACK 1, wrote port %d", port);
		opt = sizeof(saddr);
		while (recvfrom(s, (char *) &port, sizeof(short), 0,
				(struct sockaddr *) &saddr, &opt) <= 0)
			;
		vtun_syslog(LOG_INFO, "UDP ACK 1 from  %s:%d",
				inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));

		host->fs[0].daddr.sin_family = saddr.sin_family;
		host->fs[0].daddr.sin_port = saddr.sin_port;
		host->fs[0].daddr.sin_addr.s_addr = saddr.sin_addr.s_addr;

		inet_ntop(AF_INET, &(host->fs[0].daddr.sin_addr), ipstr,
				INET_ADDRSTRLEN);
		vtun_syslog(LOG_INFO, "%s:%d", ipstr,
				ntohs(host->fs[0].daddr.sin_port));

		if (connect(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
			vtun_syslog(LOG_ERR, "Can't connect socket");
			return -1;
		}

		write_n(s, (char *) &port, sizeof(short));
		vtun_syslog(LOG_INFO, "FINAL ACK SENT 1");

	} else {

		//vtun_syslog(LOG_INFO,"udp_session for client 1");
		/* Read port of the other's end UDP socket */
		if (readn_t(host->rmt_fd, (char *) &port, sizeof(short), host->timeout)
				< 0) {
			vtun_syslog(LOG_ERR, "Can't read port number %s", strerror(errno));
			return -1;
		}
		vtun_syslog(LOG_INFO, "Recieved port %d info from server 1", port);
		opt = sizeof(saddr);
		if (getpeername(host->rmt_fd, (struct sockaddr *) &saddr, &opt)) {
			vtun_syslog(LOG_ERR, "Can't get peer name");
			return -1;
		}

		saddr.sin_port = port;
		sendto(s, (char *) &port, sizeof(short), 0, (struct sockaddr *) &saddr,
				opt);
		vtun_syslog(LOG_INFO, "Sent ACK on UDP 1");
		host->fs[0].daddr = saddr;
		if (connect(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
			vtun_syslog(LOG_ERR, "Can't connect socket");
			return -1;
		}

		read_n(s, (char *) &port, sizeof(short));
		vtun_syslog(LOG_INFO, "Connected & Recived final ACK 1");
	}
	/* Why we need this ??*/
	host->sopt.rport = htons(port);
	host->rmt_sock = saddr;
	/* Close TCP socket and replace with UDP socket */
	close(host->rmt_fd);
	host->rmt_fd = s;
	//add by Kai for multiple interfaces
	// host->fs[0].daddr = saddr;

	host->fs[0].fd = s;
	host->fs[0].fd_flag = 1;

	s = 0;
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		vtun_syslog(LOG_ERR, "Can't create socket");
		return -1;
	}

	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(s, F_SETFL, O_NONBLOCK);
	/* Set local address and port */
	local_addr(&saddr, host, 1);
	saddr.sin_port = htons(host->sport[1]);
	saddr.sin_addr.s_addr = inet_addr(host->saddr[1].ip);
	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't bind to the socket");
		return -1;
	}

	opt = sizeof(saddr);
	if (getsockname(s, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get socket name");
		return -1;
	}
	host->fs[1].saddr = saddr;
	/* if we are not just binding port number then we are server*/
	//if(saddr.sin_addr.s_addr == inet_addr("0.0.0.0")){
	if (host->role == 1) {
		vtun_syslog(LOG_INFO, "udp_session for server 2");
		/* Write port of the new UDP socket */
		port = saddr.sin_port;
		if (write_n(host->rmt_fd2, (char *) &port, sizeof(short)) < 0) {
			vtun_syslog(LOG_ERR, "Can't write port number");
			return -1;
		}
		vtun_syslog(LOG_INFO, "Waiting for UDP ACK 2 wrote port %d", port);
		opt = sizeof(saddr);
		while (recvfrom(s, (char *) &port, sizeof(short), 0,
				(struct sockaddr *) &saddr, &opt) <= 0)
			;
		vtun_syslog(LOG_INFO, "UDP ACK 2 from  %s:%d",
				inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));
		host->fs[1].daddr.sin_family = saddr.sin_family;
		host->fs[1].daddr.sin_port = saddr.sin_port;
		host->fs[1].daddr.sin_addr.s_addr = saddr.sin_addr.s_addr;

		inet_ntop(AF_INET, &(host->fs[1].daddr.sin_addr), ipstr,
				INET_ADDRSTRLEN);
		vtun_syslog(LOG_INFO, "%s:%d", ipstr,
				ntohs(host->fs[1].daddr.sin_port));

		if (connect(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
			vtun_syslog(LOG_ERR, "Can't connect socket");
			return -1;
		}
		write_n(s, (char *) &port, sizeof(short));
		vtun_syslog(LOG_INFO, "FINAL ACK SENT 2");
	} else {
		vtun_syslog(LOG_INFO, "udp_session for client 2");
		/* Read port of the other's end UDP socket */
		if (readn_t(host->rmt_fd2, (char *) &port, sizeof(short), host->timeout)
				< 0) {
			vtun_syslog(LOG_ERR, "Can't read port number %s", strerror(errno));
			return -1;
		}
		opt = sizeof(saddr);
		if (getpeername(host->rmt_fd2, (struct sockaddr *) &saddr, &opt)) {
			vtun_syslog(LOG_ERR, "Can't get peer name");
			return -1;
		}

		saddr.sin_port = port;
		vtun_syslog(LOG_INFO, "Recieved port %d info from server 2", port);
		sendto(s, (char *) &port, sizeof(short), 0, (struct sockaddr *) &saddr,
				opt);
		host->fs[1].daddr = saddr;
		if (connect(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
			vtun_syslog(LOG_ERR, "Can't connect socket");
			return -1;
		}

		read_n(s, (char *) &port, sizeof(short));
		vtun_syslog(LOG_INFO, "Connected & Recived final ACK 2");
	}
	host->rmt_sock2 = saddr;
	/* Close TCP socket and replace with UDP socket */
	close(host->rmt_fd2);
	host->rmt_fd2 = s;
	//add by Kai for multiple interfaces
	host->fs[1].fd = s;
	host->fs[1].fd_flag = 1;
	inet_ntop(AF_INET, &(host->fs[0].saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, " fd is %s:%d ->", ipstr,
			ntohs(host->fs[0].saddr.sin_port));
	inet_ntop(AF_INET, &(host->fs[0].daddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, " fd is %s:%d <-", ipstr,
			ntohs(host->fs[0].daddr.sin_port));
	inet_ntop(AF_INET, &(host->fs[1].saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, " fd is %s:%d ->", ipstr,
			ntohs(host->fs[1].saddr.sin_port));
	inet_ntop(AF_INET, &(host->fs[1].daddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, " fd is %s:%d <-", ipstr,
			ntohs(host->fs[1].daddr.sin_port));
	host->fs[0].saddr.sin_port = htons(4444);
	host->fs[0].daddr.sin_port = htons(4444);
	host->fs[1].saddr.sin_port = htons(4444);
	host->fs[1].daddr.sin_port = htons(4444);
	/*
	 host->fs[0].saddr.sin_port = htons(host->dport[1]+10);
	 host->fs[0].daddr.sin_port = htons(host->dport[1]+10);
	 host->fs[1].saddr.sin_port = htons(host->dport[1]+10);
	 host->fs[1].daddr.sin_port = htons(host->dport[1]+10);
	 */
	inet_ntop(AF_INET, &(host->fs[0].saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, " fd is %s:%d ->", ipstr,
			ntohs(host->fs[0].saddr.sin_port));
	inet_ntop(AF_INET, &(host->fs[0].daddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, " fd is %s:%d <-", ipstr,
			ntohs(host->fs[0].daddr.sin_port));
	inet_ntop(AF_INET, &(host->fs[1].saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, " fd is %s:%d ->", ipstr,
			ntohs(host->fs[1].saddr.sin_port));
	inet_ntop(AF_INET, &(host->fs[1].daddr.sin_addr), ipstr, INET_ADDRSTRLEN);
	vtun_syslog(LOG_INFO, " fd is %s:%d <-", ipstr,
			ntohs(host->fs[1].daddr.sin_port));
	vtun_syslog(LOG_INFO, "UDP connection initialized");
	return s;
}

int udp_session2(struct vtun_host *host) {
	struct sockaddr_in saddr;
	short port;
	int s, opt;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		vtun_syslog(LOG_ERR, "Can't create socket");
		return -1;
	}

	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(s, F_SETFL, O_NONBLOCK);
	/* Set local address and port */
	local_addr(&saddr, host, 1);
	saddr.sin_port = host->sport[0];
	saddr.sin_addr.s_addr = inet_addr(host->saddr[0].ip);
	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't bind to the socket %s", strerror(errno));
		return -1;
	}

	opt = sizeof(saddr);
	if (getsockname(s, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get socket name");
		return -1;
	}

	/* Write port of the new UDP socket */
	port = saddr.sin_port;
	if (write_n(host->rmt_fd, (char *) &port, sizeof(short)) < 0) {
		vtun_syslog(LOG_ERR, "Can't write port number");
		return -1;
	}
	host->sopt.lport = htons(port);

	/* Read port of the other's end UDP socket */
	if (readn_t(host->rmt_fd, &port, sizeof(short), host->timeout) < 0) {
		vtun_syslog(LOG_ERR, "Can't read port number %s", strerror(errno));
		return -1;
	}

	opt = sizeof(saddr);
	if (getpeername(host->rmt_fd, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get peer name");
		return -1;
	}

	saddr.sin_port = port;
	if (connect(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't connect socket");
		return -1;
	}
	host->sopt.rport = htons(port);
	host->rmt_sock = saddr;
	/* Close TCP socket and replace with UDP socket */
	close(host->rmt_fd);
	host->rmt_fd = s;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		vtun_syslog(LOG_ERR, "Can't create socket2");
		return -1;
	}

	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(s, F_SETFL, O_NONBLOCK);

	/* Set local address and port */
	saddr.sin_port = host->sport[1];
	saddr.sin_addr.s_addr = inet_addr(host->saddr[1].ip);

	vtun_syslog(LOG_ERR, "address %s:%d", host->saddr[0].ip, host->sport[0]);
	vtun_syslog(LOG_ERR, "address %s:%d", host->saddr[1].ip, host->sport[1]);
	vtun_syslog(LOG_ERR, "address %s:%d", inet_ntoa(saddr.sin_addr),
			ntohs(saddr.sin_port));
	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't bind to the socket2 (%d:%s)", errno,
				strerror(errno));
		return -1;
	}

	saddr.sin_port = host->dport[1];
	saddr.sin_addr.s_addr = inet_addr(host->daddr[1].ip);
	if (connect(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't connect socket2 ");
		return -1;
	}
	host->rmt_sock2 = saddr;
	host->rmt_fd2 = s;

	//vtun.rmt_sock2 = saddr;
	//vtun.rmt_fd2 = s;
	vtun_syslog(LOG_INFO, "UDP connection initialized");
	return s;
}
//add by adonis for multiple interfaces
int udp_session_fs0(struct vtun_host *host) {
	struct sockaddr_in saddr;
	short port;
	int s, opt;
	vtun_syslog(LOG_ERR, "in udp_session_fs0");
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		vtun_syslog(LOG_ERR, "Can't create socket");
		return -1;
	}

	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(s, F_SETFL, O_NONBLOCK);
	/* Set local address and port */

	vtun_syslog(LOG_ERR, "in local_addr");
	local_addr(&saddr, host, 1);
	vtun_syslog(LOG_ERR, "after local_addr");
	vtun_syslog(LOG_ERR, "debug %d", host->sport[0]);
	vtun_syslog(LOG_ERR, "debug %d, %s", host->sport[0], host->saddr[0].ip);
	saddr.sin_port = host->sport[0];
	saddr.sin_addr.s_addr = inet_addr(host->saddr[0].ip);
	vtun_syslog(LOG_ERR, "before bind");
	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't bind to the socket %s", strerror(errno));
		return -1;
	}

	opt = sizeof(saddr);
	if (getsockname(s, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get socket name");
		return -1;
	}

	vtun_syslog(LOG_ERR, "after bind");
	/* Write port of the new UDP socket */
	port = saddr.sin_port;
	if (write_n(host->rmt_fd, (char *) &port, sizeof(short)) < 0) {
		vtun_syslog(LOG_ERR, "Can't write port number");
		return -1;
	}
	host->sopt.lport = htons(port);

	vtun_syslog(LOG_ERR, "after port ex send");
	/* Read port of the other's end UDP socket */
	if (readn_t(host->rmt_fd, &port, sizeof(short), host->timeout) < 0) {
		vtun_syslog(LOG_ERR, "Can't read port number %s", strerror(errno));
		return -1;
	}

	vtun_syslog(LOG_ERR, "after port ex recv");
	opt = sizeof(saddr);
	if (getpeername(host->rmt_fd, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get peer name");
		return -1;
	}

	saddr.sin_port = port;
	if (connect(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't connect socket");
		return -1;
	}
	host->sopt.rport = htons(port);
	host->rmt_sock = saddr;
	/* Close TCP socket and replace with UDP socket */
	close(host->rmt_fd);
	host->rmt_fd = s;
	//add by Kai for multiple interfaces
	host->fs[0].saddr = saddr;
	host->fs[0].fd = s;
	host->fs[0].fd_flag = 1;
	//end add

	vtun_syslog(LOG_INFO, "UDP 0 connection initialized");
	return s;
}
//add by adonis for multiple interfaces
int udp_session_fs1(struct vtun_host *host) {
	struct sockaddr_in saddr;
	short port;
	int s, opt;
	vtun_syslog(LOG_ERR, "in udp_session_fs1");
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		vtun_syslog(LOG_ERR, "Can't create socket");
		return -1;
	}

	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(s, F_SETFL, O_NONBLOCK);
	/* Set local address and port */

	vtun_syslog(LOG_ERR, "in local_addr");
	local_addr(&saddr, host, 1);
	vtun_syslog(LOG_ERR, "after local_addr");
	vtun_syslog(LOG_ERR, "debug %d", host->sport[1]);
	vtun_syslog(LOG_ERR, "debug %d, %s", host->sport[1], host->saddr[1].ip);
	saddr.sin_port = host->sport[1];
	saddr.sin_addr.s_addr = inet_addr(host->saddr[1].ip);
	vtun_syslog(LOG_ERR, "before bind");
	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't bind to the socket %s", strerror(errno));
		return -1;
	}

	opt = sizeof(saddr);
	if (getsockname(s, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get socket name");
		return -1;
	}

	vtun_syslog(LOG_ERR, "after bind");
	/* Write port of the new UDP socket */
	port = saddr.sin_port;
	if (write_n(host->rmt_fd2, (char *) &port, sizeof(short)) < 0) {
		vtun_syslog(LOG_ERR, "Can't write port number");
		return -1;
	}
	host->sopt.lport = htons(port);

	vtun_syslog(LOG_ERR, "after port ex send");
	/* Read port of the other's end UDP socket */
	if (readn_t(host->rmt_fd2, &port, sizeof(short), host->timeout) < 0) {
		vtun_syslog(LOG_ERR, "Can't read port number %s", strerror(errno));
		return -1;
	}

	vtun_syslog(LOG_ERR, "after port ex recv");
	opt = sizeof(saddr);
	if (getpeername(host->rmt_fd2, (struct sockaddr *) &saddr, &opt)) {
		vtun_syslog(LOG_ERR, "Can't get peer name");
		return -1;
	}

	saddr.sin_port = port;
	if (connect(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't connect socket");
		return -1;
	}
	host->sopt.rport = htons(port);
	host->rmt_sock2 = saddr;
	/* Close TCP socket and replace with UDP socket */
	close(host->rmt_fd2);
	host->rmt_fd2 = s;
	//add by Kai for multiple interfaces
	host->fs[1].saddr = saddr;
	host->fs[1].fd = s;
	host->fs[1].fd_flag = 1;
	//end add

	vtun_syslog(LOG_INFO, "UDP 1 connection initialized");
	return s;
}

int udp_session_fs(struct vtun_host *host, int count) {
	struct sockaddr_in saddr;
	short port;
	int s, opt;
	saddr.sin_family = AF_INET;
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		vtun_syslog(LOG_ERR, "Can't create socket %d", count);
		return -1;
	}

	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(s, F_SETFL, O_NONBLOCK);

	/* Set local address and port */
	saddr.sin_port = host->sport[count];
	saddr.sin_addr.s_addr = inet_addr(host->saddr[count].ip);

	vtun_syslog(LOG_ERR, "address %s:%d", host->saddr[count].ip,
			host->sport[count]);
	vtun_syslog(LOG_ERR, "address %s:%d", inet_ntoa(saddr.sin_addr),
			ntohs(saddr.sin_port));

	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't bind to the socket (%d:%s)", errno,
				strerror(errno));
		return -1;
	}

	saddr.sin_port = host->dport[count];
	saddr.sin_addr.s_addr = inet_addr(host->daddr[count].ip);
	if (connect(s, (struct sockaddr *) &saddr, sizeof(saddr))) {
		vtun_syslog(LOG_ERR, "Can't connect socket %d ", count);
		return -1;
	}
	host->fs[count].saddr = saddr;
	host->fs[count].fd = s;
	host->fs[count].fd_flag = 1;

	vtun_syslog(LOG_INFO, "UDP %d connection initialized", count);
	return s;
}

/* Set local address */
int local_addr(struct sockaddr_in *addr, struct vtun_host *host, int con) {
	int opt;

	if (con) {
		/* Use address of the already connected socket. */
		opt = sizeof(struct sockaddr_in);
		if (getsockname(host->rmt_fd, (struct sockaddr *) addr, &opt) < 0) {
			vtun_syslog(LOG_ERR, "Can't get local socket address");
			return -1;
		}
	} else {
		if (generic_addr(addr, &host->src_addr) < 0)
			return -1;
	}

	host->sopt.laddr = strdup(inet_ntoa(addr->sin_addr));

	return 0;
}

int server_addr(struct sockaddr_in *addr, struct vtun_host *host) {
	struct hostent * hent;

	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(vtun.bind_addr.port);

	/* Lookup server's IP address.
	 * We do it on every reconnect because server's IP
	 * address can be dynamic.
	 */
	if (!(hent = gethostbyname(vtun.svr_name))) {
		vtun_syslog(LOG_ERR, "Can't resolv server address: %s", vtun.svr_name);
		return -1;
	}
	addr->sin_addr.s_addr = *(unsigned long *) hent->h_addr;

	host->sopt.raddr = strdup(inet_ntoa(addr->sin_addr));
	host->sopt.rport = vtun.bind_addr.port;

	return 0;
}

/* Set address by interface name, ip address or hostname */
int generic_addr(struct sockaddr_in *addr, struct vtun_addr *vaddr) {
	struct hostent *hent;
	memset(addr, 0, sizeof(struct sockaddr_in));

	addr->sin_family = AF_INET;

	switch (vaddr->type) {
	case VTUN_ADDR_IFACE:
		if (!(addr->sin_addr.s_addr = getifaddr(vaddr->name))) {
			vtun_syslog(LOG_ERR, "Can't get address of interface %s",
					vaddr->name);
			return -1;
		}
		break;
	case VTUN_ADDR_NAME:
		if (!(hent = gethostbyname(vaddr->name))) {
			vtun_syslog(LOG_ERR, "Can't resolv local address %s", vaddr->name);
			return -1;
		}
		addr->sin_addr.s_addr = *(unsigned long *) hent->h_addr;
		break;
		default:
		addr->sin_addr.s_addr = INADDR_ANY;
		break;
	}

	if (vaddr->port)
		addr->sin_port = htons(vaddr->port);

	return 0;
}
