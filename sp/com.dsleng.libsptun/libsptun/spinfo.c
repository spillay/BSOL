/*
 * spinfo.c
 *
 *  Created on: 15 Nov 2015
 *      Author: suresh
 */

#include "spinfo.h"


void showFDIP(int fd,char* desc){
	 struct sockaddr_in addr;
	 char ipstr[INET_ADDRSTRLEN];

	 socklen_t addr_size = sizeof(struct sockaddr_in);
	 int res = getpeername(fd, (struct sockaddr *)&addr, &addr_size);
	 struct sockaddr_in *s = (struct sockaddr_in *) &addr;
	 inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);

	 vtun_syslog(LOG_INFO,"FD is %d IP address is %s for %s",fd,ipstr,desc);
}
