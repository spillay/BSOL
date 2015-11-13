/*
    Copyright (C) 2014-2015 Stevens Institute of Tech, Hoboken NJ
 */

/*
 * $Id: tunnel.c,v 1.14.2.2 2008/01/07 22:36:03 mtbishop Exp $
 */

#include "config.h"

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
#include <signal.h>
#include <ifaddrs.h>
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

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"
#include "netlib.h"
#include "driver.h"

//add by adonis for multiple interfaces
#include "conf_parse.h"

int (*dev_write)(int fd, char *buf, int len);
int (*dev_read)(int fd, char *buf, int len);

int (*proto_write)(int fd, char *buf, int len);
int (*proto_read)(int fd, char *buf);
void fetch_ip(struct ifaddrs *ifaddr,char* inf_name, char *ip_str)
{
        struct ifaddrs *ifa;
        struct sockaddr_in *saddr;
        int found = 0;
 
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		saddr = (struct sockaddr_in *)ifa->ifa_addr;
		if((ifa->ifa_addr !=NULL)&&(strcmp(inf_name,ifa->ifa_name)==0)&&(ifa->ifa_addr->sa_family ==AF_INET)){
			inet_ntop(AF_INET, &(saddr->sin_addr), ip_str, INET_ADDRSTRLEN);
			found = 1;
		}
        }
	if (found==0)
		ip_str = NULL;
	return;
}
void fill_ip_src(struct vtun_host *host){
	struct ifaddrs *ifaddr;
	char ip_str[INET_ADDRSTRLEN];
        char inf_str[32];
        int i;
	if (getifaddrs(&ifaddr) == -1) {
		vtun_syslog(LOG_ERR,"getifaddrs");
		exit(EXIT_FAILURE);
	}
        host->fscount =0;
        for(i =0; i < VTUN_MAX_INT; i++){
		host->fs[i].fd_flag =0;
        	if_indextoname(host->fs[i].ifa_index,inf_str);
        	if(inf_str!=NULL && host->fs[i].ifa_index!=0){
                        
			fetch_ip(ifaddr,inf_str,ip_str);
                        vtun_syslog(LOG_INFO,"%d %s -> %s",host->fs[i].ifa_index,inf_str, ip_str);
                        host->saddr[i].ip = strdup(ip_str);
        		host->fscount ++;
		        host->fs[i].fd_flag =1;
                 }
                 
	}
	return;
}
/* Initialize and start the tunnel.
   Returns:
      -1 - critical error
      0  - normal close or noncritical error
*/
void fill_host(struct vtun_host *host)
{
//CHANGE HERE
    //host->saddr[0].ip = strdup("192.168.2.120");
    host->saddr[0].ip = strdup("0.0.0.0");
    //host->saddr[1].ip = strdup("10.162.172.1");
    host->saddr[1].ip = strdup("0.0.0.0");
    host->sport[0] = 4887;
    host->sport[1] = 4888;
    host->daddr[0].ip = strdup("155.246.74.98");
    host->daddr[1].ip = strdup("155.246.74.98");
    //host->daddr[0].ip = strdup("23.22.170.14");
    //host->daddr[1].ip = strdup("23.22.170.14");
    host->dport[0] = 5887;
    host->dport[1] = 5888;


    /** //CHANGE HERE
            host->saddr[0].ip = strdup("192.168.2.83");
            host->saddr[1].ip = strdup("192.168.2.84");
            host->sport[0] = 4987;
            host->sport[1] = 4988;
            host->daddr[0].ip = strdup("192.168.2.98");
            host->daddr[1].ip = strdup("192.168.2.99");
            host->dport[0] = 4987;
            host->dport[1] = 4988;
    */
    return ;

}

int tunnel(struct vtun_host *host)
{
    int null_fd, pid, opt;
    int fd[2]= {-1, -1};
    char dev[VTUN_DEV_LEN]="";
    int interface_already_open = 0;
    int i;
    //modify by adonis for multiple interfaces
    //fill_host(host);
    vtun_syslog(LOG_INFO,"In tunnel");
    //conf_parse(host);

    if(host->role == 0)
    	fill_ip_src(host);
    for(i =0 ; i<VTUN_MAX_INT; i++)
    	vtun_syslog(LOG_INFO," %s:%d=>%s:%d",host->saddr[i].ip,host->sport[i],host->daddr[i].ip,host->dport[i]);   

    char ipstr[INET_ADDRSTRLEN];
    char ipstr2[INET_ADDRSTRLEN];
    for(i =0 ; i< VTUN_MAX_INT; i++){
        if(host->fs[i].fd_flag ==1){
            inet_ntop(AF_INET, &(host->fs[i].daddr.sin_addr), ipstr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(host->fs[i].saddr.sin_addr), ipstr2, INET_ADDRSTRLEN);
    		vtun_syslog(LOG_ERR,"fd  %s %s=>%s",strerror(errno),ipstr2,ipstr);
        }
    }

    vtun_syslog(LOG_INFO,"After XML");
    if ( (host->persist == VTUN_PERSIST_KEEPIF) &&
            (host->loc_fd >= 0) )
        interface_already_open = 1;

    /* Initialize device. */
    if( host->dev )
    {
        strncpy(dev, host->dev, VTUN_DEV_LEN);
        dev[VTUN_DEV_LEN-1]='\0';
    }
    if( ! interface_already_open )
    {
        switch( host->flags & VTUN_TYPE_MASK )
        {
        case VTUN_TTY:
            if( (fd[0]=pty_open(dev)) < 0 )
            {
                vtun_syslog(LOG_ERR,"Can't allocate pseudo tty. %s(%d)", strerror(errno), errno);
                return -1;
            }
            break;

        case VTUN_PIPE:
            if( pipe_open(fd) < 0 )
            {
                vtun_syslog(LOG_ERR,"Can't create pipe. %s(%d)", strerror(errno), errno);
                return -1;
            }
            break;

        case VTUN_ETHER:
            if( (fd[0]=tap_open(dev)) < 0 )
            {
                vtun_syslog(LOG_ERR,"Can't allocate tap device %s. %s(%d)", dev, strerror(errno), errno);
                return -1;
            }
            break;

        case VTUN_TUN:
            if( (fd[0]=tun_open(dev)) < 0 )
            {
                vtun_syslog(LOG_ERR,"Can't allocate tun device %s. %s(%d)", dev, strerror(errno), errno);
                return -1;
            }
            break;
        }
        host->loc_fd = fd[0];
    }
    host->sopt.dev = strdup(dev);

    vtun_syslog(LOG_INFO,"After  dev init");
    /* Initialize protocol. */
    switch( host->flags & VTUN_PROT_MASK )
    {
    case VTUN_TCP:
        opt=1;
        setsockopt(host->rmt_fd,SOL_SOCKET,SO_KEEPALIVE,&opt,sizeof(opt) );

        opt=1;
        setsockopt(host->rmt_fd,IPPROTO_TCP,TCP_NODELAY,&opt,sizeof(opt) );

        proto_write = tcp_write;
        proto_read  = tcp_read;

        break;

    case VTUN_UDP:
        
/*
        for (i=1; i< host->fscount; i++)
        {
            if( (opt = udp_session_fs(host, i)) == -1)
            {
                vtun_syslog(LOG_ERR,"Can't establish UDP session %d", i);
                close(fd[1]);
                if( ! ( host->persist == VTUN_PERSIST_KEEPIF ) )
                    close(fd[0]);
                return 0;
            }
        }
*/
        //end modify
        proto_write = udp_write;
        proto_read = udp_read;

        break;
    }
    vtun_syslog(LOG_INFO,"After Protocal init");
    switch( (pid=fork()) )
    {
    case -1:
        vtun_syslog(LOG_ERR,"Couldn't fork()");
        if( ! ( host->persist == VTUN_PERSIST_KEEPIF ) )
            close(fd[0]);
        close(fd[1]);
        return 0;
    case 0:
        /* do this only the first time when in persist = keep mode */
        if( ! interface_already_open )
        {
            switch( host->flags & VTUN_TYPE_MASK )
            {
            case VTUN_TTY:
                /* Open pty slave (becomes controlling terminal) */
                if( (fd[1] = open(dev, O_RDWR)) < 0)
                {
                    vtun_syslog(LOG_ERR,"Couldn't open slave pty");
                    exit(0);
                }
                /* Fall through */
            case VTUN_PIPE:
                null_fd = open("/dev/null", O_RDWR);
                close(fd[0]);
                close(0);
                dup(fd[1]);
                close(1);
                dup(fd[1]);
                close(fd[1]);

                /* Route stderr to /dev/null */
                close(2);
                dup(null_fd);
                close(null_fd);
                break;
            case VTUN_ETHER:
            case VTUN_TUN:
                break;
            }
        }
        /* Run list of up commands */
        set_title("%s running up commands", host->host);
        vtun_syslog(LOG_ERR,"running commands");
        llist_trav(&host->up, run_cmd, &host->sopt);

        exit(0);
    }

    switch( host->flags & VTUN_TYPE_MASK )
    {
    case VTUN_TTY:
        set_title("%s tty", host->host);

        dev_read  = pty_read;
        dev_write = pty_write;
        break;

    case VTUN_PIPE:
        /* Close second end of the pipe */
        close(fd[1]);
        set_title("%s pipe", host->host);

        dev_read  = pipe_read;
        dev_write = pipe_write;
        break;

    case VTUN_ETHER:
        set_title("%s ether %s", host->host, dev);

        dev_read  = tap_read;
        dev_write = tap_write;
        break;

    case VTUN_TUN:
        set_title("%s tun %s", host->host, dev);

        dev_read  = tun_read;
        dev_write = tun_write;
        break;
    }

	opt = linkfd(host);

    set_title("%s running down commands", host->host);
    llist_trav(&host->down, run_cmd, &host->sopt);

    if(! ( host->persist == VTUN_PERSIST_KEEPIF ) )
    {
        set_title("%s closing", host->host);

        /* Gracefully destroy interface */
        switch( host->flags & VTUN_TYPE_MASK )
        {
        case VTUN_TUN:
            tun_close(fd[0], dev);
            break;

        case VTUN_ETHER:
            tap_close(fd[0], dev);
            break;
        }

        close(host->loc_fd);
    }

    /* Close all other fds */
    close(host->rmt_fd);
    close(fd[1]);

    return opt;
}
