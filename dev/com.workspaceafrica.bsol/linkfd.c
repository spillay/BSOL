/*
Copyright (C) 2014-2015 Stevens Institute of Tech, Hoboken NJ
 * $Id: linkfd.c,v 1.13.2.3 2008/01/07 22:35:43 mtbishop Exp $
 */
 
#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <errno.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_SCHED_H
#include <sched.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>


// Added by vsagar
// to parse tcp header for better debugging
#include <netinet/ip.h>
#include <netinet/tcp.h>
// End of Addition

#include <sys/types.h>
//#include <net/if.h>
#include <linux/if.h>
#include <fcntl.h>
#include <string.h>
#include "vtun.h"
#include "linkfd.h"
#include "lib.h"
#include "driver.h"
#include <pthread.h>
#include "fd_manager.h"
/* used by lfd_encrypt */
int send_a_packet = 0;
int tx_frame = 0; 
/*used as hook for probing*/

// Added by vsagar
// Queue length used at Tx/Rx side per interface
//#define QLEN 2000
#define SEQLEN 60000000

// Extra header to maintain inter-link state information
#define VTUN_EXT_HDR 7

// Hardcoded duplication/failsafe mode
#define VTUN_DUPLICATE 0

// Hardcoded dynamic mode
#define VTUN_DYNAMIC 0

int VTUN_DEBUG = 1;

// Different message types to be transmitted
int ACK = 1;
int LINK = 2;
int LOSS = 3;
typedef union
{
int i;
char str[4];
}str_int;

str_int mystrint;
// Flag indicates ordered packets to transmit
int reorder_send_flag = 0;

// Flag indicates initial synchronization
int sync_flag = 0;
// per link queue use to store packets after reception and before reorder
//static Q q[2];
// Queue to stored ordered packets
//static Q order;
// State used to track reorder state
static reorder_state state;

Mux mux;

schedule_context sc;

probe_t *temp_probe;
// Time of transmission loop started
struct timeval start_tv;
struct timeval peer_tv;
// Mutex
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
struct vtun_host *lfd_host;
int *fd_list;
int num_fd;
int fd1_done = 0;
int fd3_done = 0;
double rates[VTUN_MAX_INT];
double wt[VTUN_MAX_INT];
double sum_of_rates = 0;
double sum_of_wt = 0;
double rates2[VTUN_MAX_INT];
int sched_flag[VTUN_MAX_INT] ={0};
unsigned long   d_t[VTUN_MAX_INT] ={1000000};
int reported_loss[VTUN_MAX_INT] ={0};
int old_q[VTUN_MAX_INT] ={0};
int frame[VTUN_MAX_INT] ={0};
int q_thresh[VTUN_MAX_INT];
struct lfd_mod *lfd_mod_head = NULL, *lfd_mod_tail = NULL;

void respond_back(int index, unsigned int l_seq, int flag);
long int diff_tv_us(struct timeval tv1, struct timeval tv2)
{
    return ((tv1.tv_sec - tv2.tv_sec)*1000000 + (tv1.tv_usec -tv2.tv_usec) == 0 )?1:(tv1.tv_sec - tv2.tv_sec)*1000000 + (tv1.tv_usec -tv2.tv_usec);
}

int diff_tv(struct timeval tv1, struct timeval tv2)
{
    return (tv1.tv_sec - tv2.tv_sec)*1000 + (tv1.tv_usec -tv2.tv_usec)/1000;
}
void get_tput(int index, int current_q, int frame_start, int frame_end)
{
        int i;
        int x0;
        int x1;
        int temp;
        struct timeval t0;
        struct timeval t_now;

        if(lfd_host->fs[index].tx_fs.q.at[frame_start].ls ==0){
		rates2[index] = 0;
                return; 
         }
        
        x0 = lfd_host->fs[index].tx_fs.q.at[frame_start].Q;

        t0 = lfd_host->fs[index].tx_fs.q.at[frame_start].tv;
        
        gettimeofday(&t_now,NULL);
        x1 = current_q;

        temp = 0;

        do
        {
                temp = temp + lfd_host->fs[index].tx_fs.q.at[frame_start].dQ;
                frame_start = (frame_start +1)%QLEN;
        }
        while(frame_start != (frame_end+1)%QLEN);

        rates2[index] = (double)((temp+old_q[index]-q_thresh[i]-current_q)*100000.0)/(double)diff_tv_us(t_now , t0);
        //rates2[index] = (double)((temp+old_q[index]-q_thresh[i]-current_q)*100000.0);
        if(rates2[index] < 0){
		vtun_syslog(-1,"DBG (%d,%d,%d,%d) %d %d %d %d",index,current_q,frame_start,frame_end,temp,old_q[index],q_thresh[i],current_q);
           rates2[index] = 0;
        }
        return;
}

double get_rate(int index, int current_q)
{
	int frame_start;
	int frame_end;
	int i;
	int x0;
	int x1;
	int temp;
	struct timeval t0;
	struct timeval t_now;
        int frame_length = 10;

	if(mux.c < frame_length)
		return 0;
      
	frame_start = (lfd_host->fs[index].tx_fs.q.start+QLEN-frame_length)%QLEN;
	frame_end = (lfd_host->fs[index].tx_fs.q.start+QLEN-1)%QLEN;

	if(lfd_host->fs[index].tx_fs.q.at[frame_start].ls ==0)
		return 0;
	x0 = lfd_host->fs[index].tx_fs.q.at[frame_start].Q;

	t0 = lfd_host->fs[index].tx_fs.q.at[frame_start].tv;
	gettimeofday(&t_now,NULL);
	x1 = current_q;

	temp = 0;

        do	
	{
		temp = temp + lfd_host->fs[index].tx_fs.q.at[frame_start].dQ;
		frame_start = (frame_start +1)%QLEN;
	}
	while(frame_start != (frame_end+1)%QLEN);

        //rates2[index] = (double)((temp)*100000.0)/(double)diff_tv_us(t_now , t0);
	if(diff_tv_us(t_now , t0) > 1000000 || x0+temp < x1)
        	return 0.0;
	else
		return (double)((x0+temp-x1)*100000.0)/(double)diff_tv_us(t_now , t0) ; 

}
void update_rto(int *srtt,int *rttvar, int *rto, int rtt)
{
        int diff;
        int temp_srtt;
        int temp_rtt_var;
        int temp_rto;
	if(*srtt == 0)
	{
          *srtt = rtt;
	  *rttvar = rtt/2;
          *rto = 1000000; // 1 sec
           return;
	}

        temp_srtt = *srtt;
        temp_rtt_var = *rttvar;
        temp_rto = *rto;

        if(*srtt > rtt)
           diff = temp_srtt -rtt;
        else
	   diff = rtt - temp_srtt;

	temp_rtt_var = (3*temp_rtt_var + diff)/4;
        temp_srtt = (7*temp_srtt+rtt)/8;
        if(4*temp_rtt_var < 100000)
		temp_rto = temp_srtt + 100000;
        else
		temp_rto = temp_srtt + 4*temp_rtt_var;

        *srtt = temp_srtt;
        *rttvar = temp_rtt_var;
        *rto = temp_rto;
 /* Removes effect of learning  
        *srtt = 10000000;
        *rttvar = 10000000;
        *rto = 10000000;
*/     
        return;
}
void update_rtt(int gs, struct timeval tv)
{
        int i,j;
        for(i =0; i<VTUN_MAX_INT; i++)
        {
                if(lfd_host->fs[i].tx_fs.q.start != lfd_host->fs[i].tx_fs.q.end && lfd_host->fs[i].fd_flag >0)
                {
                        for(j =0; j< QLEN; j++)
                        {
                                if(lfd_host->fs[i].tx_fs.q.at[j].len > 0 && lfd_host->fs[i].tx_fs.q.at[j].gs == gs)
                                        break;
                        }
                }
                if(j != QLEN )
                        break;
        }
        if(i< VTUN_MAX_INT && j < QLEN){
		
		mux.rtt = diff_tv_us(tv,lfd_host->fs[i].tx_fs.q.at[j].tv);
              //  vtun_syslog(LOG_ERR,"i %d, ls %d, gs %d, [%lu:%lu]- [%lu:%lu] = %d [%d]",i,j,gs,tv.tv_sec,tv.tv_usec,lfd_host->fs[i].tx_fs.q.at[j].tv.tv_sec,lfd_host->fs[i].tx_fs.q.at[j].tv.tv_usec,diff_tv_us(tv,lfd_host->fs[i].tx_fs.q.at[j].tv),mux.rto);
        }
        else
                vtun_syslog(LOG_ERR,"gs not found %d", gs );
 
}
void parse_app_msg(char *buf,int tmplen, struct sockaddr_in saddr)
{
	int tmptag;
        switch_info tempsi;
        int temp_int;
        int j;
        struct timeval tv;
        ctrl_msg cm;
        char ipstr[INET_ADDRSTRLEN];

	if(tmplen ==4){
		memcpy(&mystrint,buf,tmplen);
        	tmptag = mystrint.i;
        }else
          	tmptag = atoi(buf);
        
        vtun_syslog(LOG_ERR,"CTRL DBG INT %d",tmptag); 
                         
        if(tmptag == 1 && sc.state <=VTUN_MAX_INT)
	{
               if(sc.state != (temp_int =get_next_fd(sc.state)))
                {
	  	    sc.master = 0;
                    tmplen = sc.state;
                    sc.state = temp_int;
                    gettimeofday(&tv,NULL);
                    mux.lastack_tv = tv;
                    tempsi.type =1;
                    tempsi.state =sc.state;
                    tempsi.master =sc.master;
		    cm.type = SWITCH_INFO;
                    cm.si = tempsi;
                    sendfromto(lfd_host->ctrl,(char *)&cm,sizeof(cm),0,(struct sockaddr *)&(lfd_host->fs[sc.state].saddr), sizeof(lfd_host->fs[sc.state].saddr),(struct sockaddr *)&(lfd_host->fs[sc.state].daddr), sizeof(lfd_host->fs[sc.state].daddr));

                    vtun_syslog(-1," ctrl switching info sent ");
                    // updating lastack_tv 
                    mux.lastack_tv = tv;
                    flush_link(tmplen);
               }

       }else if(tmptag == 99)
       {
	       sc.master = (sc.master+1)%2;
               tempsi.type =1;
               tempsi.state =sc.state;
               tempsi.master =sc.master;
               cm.type = SWITCH_INFO;
               cm.si = tempsi;
               // peer's control port
	       //vtun_syslog(LOG_ERR, "DEBUG PEER CTRL %d %s:%d",sc.state,lfd_host->daddr[sc.state].ip,lfd_host->dport[1]+10);
               sendfromto(lfd_host->ctrl,(char *)&cm,sizeof(ctrl_msg),0,(struct sockaddr *)&(lfd_host->fs[sc.state].saddr), sizeof(lfd_host->fs[sc.state].saddr),(struct sockaddr *)&(lfd_host->fs[sc.state].daddr), sizeof(lfd_host->fs[sc.state].daddr));
               //vtun_syslog(-1," master switching info sent to %s:%s %d ",strerror(errno),inet_ntoa(si_other.sin_addr),ntohs(si_other.sin_port));
               // updating lastack_tv 
               mux.lastack_tv = tv;

       }else if(tmptag >=100)
       {
               lfd_host->fs[tmptag-100].daddr.sin_family = AF_INET;
               lfd_host->fs[tmptag-100].daddr.sin_port = saddr.sin_port;
               lfd_host->fs[tmptag-100].daddr.sin_addr.s_addr = saddr.sin_addr.s_addr; 
	       inet_ntop(AF_INET, &(lfd_host->fs[tmptag-100].daddr.sin_addr), ipstr, INET_ADDRSTRLEN);               
               vtun_syslog(LOG_ERR,"On server %s:%d %d",ipstr,lfd_host->fs[tmptag-100].daddr.sin_port,tmptag -100);
       }
        vtun_syslog(LOG_ERR,"parse_app_msg done"); 
	return;
}
void parse_ctrl_msg(char *buf, int tmplen, struct  vtun_host *host, struct sockaddr_in saddr)
{
     char ipstr[INET_ADDRSTRLEN];
     ctrl_msg *cm;
     int opt;
     int temp_int;
     int j;
     int i;
     ctrl_msg cm2;
     vtun_syslog(LOG_ERR,"PARSE CTRL MSG %d <-> %d",tmplen,sizeof(cm));
     if(tmplen <sizeof(ctrl_msg))
     {
     	parse_app_msg(buf,tmplen,saddr);
     	return;
     }
     cm = (ctrl_msg *) buf; 
     vtun_syslog(LOG_ERR,"PARSE CTRL MSG before switch %d",cm->type);
     switch(cm->type)
     {
	case BIND_REQ : // Server Side
             host->fs[cm->bl.index].fd_flag = 0;
     	     vtun_syslog(LOG_ERR,"BIND_REQ");
             send_new_port(host, cm->bl.index,get_ctrl_index(host),BIND_REQ_ACK);
             host->fs[cm->bl.index].fd_flag = 2;
             break;

        case BIND_REQ_ACK : // Client Side
             saddr = host->fs[0].daddr;
             saddr.sin_port = cm->bl.port;
             opt = sizeof(saddr);
             cm2.type = PING_NEW_DATAPATH;
             cm2.bl = cm->bl;
             /*Send PING on new Data Path*/
             
             inet_ntop(AF_INET, &(saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
             vtun_syslog(LOG_INFO,"%s:%d",ipstr,ntohs(saddr.sin_port));
             host->fs[cm->bl.index].daddr = saddr;

             if( connect(host->fs[cm->bl.index].fd,(struct sockaddr *)&saddr,sizeof(saddr)) ){
                vtun_syslog(LOG_ERR,"Can't connect socket");
                exit(1);
             }
 
            // sendto(host->fs[cm->bl.index].fd,(char *)&cm2,sizeof(cm2),0,(struct sockaddr *)&saddr,opt); 
             if(write(host->fs[cm->bl.index].fd,(char *)&cm2,sizeof(cm2))<0)
		vtun_syslog(LOG_ERR,"BIND_REQ_ACK send failure"); 
             host->fs[cm->bl.index].fd_flag = 2;

             inet_ntop(AF_INET, &(saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
             vtun_syslog(LOG_INFO,"To %s:%d",ipstr,ntohs(saddr.sin_port));

             vtun_syslog(LOG_ERR,"Send PING on new Data Path %s",strerror(errno));
             break;

        case PING_NEW_DATAPATH : // Server Side
             vtun_syslog(LOG_ERR,"Recieved PING on new Data Path");
             host->fs[cm->bl.index].daddr = saddr;
             if( connect(host->fs[cm->bl.index].fd,(struct sockaddr *)&saddr,sizeof(saddr)) ){
             	vtun_syslog(LOG_ERR,"Can't connect socket");
                exit(1);
             }
            // host->fs[cm->bl.index].fd_flag = 1;
             cm2.type = PING_NEW_DATAPATH_REPLY;
             cm2.bl = cm->bl;
             errno =0;
             //sendto(host->fs[cm->bl.index].fd,(char *)&cm2,sizeof(cm2),0,(struct sockaddr *)&saddr,opt); 
             if(write(host->fs[cm->bl.index].fd,(char*)&cm2,sizeof(cm2))<0)
		vtun_syslog(LOG_ERR,"PING_NEW_DATAPATH send failure");
             inet_ntop(AF_INET, &(saddr.sin_addr), ipstr, INET_ADDRSTRLEN);
             vtun_syslog(LOG_INFO,"To %s:%d",ipstr,ntohs(saddr.sin_port));
             vtun_syslog(LOG_ERR,"Sent PING_REPLY on new Data Path %s",strerror(errno));
             host->fs[cm->bl.index].fd_flag = 2;
             break;

        case PING_NEW_DATAPATH_REPLY : // Client Side
             host->fs[cm->bl.index].fd_flag = 1;
             cm2.type = BIND_REQ_COMPLETE;
             cm2.bl = cm->bl;
             if(write(host->fs[cm->bl.index].fd,(char*)&cm2,sizeof(cm2))<0)
		vtun_syslog(LOG_ERR,"PING_NEW_DATAPATH_REPLY send failure");  
             vtun_syslog(LOG_ERR,"Sent BIND_REQ_COMPLETE on new Data Path");
             break;

        case BIND_REQ_COMPLETE : // Server Side
             host->fs[cm->bl.index].fd_flag = 1;
             vtun_syslog(LOG_ERR,"Recieved BIND_REQ_COMPLETE on new Data Path");
             break; 

        case UNBIND_REQ :
             vtun_syslog(LOG_ERR,"UNBIND REQ RECEIVED %d",cm->bl.index);
             host->fs[cm->bl.index].fd_flag = 0;
             close(host->fs[cm->bl.index].fd);
             vtun_syslog(LOG_ERR,"UNBIND REQ RECEIVED");
             break; 
	case FD_INFO :
             for (i=0;i<VTUN_MAX_INT;i++)
             {
		if(host->fs[i].fd_flag != cm->fi.flag[i] && host->fs[i].fd_flag ==1){
			flush_link(i);
                        vtun_syslog(LOG_ERR,"Peer Removed %d %d",i,cm->fi.flag[i]);
		}
	        	
		if(host->fs[i].fd_flag != cm->fi.flag[i] && host->fs[i].fd_flag ==10)
		{
		       	vtun_syslog(LOG_ERR,"Peer Added %d %d",i,cm->fi.flag[i]);
			host->fs[i].test = 0;			
		}

		host->fs[i].fd_flag = cm->fi.flag[i]; 
		}
             break;
        case SWITCH_INFO :
	     sc.master = cm->si.master;
             if(cm->si.type ==2)
               break;
             if(sc.state != cm->si.state)
             {
             vtun_syslog(LOG_ERR,"switching from %d to %d",sc.state,cm->si.state);
	       temp_int = cm->si.state;
               cm->si.type = 2;
               sc.state = cm->si.state;
               if(cm->si.state>=0 && cm->si.state < VTUN_MAX_INT)
	       {
		  sendfromto(host->ctrl,(char *)&cm,sizeof(switch_info),0,(struct sockaddr *)&(host->fs[sc.state].saddr), sizeof(host->fs[sc.state].saddr),(struct sockaddr *)&(host->fs[sc.state].daddr), sizeof(host->fs[sc.state].daddr));
	        }
                else{
                 j = get_ctrl_index(host);
                  sendfromto(host->ctrl,(char *)&cm,sizeof(switch_info),0,(struct sockaddr *)&(lfd_host->fs[j].saddr), sizeof(lfd_host->fs[j].saddr),(struct sockaddr *)&(lfd_host->fs[j].daddr), sizeof(lfd_host->fs[j].daddr));
                    }
			   flush_link(sc.state);	  
             }
        default : 
	     break; 
     }
     return;
}
void getTime(char *timeString)
{
     time_t current_time;
     struct tm * time_info;
     time(&current_time);
     time_info = localtime(&current_time);
     //strftime(timeString, sizeof(timeString), "%H:%M:%S", time_info);
     sprintf(timeString,"%02d:%02d:%02d",time_info->tm_hour,time_info->tm_min,time_info->tm_sec);

     return;
}
void log_xml()
{
     xmlDocPtr doc = NULL;
     xmlNodePtr root_node = NULL, stat_node = NULL, node = NULL;
     int i;
     const char *file = "/var/log/stat.xml";
     char buff[128];
     char buff2[128];
     char timeString[9];
     static unsigned long prev_byte_in = 0, prev_byte_out =0;  
     static unsigned long prev_byte_in_link[VTUN_MAX_INT] = {0}, prev_byte_out_link[VTUN_MAX_INT] ={0};  
     doc = xmlParseFile(file);
    
     if (doc == NULL)
     {
        vtun_syslog(LOG_ERR,"Can't parse the content: %s\n", file);
        doc = xmlNewDoc(BAD_CAST "1.0");
        if(doc == NULL){
        vtun_syslog(LOG_ERR, "Can't create log file.. exiting");
	exit(0);
        }
        root_node = xmlNewNode(NULL, BAD_CAST "log");
        xmlDocSetRootElement(doc, root_node);
    }
    
    root_node = xmlDocGetRootElement(doc);
    if (root_node == NULL)
    {
        vtun_syslog(LOG_ERR,"Can't get the root element: %s\n", file);
        xmlFreeDoc(doc);
        exit(0);
    }

    stat_node = xmlNewChild(root_node, NULL,BAD_CAST "stat",NULL);
    getTime(timeString);
    xmlNewChild(stat_node, NULL, BAD_CAST "timestamp",BAD_CAST timeString); 
   
    node = xmlNewChild(stat_node, NULL, BAD_CAST "names", NULL);
    for(i =0; i<VTUN_MAX_INT;i++)
    {
        sprintf(buff,"name%d",i);

        if(lfd_host->fs[i].ifa_name==0)
        	sprintf(buff2,"inf%d",i);
        else
        	sprintf(buff2,"%s",lfd_host->fs[i].ifa_name);
                   
	xmlNewChild(node, NULL, BAD_CAST buff, BAD_CAST buff2);
	
    }
    
    node = xmlNewChild(stat_node, NULL, BAD_CAST "flags", NULL);
    for(i =0; i<VTUN_MAX_INT;i++)
    {
        sprintf(buff,"flag%d",i);
        sprintf(buff2,"%d",lfd_host->fs[i].fd_flag);
	xmlNewChild(node, NULL, BAD_CAST buff, BAD_CAST buff2);
    }
   
    sprintf(buff,"%lu",lfd_host->stat.byte_in); 

    node = xmlNewChild(stat_node, NULL, BAD_CAST "byte_in", BAD_CAST buff);

    prev_byte_in = lfd_host->stat.byte_in;

    //sprintf(buff,"%f",((lfd_host->stat.byte_out - prev_byte_out)*8/60)/1000); 

    sprintf(buff,"%lu",lfd_host->stat.byte_out); 

    node = xmlNewChild(stat_node, NULL, BAD_CAST "byte_out", BAD_CAST buff);

    prev_byte_out = lfd_host->stat.byte_out;
    
    node = xmlNewChild(stat_node, NULL, BAD_CAST "in_data", NULL);
    for(i =0; i<VTUN_MAX_INT;i++)
    {
        sprintf(buff,"in_data%d",i);
        //sprintf(buff2,"%f",((lfd_host->fs[i].in_data-prev_byte_in_link[i])*8/60)/1000);
        sprintf(buff2,"%lu",lfd_host->fs[i].in_data);
	xmlNewChild(node, NULL, BAD_CAST buff, BAD_CAST buff2);
    	prev_byte_in_link[i] = lfd_host->fs[i].in_data;
    }

    node = xmlNewChild(stat_node, NULL, BAD_CAST "out_data", NULL);
    for(i =0; i<VTUN_MAX_INT;i++)
    {
        sprintf(buff,"out_data%d",i);
	//sprintf(buff2,"%f",((lfd_host->fs[i].out_data-prev_byte_out_link[i])*8/60)/1000);
        sprintf(buff2,"%lu",lfd_host->fs[i].out_data);
	xmlNewChild(node, NULL, BAD_CAST buff, BAD_CAST buff2);
    	prev_byte_out_link[i] = lfd_host->fs[i].out_data;
    }
    sprintf(buff,"%d",mux.rto/1000);
    node = xmlNewChild(stat_node, NULL, BAD_CAST "mux_rto", BAD_CAST buff);
    
    node = xmlNewChild(stat_node, NULL, BAD_CAST "srtts", NULL);
    for(i =0; i<VTUN_MAX_INT;i++)
    {
        sprintf(buff,"srtt%d",i);
        sprintf(buff2,"%d",lfd_host->fs[i].srtt);
	xmlNewChild(node, NULL, BAD_CAST buff, BAD_CAST buff2);
    }
   
    node = xmlNewChild(stat_node, NULL, BAD_CAST "rttvars", NULL);
    for(i =0; i<VTUN_MAX_INT;i++)
    {
        sprintf(buff,"rttvar%d",i);
        sprintf(buff2,"%d",lfd_host->fs[i].rttvar);
	xmlNewChild(node, NULL, BAD_CAST buff, BAD_CAST buff2);
    }
   
    sprintf(buff,"%d",state.final_loss);
    node = xmlNewChild(stat_node, NULL, BAD_CAST "mux_loss", BAD_CAST buff);
    
    node = xmlNewChild(stat_node, NULL, BAD_CAST "link_losses", NULL);
    for(i =0; i<VTUN_MAX_INT;i++)
    {
        sprintf(buff,"loss%d",i);
        sprintf(buff2,"%d",lfd_host->fs[i].lost_count);
	xmlNewChild(node, NULL, BAD_CAST buff, BAD_CAST buff2);
    }
   
    sprintf(buff,"%d",state.block_loss);
    node = xmlNewChild(stat_node, NULL, BAD_CAST "reorder_timeout", BAD_CAST "0");
    
    node = xmlNewChild(stat_node, NULL, BAD_CAST "loss_timeouts", NULL);
    for(i =0; i<VTUN_MAX_INT;i++)
    {
        sprintf(buff,"timeout%d",i);
        sprintf(buff2,"%d",lfd_host->fs[i].timeout_count);
	xmlNewChild(node, NULL, BAD_CAST buff, BAD_CAST buff2);
    }
    xmlSaveFileEnc(file, doc, "UTF-8"); 
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return;
}

void log_xml_init()
{

 	//const char *filename = "/home/dsm1000/config/stat.xml";
	const char *filename = "/var/log/stat.xml";
	char filename2[256]={0};
	char timeString[9];
        FILE *file;
    	if (file = fopen(filename, "r")){
        	fclose(file);
                getTime(timeString);
                sprintf(filename2,"/var/log/stat_%s.xml",timeString);
                if(rename(filename,filename2)==-1)
			vtun_syslog(LOG_ERR,"Unable to rename stat file");
   	 }
        log_xml();
}
void nl_init()
{
    struct sockaddr_nl addr;
    errno = 0;
    if ((lfd_host->nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
    {
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_LINK ;

    if (bind(lfd_host->nl, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        exit(1);
    }
    vtun_syslog(LOG_ERR,"NL %s : %d",strerror(errno),lfd_host->nl);
    return;
}

void nl_handle(struct nlmsghdr *h,struct vtun_host *host )
{
  struct ifinfomsg *iface;
  struct rtattr *attribute;
  int len;
  int ret;
  int state;
  char ifname[IFNAMSIZ];
  struct ifinfomsg *ifl;
  char str[50];
  int i;
  ifl = (struct ifinfomsg *) NLMSG_DATA(h);
  if_indextoname(ifl->ifi_index,ifname);

  iface = NLMSG_DATA(h);
  len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

				sprintf(str,"<1>");
                        for (i =0;i<VTUN_MAX_INT;i++)
                        {
				sprintf(str+strlen(str)," %d",host->fs[i].fd_flag);
			}
			vtun_syslog(LOG_ERR,"%s",str);
                        memset(str,0,50);
 
  for (attribute = IFLA_RTA(iface); RTA_OK(attribute, len); attribute = RTA_NEXT(attribute, len))
    {
      switch(attribute->rta_type)
      {
         case  IFLA_OPERSTATE :
                state = *(int*)RTA_DATA(attribute);
                switch (state) {
                case IF_OPER_UP:
                        for (i =0;i<VTUN_MAX_INT;i++)
                        {
				//if(host->fs[i].ifa_index == ifl->ifi_index){
				if(strcmp(host->fs[i].ifa_name,ifname)==0){
					//host->fs[i].fd_flag =1;
                                        break;
				}
			}
                        if(host->fs[i].fd_flag ==0){
                        	memset(str,0,50);
                        	sprintf(str,"/sbin/dhclient %s",ifname);
                       		ret = system(str);
				if(system("/home/vsagar/deldefaultgw")==-1)
					vtun_syslog(LOG_ERR,"deldefaultgw failed");
                        	memset(str,0,50);
                        	send_new_port(host, i,get_ctrl_index(host),BIND_REQ);
                        	vtun_syslog(LOG_ERR," %s Up  %d", ifname,i);
                        }
                        break;
                case IF_OPER_DOWN:
                        
                        for (i =0;i<VTUN_MAX_INT;i++)
                        {
				//if(host->fs[i].ifa_index == ifl->ifi_index){
				if(strcmp(host->fs[i].ifa_name,ifname)==0){
					//host->fs[i].fd_flag =0;
					break;
				}
                        }
                        if(host->fs[i].fd_flag ==1){
			host->fs[i].fd_flag =0;
			send_unbind_req(host,i);
                        flush_link(i);
                        //vtun_syslog(LOG_ERR," %s Down %d", ifname,getifaddr(ifname),i);
                        vtun_syslog(LOG_ERR," %s Down %d", ifname,i);
                        sprintf (str, "/sbin/dhclient -r %s",ifname);
                        ret = system(str);
                        memset(str,0,50);
			}
                        break;
                default:
                        break;
                }
                break;

        default:
          break;
      }
    }


				sprintf(str,"<2>");
                        for (i =0;i<VTUN_MAX_INT;i++)
                        {
				sprintf(str+strlen(str)," %d",host->fs[i].fd_flag);
			}
			vtun_syslog(LOG_ERR,"%s",str);
                        memset(str,0,50);
 
    return;
}
void nl_recv()
{
    struct nlmsghdr *nlh;
    char buffer[8192];
    int len;
    nlh = (struct nlmsghdr *)buffer;
    while ((len = recv(lfd_host->nl,nlh,8192,0)) > 0)
    {
        if (NLMSG_OK(nlh, len))// && (nlh->nlmsg_type != NLMSG_DONE))
        {
            switch (nlh->nlmsg_type)
            {
            case RTM_NEWLINK:
            case RTM_DELLINK:
            case RTM_NEWADDR:
            case RTM_DELADDR:
                nl_handle(nlh,lfd_host);
                break;

            default:
               // printf ("get some other message %d\n", nlh->nlmsg_type);
                break;
            }

        }
    }

    return;
}
/*
    This function will try to fetch fastest fd
*/
int get_next_fd( int lstate)
{
    int temp;
    temp = lstate;

    if(lstate <0|| lstate> VTUN_MAX_INT)
       lstate = -1;
    do{
        lstate = (lstate +1)%VTUN_MAX_INT;
    } while(lfd_host->fs[lstate].fd_flag !=1 || lfd_host->fs[lstate].test >1);
    
// To avoid crash 
    if(lstate <0)
       lstate = temp;
    return lstate;

}

int get_fastest_fd(int fd)
{
    int i;
    int ret = -1;
    for(i =0; i<VTUN_MAX_INT; i++ )
    {
        if(lfd_host->fs[i].fd != fd || lfd_host->fs[i].fd_flag ==1)
        {
            ret = lfd_host->fs[i].fd;
            break;
        }
    }
    if(ret == -1)
     ret = fd;
    vtun_syslog(LOG_ERR,"fastest %d for %d",ret,fd);
    return ret;
 
}

fd_state* fetch_state(int fd)
{
    int i;
    fd_state *ret = NULL;
    for(i =0; i<VTUN_MAX_INT; i++ )
    {
        if(lfd_host->fs[i].fd == fd)
        {
            ret = &(lfd_host->fs[i]);
            break;
        }
    }
    return ret;
}

int fetch_idx(int fd)
{
    int i;
    int ret = -1;
    for(i =0; i<VTUN_MAX_INT; i++ )
    {
        if(lfd_host->fs[i].fd == fd)
        {
            ret = i;
            break;
        }
    }
    return ret;
}

/*
	Just dumping
*/
void dump_state()
{
  
   //vtun_syslog(-1,"Dumping is deffered");  
    return;
}
/*
	Flushes Tx side packets larger than sc.gs_1(acknowledged global sequence) from ith link
	using next link after i
*/
int flush_link(int i)
{
    my_pkt t;
    stamp16 l_seq_t;
    int j =i;
    int fd ;
    if(i<0)
    return 1;
    while(1){
       j = (j+1)%VTUN_MAX_INT;
       if(lfd_host->fs[j].fd_flag ==1 && j != i)
           break; 
    }
    fd = lfd_host->fs[j].fd;
    for(j =0; j<QLEN ; j++)
    {
        if(lfd_host->fs[i].tx_fs.q.at[(lfd_host->fs[i].tx_fs.q.start+j)%QLEN].len>0 && lfd_host->fs[i].tx_fs.q.at[(lfd_host->fs[i].tx_fs.q.start+j)%QLEN].gs >= sc.gs_1)
        {
            t = lfd_host->fs[i].tx_fs.q.at[(lfd_host->fs[i].tx_fs.q.start+j)%QLEN];
	    t.buf[6] = i+VTUN_MAX_INT;
            udp_write(fd,t.buf,t.len);
            //vtun_syslog(-1,"[%d]flushed gs %d",i,t.gs);
        }
        lfd_host->fs[i].tx_fs.q.at[(lfd_host->fs[i].tx_fs.q.start+j)%QLEN].len =0;

    }
    return 1;
}
// Delays dev_write to add cushion for loss recovery which may affect TCP
int delay_write(int time, struct timespec temp_tv)
{
    return 1;
}


/*
	TODO: clean up, mux.path is useless practically
	to select output file descriptor
	if there is no fixed path select rand() to select
	path with different weights.
	Start counting valid fds till count%VTUN_MAX_INT
*/
int choose_link2()
{
    int ret;
    int i; 
    static int count =0;
    //static double qlen[VTUN_MAX_INT] ={0};
    count ++;
    count = count%2;
    for(i=0;i<VTUN_MAX_INT; i++)
    {
       if(lfd_host->fs[i].tx_flag ==1 && lfd_host->fs[i].fd_flag ==1)
       {
           if(ioctl(lfd_host->fs[i].fd, SIOCOUTQ, &lfd_host->fs[i].sock_q)!=0)
               lfd_host->fs[i].sock_q = SOCK_Q_MAX;
       }
     //  qlen[i] = qlen[i]+lfd_host->fs[i].sock_q;
    }
    //if(qlen[0]/count > 10000 && lfd_host->fs[0].sock_q >5000)
    if(lfd_host->fs[0].sock_q >10000 &&lfd_host->fs[1].sock_q <5000)
       ret = 1;
    else
       ret = 0;
/*
    count++;
    count = count%6;
    if(count ==0)
    ret = 1;
    else 
    ret = 0;
*/
/*
// RR
    count = count%2;
    ret = count;
*/
/*
    ret = 0;
    if(lfd_host->fs[0].sock_q <4000)
       ret = 0;
    else if(lfd_host->fs[1].sock_q<4000)
       ret = 1;
    else if (lfd_host->fs[1].sock_q > lfd_host->fs[0].sock_q)
       ret = 0;
    else
        ret = 1;
*/    
    if(lfd_host->fs[ret].tx_flag ==0)
       ret = (ret+1)%2;

    vtun_syslog(-1, "RET %d q %d %d f %d %d : %d %d",ret,lfd_host->fs[0].sock_q,lfd_host->fs[1].sock_q,lfd_host->fs[0].fd_flag,lfd_host->fs[1].fd_flag,lfd_host->fs[0].tx_flag,lfd_host->fs[1].tx_flag); 
    
    return ret; 
 
}
int choose_link()
{
    int ret;
    static int count = 0;
    int i = 0;
    int j =  -1;
    int k =  -1;
    int fast = 0;
    int found_fast = -1;
    int max_q = 0;
    int min_q = 0;
    int prev_q[VTUN_MAX_INT];
    ret = 0;

    for(i=0;i<VTUN_MAX_INT; i++)
    {
       prev_q[i] = 0;
       if(lfd_host->fs[i].tx_flag ==1 && lfd_host->fs[i].fd_flag ==1)
       {
           prev_q[i] = lfd_host->fs[i].sock_q;
           if(ioctl(lfd_host->fs[i].fd, SIOCOUTQ, &lfd_host->fs[i].sock_q)!=0)
               lfd_host->fs[i].sock_q = SOCK_Q_MAX;

           if(k < 0)
              k = i;
           else if(lfd_host->fs[k].sock_q >lfd_host->fs[i].sock_q)
               k =i;

           if(j < 0)
              j = i;
           else if(lfd_host->fs[j].sock_q <lfd_host->fs[i].sock_q)
               j = i;

           if(lfd_host->fs[i].sock_q -prev_q[i] < lfd_host->fs[fast].sock_q -prev_q[fast])
           {
                fast = i;
                found_fast = 1;
           }
       }
    }
    i =0;
    min_q = k;
    max_q = j;
    vtun_syslog(-1," min %d %d, max %d %d fast %d found %d",k,lfd_host->fs[k].sock_q,j,lfd_host->fs[j].sock_q,fast, found_fast);
//===============
#if 0
    if(lfd_host->fs[0].sock_q >lfd_host->fs[1].sock_q )
      ret = 1;
    else
      ret = 0;
/*
    if(lfd_host->fs[0].sock_q >2000 && lfd_host->fs[1].sock_q <8000 )
        ret = 1;
    else 
        ret = 0;
*/
    if(lfd_host->fs[ret].fd_flag != 1||lfd_host->fs[ret].tx_flag != 1)
        ret = (ret+1)%2;
    vtun_syslog(-1,"(%d) [%d,%d,%d] [%d,%d,%d]",ret,lfd_host->fs[0].fd_flag,lfd_host->fs[0].tx_flag,lfd_host->fs[0].sock_q,lfd_host->fs[1].fd_flag,lfd_host->fs[1].tx_flag,lfd_host->fs[1].sock_q);
    return ret;
#endif
//================
    //1) maximum is less than threshold then roundrobin
    //2) minimum is less than threshold then minimum
    //3) if there is a faster queue, then faster queue
    //4) Otherwise queue with least queue length
    //if(lfd_host->fs[j].sock_q- lfd_host->fs[k].sock_q < 1000 || (lfd_host->fs[j].sock_q <2000)||(lfd_host->fs[k].sock_q>1000)){
    //if(lfd_host->fs[j].sock_q- lfd_host->fs[k].sock_q < 1000 || (lfd_host->fs[k].sock_q < 1000)){
    //if(lfd_host->fs[k].sock_q < 1000){
    if(lfd_host->fs[max_q].sock_q < 1000){
        while(1)
        {
            //if(lfd_host->fs[j].fd_flag ==1 && lfd_host->fs[j].tx_flag ==1)
            //vtun_syslog(LOG_ERR, "j %d, flag %d, tx_flag %d",j,lfd_host->fs[j].fd_flag,lfd_host->fs[j].tx_flag);
            if(lfd_host->fs[j].tx_flag ==1)
            {

                if(i >= count%VTUN_MAX_INT)
                    break;
                i++;
            }
            j++;
            j = j%VTUN_MAX_INT;
        }

        count ++;
        vtun_syslog(-1," %d sock rr %d %d",j, lfd_host->fs[0].sock_q,lfd_host->fs[1].sock_q);
    }else if(lfd_host->fs[min_q].sock_q < 1000){
        j = min_q;
        vtun_syslog(-1," %d sock zero %d %d",j, lfd_host->fs[0].sock_q,lfd_host->fs[1].sock_q);
    }else if(found_fast >0){
        j = fast;
        vtun_syslog(-1," %d sock fast %d %d",j, lfd_host->fs[0].sock_q,lfd_host->fs[1].sock_q);
    }else {
         j = min_q;
        vtun_syslog(-1," %d sock min %d %d",j, lfd_host->fs[0].sock_q,lfd_host->fs[1].sock_q);
    }
    return j;
}

int new_choose_link()
{
    int ret;
    static int count = 0;
    int i = 0;
    int j =  -1;
    int k =  -1;
    int p =  -1;
    int q =  -1;
    int fast = 0;
    int found_fast = -1;
    int max_q = 0;
    int min_q = 0;
    int min_rate = 0;
    int max_rate = 0;
    int prev_q[VTUN_MAX_INT];
    double draw =0.0;
    double cumsum_rate = 0.0;
    struct timeval t1;
//  double sum_of_rates = 0;
//  double sum_of_wt = 0;
    static struct timeval prev_t1[VTUN_MAX_INT];
    double wt_rr[VTUN_MAX_INT]={0};
    double wt_qrr[VTUN_MAX_INT]={0};
    double wt_fix[VTUN_MAX_INT]={1};
    gettimeofday(&t1,NULL);
    for(i=0;i<VTUN_MAX_INT; i++)
    {
       wt_fix[i] = 0;
       prev_q[i] = 0;
       if(lfd_host->fs[i].tx_flag ==1 && lfd_host->fs[i].fd_flag ==1)
       {
	   wt_fix[i] =1;
           prev_q[i] = lfd_host->fs[i].sock_q;
           if(ioctl(lfd_host->fs[i].fd, SIOCOUTQ, &lfd_host->fs[i].sock_q)!=0)
               lfd_host->fs[i].sock_q = SOCK_Q_MAX;

           //k => min{q_i}
           if(k < 0)
              k = i;
           else if(lfd_host->fs[k].sock_q >lfd_host->fs[i].sock_q)
               k =i;

           //j => max{q_i}
           if(j < 0)
              j = i;
           else if(lfd_host->fs[j].sock_q <lfd_host->fs[i].sock_q)
               j = i;

           rates[i] = get_rate(i,lfd_host->fs[i].sock_q);
           //p ==> min{rate_i}
           if(p < 0 && rates[i]>=0.0)
              p = i;
           else if(rates[p] >rates[i])
               p =i;

           //q ==> max{rate_i}
           if(q < 0)
              q = i;
           else if(rates[q] <rates[i])
               q = i;

           prev_t1[i] = t1;
           sum_of_rates += rates[i];
         
        }
    }

    if(tx_frame ==0)
    {
       for(i=0;i<VTUN_MAX_INT; i++)
          if(lfd_host->fs[i].tx_flag ==1 && lfd_host->fs[i].fd_flag ==1)
          {
              wt[i] = 0.3*wt[i]+0.7*rates[i]/(q_thresh[i]+lfd_host->fs[i].sock_q+1.0);
              sum_of_wt += wt[i];
          }
    }
// This actually works when some queue's rates are unknown
   if(rates[p]>0)
   {
   	tx_frame++;
   	tx_frame = tx_frame%(100*VTUN_MAX_INT);
   }else
        tx_frame = 0;

   if(j<0||k<0||p<0||q<0)
   {
        vtun_syslog(-1,"Queue State Failed Q %d %d Rate %f %f=> %d, %d, %d, %d",lfd_host->fs[0].sock_q,lfd_host->fs[1].sock_q,rates[0],rates[1],j,k,p,q);
        ret -1;
   }

   max_q = j;
   min_q = k;
   min_rate = p;
   max_rate = q;
   ret = min_q;

    wt_qrr[0] = (wt[0]>=0.0?wt[0]:0.0);
    for (i =1; i< VTUN_MAX_INT;i++)
        wt_qrr[i]= wt_qrr[i-1] + wt_fix[i]*(wt[i]>=0.0?wt[i]:0.0);
	
// Ignore divide by zero
    if(wt_qrr[VTUN_MAX_INT-1] >0)
	for(i=0; i<VTUN_MAX_INT;i++)
	{
	    wt_qrr[i] = wt_qrr[i]/wt_qrr[VTUN_MAX_INT-1];
	} 
// To track scheduler state
    p =0;
   if(tx_frame > (90*VTUN_MAX_INT))
   {
       p =1;
       j = 0;
       for(j =0; j<VTUN_MAX_INT; j++)
       {
           count = count+1;
	   count = count%VTUN_MAX_INT;
           if(lfd_host->fs[count].tx_flag ==1 && lfd_host->fs[count].sock_q < 23500 )
               break;
       }
	
       ret = count;
       for(j =0; j<VTUN_MAX_INT;j++)
           sched_flag[j]=1;
 
    }else
    {
       //if(lfd_host->fs[max_q].sock_q == 0)
       if(lfd_host->fs[max_q].sock_q < 4000)
       {
           if(rates[min_rate]==0.0)
           {
               p =2;
               j = 0;
               for(j =0; j<VTUN_MAX_INT; j++)
               {
                   count = count+1;
		   count = count%VTUN_MAX_INT;
                   if(lfd_host->fs[count].tx_flag ==1 && lfd_host->fs[count].sock_q < 23500 )
                       break;
	       }
	       ret = count;
 
           }else{
               srand(t1.tv_usec);
               draw = (double)rand()/(double)RAND_MAX;
               cumsum_rate = 0.0;
	       p =3;
               for(j =0; j<VTUN_MAX_INT; j++)
	       {
			
	           if(draw < wt_qrr[j] && lfd_host->fs[j].sock_q <23500 && lfd_host->fs[j].tx_flag ==1)
		       break;
	       }
		ret = j;
	   }
           for(j =0; j<VTUN_MAX_INT;j++)
               sched_flag[j]=1;

       //}else if(lfd_host->fs[max_q].sock_q > 0 && lfd_host->fs[min_q].sock_q == 0)
       }else if(lfd_host->fs[max_q].sock_q >= 4000 && lfd_host->fs[min_q].sock_q <4000)
       {
       ret = -1;
       if(rates[min_rate]==0.0)
       {
           p =4;
           j = 0;
           for(j =0; j<VTUN_MAX_INT; j++)
           {
               count = count+1;
               count = count%VTUN_MAX_INT;
               if(lfd_host->fs[count].tx_flag ==1 && lfd_host->fs[count].sock_q <4000 && sched_flag[count]==1 )
               {
                   sched_flag[count] = 0;
                   break;
               }
           }
           ret = count;

       }else{
           srand(t1.tv_usec);
           draw = (double)rand()/(double)RAND_MAX;
           cumsum_rate = 0.0;
           p =5;
           for(j =0; j<VTUN_MAX_INT; j++)
           {
               if(draw < wt_qrr[j] && lfd_host->fs[j].sock_q <4000 && lfd_host->fs[j].tx_flag ==1 && sched_flag[j]==1)
               {
                   sched_flag[j] = 0;
                   break;
               }else if (draw >= wt_qrr[j])
               {
                   // if WRR doesnot work fall to default and select minimum queue
                   sched_flag[min_q] = 0;
                   j = min_q;
                   break;
               }
           }
           ret = j;
       }
       if(ret == -1 || ret == VTUN_MAX_INT||lfd_host->fs[ret].tx_flag ==0)
       {
           q = -1;
           p =6; 
           for(i =0; i<VTUN_MAX_INT;i++){
               if(lfd_host->fs[i].sock_q >=4000 && lfd_host->fs[i].sock_q <10000){
                   if(q == -1)
                       q =i;
                   else if(lfd_host->fs[q].sock_q > lfd_host->fs[i].sock_q)
                       q =i;
               }
               sched_flag[i] = 1;
           }
           if(q != -1 && lfd_host->fs[q].tx_flag ==1 )
               ret = q;
       }

/*
           ret = -1;
           // We need to have minimum among all q >0 
           // But it is okay to go in round robin fashion too
           for(i =0; i<VTUN_MAX_INT;i++)
    	       //if(sched_flag[i]==1 && lfd_host->fs[i].sock_q >0 && lfd_host->fs[i].sock_q <10000)
    	       if(sched_flag[i]==1 && lfd_host->fs[i].sock_q >=3000 && lfd_host->fs[i].sock_q <10000)
    	       {
	           ret= i;
	           sched_flag[ret]=0;
		   p = 4;
                   break;
	       }
           if(ret == -1)
	   {
               //schedule all queues which have q==0
	       if(rates[min_rate]==0.0)
               {
                   p =5;
                   j = 0;
                   for(j =0; j<VTUN_MAX_INT; j++)
                   {
                       count = count+1;
		       count = count%VTUN_MAX_INT;
                       //if(lfd_host->fs[count].tx_flag ==1 && lfd_host->fs[count].sock_q ==0 )
                       if(lfd_host->fs[count].tx_flag ==1 && lfd_host->fs[count].sock_q <3000 )
                          break;
	           }
	           ret = count;
 
               }else{
                   srand(t1.tv_usec);
                   draw = (double)rand()/(double)RAND_MAX;
                   cumsum_rate = 0.0;
	           p =6;
                   for(j =0; j<VTUN_MAX_INT; j++)
	           {
			
	               //if(draw < wt_qrr[j] && lfd_host->fs[j].sock_q ==0 && lfd_host->fs[j].tx_flag ==1)
	               if(draw < wt_qrr[j] && lfd_host->fs[j].sock_q <3000 && lfd_host->fs[j].tx_flag ==1)
		           break;
	           }
		   ret = j;
	       }
               for(j =0; j<VTUN_MAX_INT;j++)
                   sched_flag[j]=1;
	       
	   }
*/
       }
       
       if(ret == -1 || ret == VTUN_MAX_INT )
	   ret = min_q;
       
    }

    vtun_syslog(-1, "RET %d p %d q %d %d rates %f %f rates2 %f, %f  wt %f %f draw %f Q %d %d loss %d %d tf %d",ret,p,lfd_host->fs[0].sock_q,lfd_host->fs[1].sock_q,rates[0],rates[1], rates2[0],rates2[1],wt_qrr[0],wt_qrr[1],draw,q_thresh[0],q_thresh[1],reported_loss[0],reported_loss[1],tx_frame); 
    return ret;
}

/*
	Convert timeval to milliseconds
*/
unsigned long int timeval_ms(struct timeval t)
{
    return (t.tv_usec/1000 + t.tv_sec*1000);
}

/*
    Encapsulate VTUN_EXT_HDR in buffer and store packets in mux for future retransmission
    fd = index of fd 

*/
void encap(my_pkt *t, int fd)
{
    stamp32 g_seq_t;
    stamp16 l_seq_t;
    //stamp16 t_seq_t;
    char    fd_index;
    struct timeval curr_t;
    char *temp;
    char tag;
    temp = t->buf+VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD;

    gettimeofday(&curr_t, NULL);

    //Shift copy outbound packet to add header
    memcpy(temp+VTUN_EXT_HDR,t->buf,t->len);

    g_seq_t.value = mux.c%SEQLEN;

    temp[0] = g_seq_t.stamp[0];
    temp[1] = g_seq_t.stamp[1];
    temp[2] = g_seq_t.stamp[2];
    temp[3] = g_seq_t.stamp[3];

    t->len = t->len+VTUN_EXT_HDR;

    t->fd = lfd_host->fs[fd].fd;
    l_seq_t.value = lfd_host->fs[fd].tx_fs.count;
    temp[4] = l_seq_t.stamp[0];
    temp[5] = l_seq_t.stamp[1];
    
    lfd_host->fs[fd].tx_fs.count = (lfd_host->fs[fd].tx_fs.count+1)%QLEN ;

    //t_seq_t.value = (unsigned int)((curr_t.tv_sec-start_tv.tv_sec)*1000+(curr_t.tv_usec-start_tv.tv_usec)/1000)%65535;
    //temp[6] = t_seq_t.stamp[0];
    //temp[7] = t_seq_t.stamp[1];
    temp[6] = (char)fd;

    t->buf = temp;
    t->ls = l_seq_t.value;
    t->id = fd;
    t->gs = g_seq_t.value;
    return;
}

/*
	Decapsulate packets and update delay differences
	TODO: last_delay and delay_init in Not used
	TODO: Cleanup
*/
void decap(my_pkt *t, uint32_t *g_seq, uint16_t *l_seq, char *idx, fd_state *netfd)
{
    stamp32 g_seq_t;
    stamp16 l_seq_t;

    struct timeval curr_t;
    static int temp[2] = {0,0};
    static int last_ts[2] = {0,0};
    static struct timeval tv[2] = {{0,0},{0.0}};
    static int last_delay[2] = {0,0};

    gettimeofday(&curr_t,NULL);

    g_seq_t.stamp[0] = t->buf[0];
    g_seq_t.stamp[1] = t->buf[1];
    g_seq_t.stamp[2] = t->buf[2];
    g_seq_t.stamp[3] = t->buf[3];
    *g_seq =g_seq_t.value;

    l_seq_t.stamp[0] = t->buf[4];
    l_seq_t.stamp[1] = t->buf[5];
    *l_seq = l_seq_t.value;

    *idx = t->buf[6];
  
    t->len = t->len -VTUN_EXT_HDR;
    t->buf = t->buf+VTUN_EXT_HDR;
    return;
}
/*
	Initialize Multiplexer
*/
int mux_init()
{
    int i;
    struct timeval tv;
    gettimeofday(&tv,NULL);
    /*
    fd independent intialization
    */
    mux.c= 0;
    //mux.path = -1;
    state.blocked = 0;
    state.expected = 0;
    state.block_tv.tv_sec= 0;
    state.block_tv.tv_usec= 0;
    state.loss_timeout = 0;
    state.last_reported = 0;
    mux.rto = -1;
    mux.rtt = 0;
    mux.srtt = 0;
    mux.rttvar = 0;
    mux.lastack_tv.tv_sec = mux.lastack_tv.tv_usec =0;
    sc.gs_1 = 0;
    sc.master =1;
    sc.tag = 0;
    state.final_loss = 0;
    state.block_loss = 0;
    for(i=0; i<VTUN_MAX_INT; i++)
    {
        bzero(&(lfd_host->fs[i].rx_fs),sizeof(rx_fd_state));
        bzero(&(lfd_host->fs[i].tx_fs),sizeof(tx_fd_state));
        lfd_host->fs[i].tx_fs.last_tv = lfd_host->fs[i].rx_fs.last_tv = tv;
        lfd_host->fs[i].idle_timer = 500000;
        lfd_host->fs[i].strict_timer = 300000;
	lfd_host->fs[i].rto =-1;
	lfd_host->fs[i].rtt =0;
	lfd_host->fs[i].srtt =0;
	lfd_host->fs[i].rttvar =0;
        sc.ls_1[i] =0;
        sc.unack_1[i] =0;
    }

    return 1;
}

/***************************
	The multiplexer function
	After reading from TUN interface buffer is written on MUX via this function
	Steps:
	1) Encapuslate and choose path/socket/link via encap()
	2) Store packet for retransmission
	2) write of udp socket
***************************/
int send_broadcast(char *buf, int len)
{
    int ret;
    int i;
    for(i =0; i<VTUN_MAX_INT; i++)
    {
        if(lfd_host->fs[i].fd_flag==1 && lfd_host->fs[i].tx_flag==1)
        {
           ret = send_on_link(buf,len,i);
        }
    }
    return ret;
}
int send_on_link(char *buf, int len, int index)
{
    struct timeval t1;
    my_pkt t;
    t.buf = buf;
    t.len = len;
    int ret;
    int temp1;
    gettimeofday(&t1, NULL);
    if(mux.lastack_tv.tv_sec == mux.lastack_tv.tv_usec && mux.lastack_tv.tv_sec ==0)
    	mux.lastack_tv = t1;
    //vtun_syslog(LOG_ERR,"chosen index %d",index);
    if(index == -1)
       index = choose_link2();
    //vtun_syslog(LOG_ERR,"chosen link %d",index);
    if(index == -1){
        vtun_syslog(-1," choose_link_failed %d",index);
 //TODO: Dirty HACK
	 if(lfd_host->fs[0].fd_flag ==10)
	 	lfd_host->fs[0].fd_flag ==1;
	 if(lfd_host->fs[1].fd_flag ==10)
	 	lfd_host->fs[1].fd_flag ==1;
//       send_broadcast(buf,len);
//       send_on_link(buf,len,0);
//       send_on_link(buf,len,1);
         index = choose_link2();
    if(index == -1){
        vtun_syslog(-1," choose_link_failed exiting %d",index);
		return 1; 
	}
    }
    encap(&t,index);
    index = t.id;
    //if(lfd_host->fs[index].fd_flag !=1)
    if(lfd_host->fs[index].fd_flag ==0)
    {
        vtun_syslog(-1,"Wrong FD %d",index);
      // TODO HACK
		index = (index+1)%2;
    //    exit(1);
    }

    lfd_host->fs[index].tx_fs.last_tv =t1;

    if (lfd_host->fs[index].tx_fs.q.at[t.ls].len != 0)
    {
        if(lfd_host->fs[index].tx_fs.q.at[t.ls].buf != NULL)
            lfd_free(lfd_host->fs[index].tx_fs.q.at[t.ls].buf);
        lfd_host->fs[index].tx_fs.q.at[t.ls].buf = NULL;
        lfd_host->fs[index].tx_fs.q.at[t.ls].len = 0;
    }

    // Now we can write

    lfd_host->fs[index].tx_fs.q.at[t.ls].len = t.len;
    lfd_host->fs[index].tx_fs.q.at[t.ls].buf = (char *)lfd_alloc((t.len)*sizeof(char));
    if(lfd_host->fs[index].tx_fs.q.at[t.ls].buf== NULL)
    {
        vtun_syslog(LOG_ERR,"MALLOC FAILED");
        exit(1);
    }

    // Store it for retransmission

    memcpy(lfd_host->fs[index].tx_fs.q.at[t.ls].buf, t.buf, t.len);
    lfd_host->fs[index].tx_fs.q.at[t.ls].ls = t.ls;
    lfd_host->fs[index].tx_fs.q.at[t.ls].gs = t.gs;
    lfd_host->fs[index].tx_fs.q.at[t.ls].fd = t.fd;
    lfd_host->fs[index].tx_fs.q.at[t.ls].id = t.id;
    lfd_host->fs[index].tx_fs.q.at[t.ls].tv = t1;

//    vtun_syslog(-1,"mux(ls %d, gs %d, fd %d,id %d)",t.ls,t.gs,t.fd,t.id);
    // Timestamp though not being used as of now can
    // regulate input rate of system.(Input rate control)
    /*
        clock_gettime(CLOCK_REALTIME, &mux.q[index].at[t.ls].tag);
        mux.q[index].at[t.ls].tag.tv_nsec += 1000000;

        if( mux.q[index].at[t.ls].tag.tv_nsec> 1000000000)
        {
            mux.q[index].at[t.ls].tag.tv_nsec =  mux.q[index].at[t.ls].tag.tv_nsec -1000000000;
            mux.q[index].at[t.ls].tag.tv_sec +=1;
        }
    */
    // Set start to next packet expected
    lfd_host->fs[index].tx_fs.q.start = (t.ls+1)%QLEN;

    ret = udp_write(t.fd,t.buf,t.len);
    ret = t.len;
    temp1 = lfd_host->fs[index].sock_q;
    if(ioctl(lfd_host->fs[index].fd, SIOCOUTQ, &lfd_host->fs[index].sock_q)!=0)
        lfd_host->fs[index].sock_q = SOCK_Q_MAX;
//if(VTUN_DEBUG)
    vtun_syslog(-1," tx [%d] %d,%d,%d,%d,%d,%s (%d,%d) ",index,t.gs,t.ls,t.id,t.len,len,strerror(errno), lfd_host->fs[0].sock_q,lfd_host->fs[1].sock_q);
    //lfd_host->fs[index].tx_fs.q.at[t.ls].Q = lfd_host->fs[index].sock_q;
    lfd_host->fs[index].tx_fs.q.at[t.ls].Q = temp1;
    if(lfd_host->fs[index].sock_q > temp1)
    	lfd_host->fs[index].tx_fs.q.at[t.ls].dQ = lfd_host->fs[index].sock_q -temp1;
    else 
        lfd_host->fs[index].tx_fs.q.at[t.ls].dQ = 2304;
  
    lfd_host->fs[index].out_data = lfd_host->fs[index].out_data+ len;
/*
    if(temp1 <2000)
    	q_thresh[index] = -1;
    if (temp1 >= 2000 && q_thresh[index]==-1){
	q_thresh[index] = temp1;
    }	
    if(temp1 >= 2000 && q_thresh[index]>0 && temp1 > q_thresh[index])
	q_thresh[index] = temp1;
*/
    return ret;
}
/*
	sends/stores packet in tx queue of link
	selected based upon schedule context state
        state = 3 DUPLICATE, then see the mask and weights, sum will be more than 1 
        state = 2 DYNAMIC, then see the mask and weights between 0 and 1, sum will be 1  
	state = 1 STATIC, then see the mask, select least highest weight (ideally 1 ) 
	state = 0 UNDECIDED,same as 2
	TODO: Finish it
*/
int mux_write(char *buf, int len)
{
    int ret,i;
    int index;
    static num =0;
    
    if(VTUN_DUPLICATE)
        sc.state = VTUN_MAX_INT+1;
    if(VTUN_DYNAMIC)
        sc.state =-1;
    // vtun_syslog(-1,"state %d",sc.state);
    if(sc.state < VTUN_MAX_INT && sc.state >= -1)
	ret = send_on_link(buf,len,sc.state);
    else
        ret = send_on_link(buf,len,-1);
/*
    if(sc.state == -1)
        ret = send_on_link(buf,len,sc.state);
    else if(sc.state < VTUN_MAX_INT && sc.state >= 0 && lfd_host->fs[sc.state].fd_flag ==1 && lfd_host->fs[sc.state].tx_flag ==1)
        ret = send_on_link(buf,len,sc.state);
    else 
        switch(sc.state)
        {
            case VTUN_MAX_INT+1:
                ret = send_broadcast(buf,len);
                break;
            default:
                sc.state =-1;
                vtun_syslog(-1,"Something went wrong");
                ret = send_on_link(buf,len,-1);
                break;
        }
*/    
    mux.c = (mux.c+1)%SEQLEN;
    return ret;
}

/**************************
	Alternate function for mux transmission
	It can be used for delaying transmission
	hence rate control traffic.
	TODO:
	1) For packet to transmit using this we
	need to comment udp_write() from mux_write
	2) Preferably use pthread

**************************/
/*
int mux_write2( struct timespec ts, int i)
{
    //int i;

    my_pkt t;
    while(lfd_host->fs[i].tx_fs.q.start != lfd_host->fs[i].tx_fs.q.end)
    {
        t = lfd_host->fs[i].tx_fs.q.at[lfd_host->fs[i].tx_fs.q.end];
        if(t.tag.tv_sec > ts.tv_sec)
            break;
        else if(t.tag.tv_sec == ts.tv_sec && t.tag.tv_nsec >= ts.tv_nsec)
            break;

        if(udp_write(t.fd, t.buf,t.len)>0)
            lfd_host->fs[i].tx_fs.q.end = (lfd_host->fs[i].tx_fs.q.end +1)%QLEN;
        else
            break;
    }

    return 1;
}
*/
/************************
	Initialize Queues
************************/
int Queue_init()
{
    int i = 0;
    int j = 0;
    state.expected = 0;
    state.loss_timeout = 60;
    state.last_reported =0;
    temp_probe = (probe_t *)lfd_alloc(sizeof(probe_t));
    for(i =0; i<VTUN_MAX_INT;i++)
    {
	for(j=0;j<QLEN;j++)
	{
		lfd_host->fs[i].tx_fs.q.at[j].len=0;
		lfd_host->fs[i].tx_fs.q.at[j].tv.tv_sec=0;
		lfd_host->fs[i].rx_fs.q.at[j].len=0;
		lfd_host->fs[i].rx_fs.q.at[j].tv.tv_sec=0;
        }
	lfd_host->fs[i].lost_count = 0;
	lfd_host->fs[i].timeout_count = 0;
	lfd_host->fs[i].in_data = 0;
	lfd_host->fs[i].out_data = 0;
    }
    return 0;
}
/*******************
	Most important function:
	1) update current time
	2) if any of the link has reported loss and timeout has occured break wait
	3) do while
		a) if more than 50 packets are already written on tun/tap break the loop
		   for recieving more packets from udp sockets
		b) if we are at wait_pos (position till which we have recovered data
		   while through retransmission). It should help in sending packets
		   while bulk losses and larger delay for recovering all packets
		c) adjust start and end of queues considering some losses
		d) find q1len and q2len
		e) if above values are zero i.e. both queues are empty return;
		e) if qXseq is nonzero select q1seq and q2seq as global sequence number of end of queue
			i) otherwise largest possible global sequence number as qXseq
		f) if one link is empty and another one is not empty
			i) start block state if not started already and set block_tv with current time and retrun
			ii) if started already, check timeout if has occured or not
				1) if timeout has occured toggle block state
				2) otherwise return;
		g) reset block variables
		g) select queue for transmission having minimum qXseq
		h.1) use dev_write() to write packet on tun/tap interface
		h.2) use dev_write2() to write packet on order queue to subdue delay variation due to retransmission
		i) count number of packet processed
         4) return

*******************/
int  reorder_send()
{
    int q1len, q2len,q1seq,q2seq;
    int qlen[VTUN_MAX_INT];
    int qseq[VTUN_MAX_INT];
    int sum_qlen;
    int empty_q;
    int valid_q;
    int min_q;
    int i;
    struct tcphdr *tcp;
    struct ip *ip;
    struct timeval temp_tv;
    int temp[2]= {0,0};
    int count = 0;
    reorder_send_flag = 0;
    int d1 =0;
    int block_timeout = 0;
    int temp_timeout = 0;
 
    for (i = 0; i <VTUN_MAX_INT; i++)
	if(lfd_host->fs[i].fd_flag ==1){
		if(block_timeout < lfd_host->fs[i].strict_timer)
			block_timeout = lfd_host->fs[i].strict_timer;
		if(temp_timeout == 0 || temp_timeout > lfd_host->fs[i].idle_timer)
			temp_timeout = lfd_host->fs[i].idle_timer;
	}
    if(temp_timeout < block_timeout)
	block_timeout = (temp_timeout*9)/10;

   //TODO: is it correct ?
   if(block_timeout <1000 || block_timeout > 1000000)
   {
	block_timeout =10000000;
   }
//   block_timeout = 2*block_timeout;
    gettimeofday( &temp_tv, NULL);

    do
    {
        // For each queue
        // 1) if loss has happened, break for loop
        // 2) if global sequence is greater equal to expected, break the loop
        // 3) if global sequence is less than expected, free this (failsafe or flushing or failed retx), continue
        // 4) otherwise increase end and contniue

        //for(i=0; i<2; i++)
        for(i=0; i<VTUN_MAX_INT; i++)
        {
            //if(lfd_host->fs[i].fd>0 &&lfd_host->fs[i].fd_flag==1)
            if(lfd_host->fs[i].fd_flag==1 || lfd_host->fs[i].fd_flag==10)
            {

                if(lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].len == -1)
                {
			if( diff_tv_us(temp_tv, lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].tv) < block_timeout)
                    		return 1;

			else
			 lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].len == 0;
                         
                     lfd_host->fs[i].timeout_count++;
		    vtun_syslog(-1,"loss timeout %d, at %d, len %d, timeout %d",i,lfd_host->fs[i].rx_fs.q.end,lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].len, block_timeout/1000);
                }
         
       	    }
       }
        for(i=0; i<VTUN_MAX_INT; i++)
        {
            //if(lfd_host->fs[i].fd>0 &&lfd_host->fs[i].fd_flag==1)
            if(lfd_host->fs[i].fd_flag==1|| lfd_host->fs[i].fd_flag==10)
            {
       // pthread_mutex_lock( &mutex );
                while(lfd_host->fs[i].rx_fs.q.end != lfd_host->fs[i].rx_fs.q.start)
                {
                    if((lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].len >0)&&(lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].gs < state.expected))
                    {
                        free(lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].buf);
                        lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].len =0;
                    }
                    if((lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].len >0)&&(lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].gs >= state.expected))
                        break;
                    lfd_host->fs[i].rx_fs.q.end = (lfd_host->fs[i].rx_fs.q.end+1)%QLEN;
                }
               // pthread_mutex_unlock( &mutex );
            }

        }

        sum_qlen = 0;
        empty_q = 0;
        valid_q = 0;
        min_q = -1;
        for(i=0; i<VTUN_MAX_INT; i++)
        {
            
            //if(lfd_host->fs[i].fd>0 &&lfd_host->fs[i].fd_flag==1)
            if(lfd_host->fs[i].fd_flag==1|| lfd_host->fs[i].fd_flag==10)
            {
     //           pthread_mutex_lock( &mutex );
                if(min_q== -1)
                    min_q = i;
                qlen[i] = (lfd_host->fs[i].rx_fs.q.start >=lfd_host->fs[i].rx_fs.q.end)?(lfd_host->fs[i].rx_fs.q.start -lfd_host->fs[i].rx_fs.q.end):(QLEN+lfd_host->fs[i].rx_fs.q.start -lfd_host->fs[i].rx_fs.q.end);
                sum_qlen = sum_qlen +qlen[i];
                qseq[i] = (qlen[i]==0)? SEQLEN:lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].gs;
                if(empty_q !=1)
                    empty_q = (qlen[i]==0)? 1:0;
                if(qseq[i]>=state.expected && valid_q !=1)
                    valid_q =1;

       //         pthread_mutex_unlock( &mutex );
            }
            else qseq[i] = SEQLEN;
            if(qseq[min_q]>qseq[i])
                min_q = i;
        }
    //    if(state.blocked ==1)
//        if(state.expected != 0 && sum_qlen !=0)
     //   vtun_syslog(-1," min_q %d,sum_qlen %d,empty_q %d,valid_q %d expected %d",min_q,sum_qlen,empty_q,valid_q,state.expected);
        if(sum_qlen==0 || valid_q ==0){
            if(sum_qlen)
            vtun_syslog(-1,"invalid %d", sum_qlen);
            return 1;
         }
        //If one of the queue is empty OR QxSeq is greater than expected wait for packet on another queue
        // AND if not using just one link
        // Block reorder if not blocked and return
        // If already blocked, till block_timeout, simply return
        // Otherwise, we are going to unblock after this
        if(valid_q ==1 && empty_q ==1 && qseq[min_q]!=state.expected)
        {
            //BLOCKING
           // if(sc.state>1)
           // {
                //Already blocked
                if(state.blocked == 0)
                {
                    state.blocked = 1;
                    state.block_tv.tv_sec = temp_tv.tv_sec;
                    state.block_tv.tv_usec = temp_tv.tv_usec;
//                    vtun_syslog(-1," block |%d %d<%d>] |%d %d<%d>]",lfd_host->fs[0].rx_fs.q.start,lfd_host->fs[0].rx_fs.q.end,lfd_host->fs[0].rx_fs.q.at[lfd_host->fs[0].rx_fs.q.end].gs,lfd_host->fs[1].rx_fs.q.start,lfd_host->fs[1].rx_fs.q.end,lfd_host->fs[1].rx_fs.q.at[lfd_host->fs[1].rx_fs.q.end].gs);
                    return 1;
                }

                if(diff_tv_us(temp_tv,state.block_tv) < block_timeout)
                {

                    state.blocked ++;
//                    vtun_syslog(-1," block wait %d", (temp_tv.tv_sec - state.block_tv.tv_sec)*1000 +(temp_tv.tv_usec -state.block_tv.tv_usec)/1000);
                    return 1;
                }
            //    else
              //      vtun_syslog(-1," [%d,%d,q(%d,%d)]",state.blocked, (temp_tv.tv_sec-state.block_tv.tv_sec)*1000+(temp_tv.tv_usec-state.block_tv.tv_usec)/1000,q1len,q2len);

          //  }

        }
        //if system is blocked previously but not blocked now
        if(state.blocked > 0 && state.expected >0)
        {
            if(qseq[min_q] != state.expected){
            vtun_syslog(-1,"unblocked %d,%d > %d valid_q %d empty_q %d qseq[min_q] %d expected %d",state.blocked, diff_tv(temp_tv,state.block_tv),block_timeout/1000,valid_q,empty_q,qseq[min_q],state.expected);
            state.block_loss++;
            }
            state.blocked = 0;
            state.block_tv.tv_sec = 0;
            state.block_tv.tv_usec = 0;
        }

        //i =(q1seq<q2seq)?0:1;
        if(min_q<0){
	    vtun_syslog(-1," min_q<0");
            return 1;
	}

//        vtun_syslog(-1,"reordering %d, %d, %d", valid_q, empty_q, min_q);
        //check for basic sanity
        /*
        tcp =NULL;
        ip = (struct ip*)q[i].at[q[i].end].buf;
        if( 4!=ip->ip_v ||
                5<ip->ip_hl || (q[i].at[q[i].end].len<ip->ip_hl*4))
        {
            fprintf(stderr,"invalid_packet!\n");
        }
        else if(ip->ip_p == IPPROTO_TCP)
        {

            tcp=(struct tcphdr *)(q[i].at[q[i].end].buf+ip->ip_hl*4);
        //        if(tcp != NULL)
        //        vtun_syslog(-1,"TCP seq %u",ntohl(tcp->seq));
        }
        */

//        dev_write(q[i].fd,q[i].at[q[i].end].buf,q[i].at[q[i].end].len);
    //    vtun_syslog(-1, "fd  %d, buf %d, len %d ",lfd_host->fs[min_q].rx_fs.q.fd,lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].buf,lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].len );
        //dev_write(lfd_host->fs[min_q].rx_fs.q.fd,lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].buf,lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].len);
        if(state.expected > lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].gs){
        free(lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].buf);
        lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].len = 0;
        lfd_host->fs[min_q].rx_fs.q.end = (lfd_host->fs[min_q].rx_fs.q.end+1)%QLEN;
        vtun_syslog(-1," freeing gs %d ls %d fd %",lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].gs,lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].ls,min_q);
        continue;
        }
        dev_write(lfd_host->loc_fd,lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].buf,lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].len);
//        vtun_syslog(-1," out %d,%d,%d,%d",lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].gs,lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].ls,lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].len,min_q);
        if(state.expected != lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].gs){
	state.final_loss = state.final_loss+(lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].gs-state.expected);
  //vtun_syslog(-1," state.blocked %d,min_q %d,sum_qlen %d,empty_q %d,valid_q %d expected %d",state.blocked,min_q,sum_qlen,empty_q,valid_q,state.expected);
	vtun_syslog(-1," [%lu:%lu] %u(%u):e%u,q(%u),l(%u)",temp_tv.tv_sec,temp_tv.tv_usec,lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].gs,lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].ls,state.expected,qseq[min_q],qlen[min_q]);
	}
        free(lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].buf);
        lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].len = 0;
        state.expected = lfd_host->fs[min_q].rx_fs.q.at[lfd_host->fs[min_q].rx_fs.q.end].gs+1;
        lfd_host->fs[min_q].rx_fs.q.end = (lfd_host->fs[min_q].rx_fs.q.end+1)%QLEN;
        count ++;
        //if((state.last_reported + 100)%SEQLEN<state.expected)
	//	respond_back(2,state.expected,ACK);
        
    }
    while(sum_qlen >0 );
    return 1;

}
/********************************
	function to send report messages
	right now just sends ACK,
	TODO: add loss_info etc
*********************************/
void respond_back(int index, unsigned int l_seq, int flag)
{
    report_pkt *rpkt= (report_pkt *)lfd_alloc(sizeof(report_pkt));
    ack_t ack;
    int i;
    switch(flag)
    {
    case 1:
            rpkt->tag='V';
            rpkt->type = ACK;
            ack.gs = state.expected;
	    for(i =0; i<VTUN_MAX_INT; i++){
                ack.l[i] = lfd_host->fs[i].rx_fs.last_rcvd;
            }
            rpkt->info.ack = ack;
            // Sending it on default interface 
            udp_write(lfd_host->fs[0].fd, (void *)rpkt, sizeof(report_pkt));
            state.last_reported = state.expected;

        break;
    case 2:
        break;
    case 3:
        // LOSS
        rpkt->tag='V';
        rpkt->type = LOSS;
        rpkt->info.loss_info = lfd_host->fs[index].rx_fs.li_tx;

        // Sending it on default interface 
        udp_write(lfd_host->fs[0].fd, (void *)rpkt, sizeof(report_pkt));

        break;

    }
    if(rpkt !=NULL)
        lfd_free(rpkt);
    rpkt =NULL;

    return ;
}
/***********************
	Second most important function

	1) decapsulate packets

	2) if local sequence number is more than QLEN, check for retransmitted packets
		a) for each link if (local sequence number - last sent loss timestamp)
		   falls within loss range select that link
		b) rectify actual local sequence number

	3) local sequence number is more than expected local sequence number i.e. loss occurred**
		a) if the link is in lost state, then dont do anything as we are ignoring subsequent losses as of now
		b) otherwise, set state parameters, which will trigger transmission of loss info to peer in future
		c) TODO: we can randomize or find a way reduce number of retransmission request as retransmission
		   for congestion loss is not desired.

	4) local sequence number is equal to expected location 'pos', update pos

	5) if local sequence is less than expected it must be retransmitted once, so update wait_pos
	   so that reorder can go ahead with keeping lost lock.
		a) if we have completed retransmission request, just toggle lost state

	6) if there is already a packet where we want to write it, inform "BUFFER OVERFLOW"

	7) Allocate new memory and copy packet, update all packet informations

	8) if the packet was retransmitted buffer, update time tag as per loss's time interval

		a) Otherwise assign current time as time tag on the packet***

	9) call reorder_send to reorder recieved and recovered packets

	10) respond_back with delay, loss, ack indication (TODO: just ACK is supported right now)


	** We assume there is no reordering among packet transmitted on same link
	*** Since this time tag can be used to transmit packets with a certain delay value after reorder
            this will delay all normal packets and retransmitted packets will be less delayed as their
	    tag represents time when they are identified rather than actually recovered [Delay based waterfilling :-)]

**********************/
int Queue_write( int fd, char *buf, int len, fd_state *netfd)
{
    int q1len, q2len,q1seq,q2seq;
    int i,prev_flag;
    uint32_t g_seq;
    uint16_t l_seq;
    struct ip *ip;
    struct tcphdr *tcp;
    int loc,num;
    struct timeval temp_tv,t1,t2;
    //struct timespec ts;
    int max_delay = 0;
    int loss_by_pass = 1;
    my_pkt t;
    char idx;
    int temp_idx;
    t.buf = buf;
    t.len = len;
    prev_flag = 0;
    gettimeofday(&t1,NULL);

    //clock_gettime(CLOCK_REALTIME, &ts);
    decap (&t, &g_seq, &l_seq, &idx, netfd);
    vtun_syslog(-1,"QW %d %d %d",g_seq, l_seq, idx); 
    if(fetch_idx(netfd->fd)==idx)
     {
        i = idx;
//        t.delay = diff_tv(t1,sc.reference_tv[i])+sc.rtt0[i]- t.delay;
//        lfd_host->fs[i].rx_fs.in_delay = (lfd_host->fs[i].rx_fs.in_delay + t.delay)/2;
          lfd_host->fs[i].in_data = lfd_host->fs[i].in_data+ t.len;
     }
    else{
        if(idx >= VTUN_MAX_INT && idx < 2*VTUN_MAX_INT)
        {
            // THIS IS FLUSHED PACKET
            i = idx-VTUN_MAX_INT;
        }else if(idx >2*VTUN_MAX_INT)
	{
            // THIS IS RETX PACKET
            vtun_syslog(-1, " retx nq %d,%d,%d,%d,%d<-> %d lost %d", g_seq, l_seq, idx, len,i,idx-2*VTUN_MAX_INT-1,lfd_host->fs[i].rx_fs.lost);
            i = idx-2*VTUN_MAX_INT-1;
            loss_by_pass = 0;
           // if(lfd_host->fs[i].rx_fs.lost == 0)
             //   return 1;
            
        }
	//TODO : THIS IS NOT CORRECT FIX
	else
	{ 
          vtun_syslog(LOG_ERR,"fetch_idx fail %d!=%d,",fetch_idx(netfd->fd),index);
	  
          vtun_syslog(LOG_ERR,"%d %d",l_seq,g_seq);
	  return 1;
	  //i = idx;
		
	}
    }
//if(VTUN_DEBUG)
    vtun_syslog(-1, " nq %d,%d,%d,%d,%d", g_seq, l_seq, idx, len,i);
    // Since we round off local sequence after QLEN, we need to add one more condition
    if(loss_by_pass &&((l_seq > lfd_host->fs[i].rx_fs.pos) || (lfd_host->fs[i].rx_fs.pos-l_seq > 9*QLEN/10))){
       num = (l_seq -lfd_host->fs[i].rx_fs.pos >0) ?(l_seq - lfd_host->fs[i].rx_fs.pos):(l_seq - lfd_host->fs[i].rx_fs.pos+QLEN);
       vtun_syslog(-1," [%lu:%lu] loss[%d] ls %d: pos %d: num %d",t1.tv_sec ,t1.tv_usec,i,l_seq,lfd_host->fs[i].rx_fs.pos,num);

       if(1)
       {
/*
           lfd_host->fs[i].rx_fs.lost =1;
           lfd_host->fs[i].rx_fs.loss_flag =1;
           lfd_host->fs[i].rx_fs.loss_tv =t1;
           lfd_host->fs[i].rx_fs.wait_pos =lfd_host->fs[i].rx_fs.pos;
*/           
           lfd_host->fs[i].rx_fs.li_tx.fd =i;
           lfd_host->fs[i].rx_fs.li_tx.start =lfd_host->fs[i].rx_fs.pos ;
           lfd_host->fs[i].rx_fs.li_tx.len =  num;
           lfd_host->fs[i].rx_fs.li_tx.stamp = (lfd_host->fs[i].rx_fs.li_tx.stamp +1)%500;
           respond_back(i,0,LOSS);
           
       }//else
          // vtun_syslog(-1,"LOSS more than 5");
//=====================
      while( lfd_host->fs[i].rx_fs.pos != l_seq)
      {
        if (num <6)
       		lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.pos].len = -1; 
        else 
       		lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.pos].len = 0; 
        lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.pos].tv = t1; 
	lfd_host->fs[i].rx_fs.pos = (lfd_host->fs[i].rx_fs.pos +1)%QLEN;
        lfd_host->fs[i].lost_count = lfd_host->fs[i].lost_count+1;
      }
//=====================      
       lfd_host->fs[i].rx_fs.pos = (lfd_host->fs[i].rx_fs.pos +1)%QLEN;
    } else if(l_seq == lfd_host->fs[i].rx_fs.pos){
       lfd_host->fs[i].rx_fs.pos = (lfd_host->fs[i].rx_fs.pos +1)%QLEN;
    } 
  
/* 
    if(!loss_by_pass){
       vtun_syslog(-1,"retx state ls %d, start %d, len %d",l_seq,lfd_host->fs[i].rx_fs.li_tx.start,lfd_host->fs[i].rx_fs.li_tx.len);
       if(l_seq == (lfd_host->fs[i].rx_fs.li_tx.start +lfd_host->fs[i].rx_fs.li_tx.len -1)%QLEN)
       {
          lfd_host->fs[i].rx_fs.lost = 0; 
          vtun_syslog(-1," [%d]retx done",(-lfd_host->fs[i].rx_fs.loss_tv.tv_sec +t1.tv_sec)*1000 +(-lfd_host->fs[i].rx_fs.loss_tv.tv_usec +t1.tv_usec)/1000);
       }else
          lfd_host->fs[i].rx_fs.wait_pos = (lfd_host->fs[i].rx_fs.wait_pos+1)%QLEN;
   	vtun_syslog(-1," retx stat: i %d, l_seq %d, pos %d lost %d",i,l_seq,lfd_host->fs[i].rx_fs.pos,lfd_host->fs[i].rx_fs.lost); 
    }
*/
    // loc can be removed though, I am continuing use of it
    loc = l_seq;

    pthread_mutex_lock( &mutex );
    if(lfd_host->fs[i].rx_fs.q.at[loc].len > 0)
    {
        vtun_syslog(-1,"BUFFER OVERFLOW [%d]%d, %d <-> %d",i,l_seq,g_seq,lfd_host->fs[i].rx_fs.q.at[loc].gs);
        free(lfd_host->fs[i].rx_fs.q.at[loc].buf);
    }
    lfd_host->fs[i].rx_fs.q.at[loc].buf =(char *)malloc(sizeof(char)*(t.len));

    memcpy(lfd_host->fs[i].rx_fs.q.at[loc].buf,t.buf,t.len);

    lfd_host->fs[i].rx_fs.q.at[loc].len = t.len;
    lfd_host->fs[i].rx_fs.q.at[loc].tv = t1;
    lfd_host->fs[i].rx_fs.q.at[loc].fd = fd;
    lfd_host->fs[i].rx_fs.q.at[loc].ls = l_seq;
    lfd_host->fs[i].rx_fs.q.at[loc].gs = g_seq;

    if(((loc+1)%QLEN > lfd_host->fs[i].rx_fs.q.start) || (lfd_host->fs[i].rx_fs.q.start -(loc+1)%QLEN > QLEN/2))
    {
        lfd_host->fs[i].rx_fs.q.start = (loc+1)%QLEN;
    }
   pthread_mutex_unlock( &mutex );
    //else
    //vtun_syslog(-1,"[%d]l%d<s%d",i,loc,q[i].start);

    if(((loc+1)%QLEN > lfd_host->fs[i].rx_fs.q.lastrecvd) || (lfd_host->fs[i].rx_fs.q.lastrecvd -(loc+1)%QLEN > QLEN/2))
        lfd_host->fs[i].rx_fs.q.lastrecvd = g_seq;

// Lets reorder them
/*
    if(pthread_mutex_trylock( &mutex )==0){
    	reorder_send();
    	pthread_mutex_unlock( &mutex );
    }
*/ 
    lfd_host->fs[i].rx_fs.last_rcvd = l_seq;
//if(!loss_by_pass)
// vtun_syslog(-1,"w %d, at %d, len %d, retx len %d",i,lfd_host->fs[i].rx_fs.q.end,lfd_host->fs[i].rx_fs.q.at[lfd_host->fs[i].rx_fs.q.end].len,lfd_host->fs[i].rx_fs.q.at[l_seq].len);
    return 1 ;
}
/* Modules functions*/

/* Add module to the end of modules list */
void lfd_add_mod(struct lfd_mod *mod)
{
    if( !lfd_mod_head )
    {
        lfd_mod_head = lfd_mod_tail = mod;
        mod->next = mod->prev = NULL;
    }
    else
    {
        lfd_mod_tail->next = mod;
        mod->prev = lfd_mod_tail;
        mod->next = NULL;
        lfd_mod_tail = mod;
    }
}

/*  Initialize and allocate each module */
int lfd_alloc_mod(struct vtun_host *host)
{
    struct lfd_mod *mod = lfd_mod_head;

    while( mod )
    {
        if( mod->alloc && (mod->alloc)(host) )
            return 1;
        mod = mod->next;
    }

    return 0;
}

/* Free all modules */
int lfd_free_mod(void)
{
    struct lfd_mod *mod = lfd_mod_head;

    while( mod )
    {
        if( mod->free && (mod->free)() )
            return 1;
        mod = mod->next;
    }
    lfd_mod_head = lfd_mod_tail = NULL;
    return 0;
}

/* Run modules down (from head to tail) */
inline int lfd_run_down(int len, char *in, char **out)
{
    register struct lfd_mod *mod;

    *out = in;
    for(mod = lfd_mod_head; mod && len > 0; mod = mod->next )
        if( mod->encode )
        {
            len = (mod->encode)(len, in, out);
            in = *out;
        }
    return len;
}

/* Run modules up (from tail to head) */
inline int lfd_run_up(int len, char *in, char **out)
{
    register struct lfd_mod *mod;

    *out = in;
    for(mod = lfd_mod_tail; mod && len > 0; mod = mod->prev )
        if( mod->decode )
        {
            len = (mod->decode)(len, in, out);
            in = *out;
        }
    return len;
}

/* Check if modules are accepting the data(down) */
inline int lfd_check_down(void)
{
    register struct lfd_mod *mod;
    int err = 1;

    for(mod = lfd_mod_head; mod && err > 0; mod = mod->next )
        if( mod->avail_encode )
            err = (mod->avail_encode)();
    return err;
}

/* Check if modules are accepting the data(up) */
inline int lfd_check_up(void)
{
    register struct lfd_mod *mod;
    int err = 1;

    for(mod = lfd_mod_tail; mod && err > 0; mod = mod->prev)
        if( mod->avail_decode )
            err = (mod->avail_decode)();

    return err;
}

/********** Linker *************/
/* Termination flag */
static volatile sig_atomic_t linker_term;

static void sig_term(int sig)
{
    vtun_syslog(LOG_INFO, "Closing connection");
    vtun_syslog(-3,"");
    io_cancel();
    linker_term = VTUN_SIG_TERM;
}

static void sig_hup(int sig)
{
    vtun_syslog(LOG_INFO, "Reestablishing connection");
    io_cancel();
    linker_term = VTUN_SIG_HUP;
}
void
myfunc3(void)
{
/*
    int j, nptrs;
#define SIZE 100
    void *buffer[100];
    char **strings;

    vtun_syslog(LOG_ERR,"SIGSEV RCVD");
   nptrs = backtrace(buffer, SIZE);
    vtun_syslog(LOG_ERR,"backtrace() returned %d addresses", nptrs);

//    The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
//       would produce similar output to the following: 

   strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        vtun_syslog(LOG_ERR,"backtrace_symbols");
        exit(EXIT_FAILURE);
    }

   for (j = 0; j < nptrs; j++)
        vtun_syslog(LOG_ERR,"%s", strings[j]);

   free(strings);
*/
}
static void sig_sigsev(int sig)
{
myfunc3();
}

/* Statistic dump */
void sig_alarm(int sig)
{
/*
    static time_t tm;
    static char stm[20];
    static char stm2[40];
    tm = time(NULL);
    vtun_syslog(LOG_ERR,"ALARM");
    strftime(stm, sizeof(stm)-1, "%b %d %H:%M:%S", localtime(&tm));
    sprintf(stm2,"%s %lu %lu %lu %lu\n", stm,
            lfd_host->stat.byte_in, lfd_host->stat.byte_out,
            lfd_host->stat.comp_in, lfd_host->stat.comp_out);
    write(lfd_host->stat.fd,stm2,40);
    fsync(lfd_host->stat.fd);
    alarm(VTUN_STAT_IVAL);

   ualarm(500000,0);
*/
}

static void sig_usr1(int sig)
{
    /* Reset statistic counters on SIGUSR1 */
    lfd_host->stat.byte_in = lfd_host->stat.byte_out = 0;
    lfd_host->stat.comp_in = lfd_host->stat.comp_out = 0;
}

/***********************
	TUNNEL TO UDP SOCKET/NETWORK OPERATIONS
	1) read from TUN, update states
	2) call all linked modules (original vtun encryption and compression)
	3) write on MUX (which will further encapsulate and store packet for retransmission
	and send it either directly or via pthread to udp sockets)
**********************/
int t2n(int fd2,char* buf)
{
    register int len;
    char* out;
    struct timeval t1,t2;
    gettimeofday(&t1,NULL);
    if( (len = dev_read(fd2, buf, VTUN_FRAME_SIZE)) < 0 )
    {
        if( errno != EAGAIN && errno != EINTR )
            return 0;
        else
            return 1;
    }
    if( !len ) return 0;
    lfd_host->stat.byte_out += len;
    if( (len=lfd_run_down(len,buf,&out)) == -1 )
        return 0;

    //if( len && proto_write(fd1, out, len) < 0 )
    //if( len && mux_write(fd1, out, len) < 0 )
    /*if(sc.state>0 && sc.state<VTUN_MAX_INT) 
        if(lfd_host->fs[sc.state].tx_flag ==1)
    		if( len && mux_write(out, len) < 0 )
        	return 0;

    if(sc.state==-1)
    */
    		if( len && mux_write(out, len) < 0 )
        	return 0;
		
		
    lfd_host->stat.comp_out += len;
//        gettimeofday(&t2,NULL);
    return 1;
}
/*********************
	Retransmission procedure being called upon valid retransmission request from peer
	It codes local sequence with timestamp of loss_info and actual local sequence
	It can use same channel or alternate channel to retransmit
*********************/
int retx(loss_info_t li)
{
    int i;
    int index;
    my_pkt t;
    stamp16 l_seq_t;
    index = li.fd ;
    reported_loss[li.fd] = reported_loss[li.fd]+li.len;
    //q_thresh[li.fd] = q_thresh[li.fd]/2;
    vtun_syslog(-1," retx report [%d] %d",li.fd,li.len);
    if(li.len >5)
    	return 1;
    for(i =0; i<li.len; i++)
        if(lfd_host->fs[index].tx_fs.q.at[i+li.start].len >0)
        {
            t = lfd_host->fs[index].tx_fs.q.at[(i+li.start)%QLEN];
//            l_seq_t.value = t.ls + QLEN*(index+1);
            t.buf[6] = index+VTUN_MAX_INT*2+1;
/*
            t.buf[4] = l_seq_t.stamp[0];
            t.buf[5] = l_seq_t.stamp[1];

// RETX ON SAME CHANNEL
            if(sc.state <= 1)
                udp_write (mux.q[li.fd].at[i+li.start].fd,t.buf,mux.q[index].at[i+li.start].len);
            else
            {
// RETX ON ANOTHER CHANNEL
                {
                    udp_write(mux.l1,t.buf,mux.q[index].at[i+li.start].len);
                    //vtun_syslog(LOG_ERR,"%d error %d",mux.l1,errno);
                }
                else
                {
                    udp_write(mux.l2,t.buf,mux.q[index].at[i+li.start].len);
                    //vtun_syslog(LOG_ERR,"%d error %d",mux.l2,errno);
                }
*/
/*
        if(rates[t.id] <0){
        if(rates[0]<rates[1])
        udp_write(lfd_host->fs[1].fd,t.buf,t.len);
        else
        udp_write(lfd_host->fs[0].fd,t.buf,t.len);
        }else
*/
                //udp_write(lfd_host->fs[t.id].fd,t.buf,t.len);
                udp_write(lfd_host->fs[(index+1)%2].fd,t.buf,t.len);
	 
//        udp_write(get_fastest_fd(lfd_host->fs[t.id].fd),t.buf,t.len);
        //udp_write(t.fd,t.buf,t.len);
//        lfd_free(t.buf);
//        t.buf = NULL;
        vtun_syslog(-1," retx[%d]: ls %d,gs %d Q %d %d dQ %f %f preQ %d %d predQ %d %d -> %d %d$",t.id,t.ls,t.gs,lfd_host->fs[0].sock_q,lfd_host->fs[1].sock_q,rates[0],rates[1],lfd_host->fs[0].tx_fs.q.at[sc.ls_1[0]].Q,lfd_host->fs[1].tx_fs.q.at[sc.ls_1[1]].Q,lfd_host->fs[0].tx_fs.q.at[sc.ls_1[0]].dQ,lfd_host->fs[1].tx_fs.q.at[sc.ls_1[1]].dQ,q_thresh[0],q_thresh[1]);
//        t.len =0;
        }
    return 1;
}
/*********************
	This function is supposed to handle all report packets as of now we are just doing it for ACK
	It will calculate
		1)unack or in-flight packets
		2)weights for WRR
		3)link delay
*********************/
void process_report( int fd, report_pkt rp)
{
    //TODO: include all types of report packets
    int index, sent, diff0,diff1;
    struct timeval tv1;
    int i;
    int diff;
    int temp,frame_start, frame_end;
    switch(rp.type)
    {
    case 1:
        gettimeofday(&tv1,NULL);
        diff = rp.info.ack.gs- sc.gs_1;
        if(diff>0){
        update_rtt(sc.gs_1,tv1);
        update_rto(&mux.srtt, &mux.rttvar, &mux.rto, mux.rtt);
        }
        for(i =0; i<VTUN_MAX_INT; i++){

            if(sc.ls_1[i] != rp.info.ack.l[i] && mux.lastack_tv.tv_sec != 0)
	    {
                        //if(rp.info.ack.l[i]>sc.ls_1[i]){
                        if(diff >0){
			//sc.rtt[i] = diff_tv_us(tv1,lfd_host->fs[i].tx_fs.q.at[sc.ls_1[i]].tv);
			lfd_host->fs[i].rtt = diff_tv_us(tv1,lfd_host->fs[i].tx_fs.q.at[sc.ls_1[i]].tv);
			update_rto(&(lfd_host->fs[i].srtt), &(lfd_host->fs[i].rttvar), &(lfd_host->fs[i].rto), lfd_host->fs[i].rtt);
/**/
                        if(lfd_host->fs[i].rttvar > lfd_host->fs[i].srtt/4)
				lfd_host->fs[i].idle_timer = (lfd_host->fs[i].srtt +3*lfd_host->fs[i].rttvar); 
                        else
				lfd_host->fs[i].idle_timer = (lfd_host->fs[i].srtt +lfd_host->fs[i].srtt/3); 

                        if(lfd_host->fs[i].rttvar > lfd_host->fs[i].srtt/4)
				lfd_host->fs[i].strict_timer = (lfd_host->fs[i].srtt +4*lfd_host->fs[i].rttvar); 
                        else
				lfd_host->fs[i].strict_timer = (lfd_host->fs[i].srtt +4*lfd_host->fs[i].srtt/5); 
/**/
                        }
	    }
            sc.ls_1[i] = rp.info.ack.l[i];
            sc.unack_1[i] = (rp.info.ack.l[i]>lfd_host->fs[i].tx_fs.count)?(lfd_host->fs[i].tx_fs.count- rp.info.ack.l[i] +QLEN):(lfd_host->fs[i].tx_fs.count-rp.info.ack.l[i]);
       
        temp = 0;
        frame_start = sc.ls_1[i];
	frame_end = lfd_host->fs[i].tx_fs.count;
        do
        {
                temp = temp + lfd_host->fs[i].tx_fs.q.at[frame_start].dQ;
        //        vtun_syslog(-1,"[%d][%d] %d %d", index, lfd_host->fs[index].tx_fs.q.at[frame_start].ls,lfd_host->fs[index].tx_fs.q.at[frame_start].dQ,lfd_host->fs[index].tx_fs.q.at[frame_start].Q);
                frame_start = (frame_start +1)%QLEN;
        }
        while(frame_start != (frame_end+1)%QLEN);
	q_thresh[i] = temp;
        tx_frame = 0;
/* 
	   if(lfd_host->fs[i].tx_fs.q.at[sc.ls_1[i]].Q<2000)
		q_thresh[i] = -1;
            if (lfd_host->fs[i].tx_fs.q.at[sc.ls_1[i]].Q >= 2000 && q_thresh[i]==-1){
        	q_thresh[i] = lfd_host->fs[i].tx_fs.q.at[sc.ls_1[i]].Q;
    		}
    	    if(lfd_host->fs[i].tx_fs.q.at[sc.ls_1[i]].Q >= 2000 && q_thresh[index]>0 && lfd_host->fs[i].tx_fs.q.at[sc.ls_1[i]].Q > q_thresh[i])
        	q_thresh[i] = lfd_host->fs[i].tx_fs.q.at[sc.ls_1[i]].Q;
*/

	}
        mux.lastack_tv = tv1;
        sc.gs_1 = rp.info.ack.gs;
        break;
    case 3:
        retx(rp.info.loss_info);
        break;

    }
    return;
}
/**********************
	NETWORK to TUN Device:
	1) read from udp socket
		a) if packet is ECHO send ECHO_REP
		b) if packet is ECHO_REP, if sync is not done, send ECHO on another interface
			i) if sync is not done set it as done
		c) loss_info is received if it is valid trigger retransmission
		d) if report is recieved process it
		e) finally normal data packets will be written on Queue.

*********************/
int n2t(int fd1, int fd2,char* buf)
{
    int idle = 0;
    char *out;
    register int len;
    register int fl;
    char strbuf[10];
    loss_info_t temp_li;
    struct timeval t1;
    struct timeval echo_tv;
    struct timeval echo_rep_tv;
    report_pkt  tmp_report;
    int temp_int;
    fd_state *link_state;
    if( (len=proto_read(fd1, buf)) <= 0 )
        return 0;
    gettimeofday(&t1,NULL);
    /* Handle frame flags */
    fl = len & ~VTUN_FSIZE_MASK;
    len = len & VTUN_FSIZE_MASK;
    if( fl )
    {
        if( fl==VTUN_BAD_FRAME )
        {
            vtun_syslog(LOG_ERR, "Received bad frame");
            return 1;
        }
        if( fl==VTUN_ECHO_REQ )
        {
            /* Send ECHO reply */
            vtun_syslog(LOG_ERR,"recvd ECHO %d",fd1);
            if(peer_tv.tv_sec == 0)
                memcpy(&peer_tv,buf,sizeof(peer_tv));
            memcpy(buf+sizeof(echo_tv),&t1,sizeof(t1));

            if( proto_write(fd1, buf, VTUN_ECHO_REP) < 0 )
                return 0;
            return 1;
        }

        if( fl==VTUN_ECHO_REP )
        {
	    if(sync_flag < 1)
		sync_flag ++;
	    //sc.delay_1[fetch_idx(fd1)] = ((t1.tv_sec-start_tv.tv_sec)*1000+(t1.tv_usec-start_tv.tv_usec)/1000);
//            sc.rtt0[fetch_idx(fd1)] = sc.delay_1[fetch_idx(fd1)];
//            sc.reference_tv[fetch_idx(fd1)] = t1;
            
             //vtun_syslog(LOG_ERR,"RTT is on %d is %d at on %lu:%lu",fetch_idx(fd1),sc.delay_1[fetch_idx(fd1)], t1.tv_sec,t1.tv_usec);
            if(sync_flag ==1)
               vtun_syslog(LOG_ERR,"SYNCED ALL");
            //sync_flag =1;
            return 1;
        }
        if( fl==VTUN_CONN_CLOSE )
        {
            vtun_syslog(LOG_INFO,"Connection closed by other side");
            vtun_syslog(-3,"");
            return 0;
        }
        vtun_syslog(LOG_INFO,"Good Frame -1");
    }


    lfd_host->stat.comp_in += len;
    if( (len=lfd_run_up(len,buf,&out)) == -1 )
        return 0;
    /* We have recieved a valid frame*/
    link_state = fetch_state(fd1);
    link_state->rx_fs.last_tv = t1;
     if(len == sizeof(report_pkt))
     {
         memcpy(&tmp_report, buf, sizeof(report_pkt));
         if(tmp_report.tag == 'V')
         {

            // if (tmp_report.type == LOSS)
            //     vtun_syslog(-1, "[%d] LOSS recieved %d, %d",tmp_report.info.loss_info.fd, tmp_report.info.loss_info.start, tmp_report.info.loss_info.len);
             process_report(fd1,tmp_report);
             return 1;
         }
     }

     if(len == sizeof(probe_t))
     {
         memcpy(temp_probe,buf,len);
         if(temp_probe->tag == 'Q')
         {
/*
		TODO: Very unlikely
             if((temp_probe->i == 0 && fd1 == mux.l2)||(temp_probe->i ==1 && fd1 ==mux.l1))
             {
                 vtun_syslog(-1,"mismatch:( fd %d index %d stamp %d", fd1,temp_probe->i,temp_probe->stamp);
                 return 1;
             }
*/
             lfd_host->fs[temp_probe->i].test = 0;
	     if(sc.state == -1){
		if(lfd_host->fs[temp_probe->i].fd_flag ==10){
                        lfd_host->fs[temp_probe->i].test = 0;
			vtun_syslog(-1,"[%lu : %lu] Adding in agg %d",t1.tv_sec, t1.tv_usec,temp_probe->i);
                        temp_int = get_ctrl_index(lfd_host);
	     		lfd_host->fs[temp_probe->i].fd_flag = 1;
	     		lfd_host->fs[temp_probe->i].tx_flag = 1;
                        send_flag_info(lfd_host,temp_int);
		}
		else 
	     		lfd_host->fs[temp_probe->i].fd_flag = 1;
	     }
             vtun_syslog(-1,"Probe report at %d (%d,%d) stamp %d",temp_probe->i,lfd_host->fs[0].test,lfd_host->fs[1].test, temp_probe->stamp);
             memset(buf,0,sizeof(buf));
             return 1;

         }
         else if(temp_probe->tag =='P')
         {

//             if(temp_probe->i != sc.state)
//             vtun_syslog(-1,"Probe recvd at %d, %d",temp_probe->i,temp_probe->stamp);
             temp_probe->tag = 'Q';
             udp_write(fd1,(char *)temp_probe,sizeof(probe_t));
             memset(buf,0,sizeof(buf));
             if(sc.state == -1){
                if(lfd_host->fs[temp_probe->i].fd_flag ==10){
                        vtun_syslog(-1,"[%lu :%lu]Adding in agg",t1.tv_sec, t1.tv_usec);
			lfd_host->fs[temp_probe->i].test = 0;
                        temp_int = get_ctrl_index(lfd_host);
                	lfd_host->fs[temp_probe->i].fd_flag = 1;
                	lfd_host->fs[temp_probe->i].tx_flag = 1;
                        send_flag_info(lfd_host,temp_int);
		}
               else 
                lfd_host->fs[temp_probe->i].fd_flag = 1;
             }

             return 1;

         }
     }
    if( len && Queue_write(lfd_host->loc_fd,out,len,link_state) < 0 )
    {
        return 1;
    }

    lfd_host->stat.byte_in += len;
    return 1;

}

/**********************
	check priority for interfaces.
***********************/

int check_priority(int fd1,int fd3)
{
    if(fd1_done == fd3_done)
        return fd1-fd3;
    else if(fd1_done > fd3_done)
        return fd3-fd1;
    else
        return fd1-fd3;
}
/*******************
	The main function which runs infinte loop of tunnel-2-network and network-2-tunnel processes
	It also takes care special packets transmission e.g. loss_info and delay/overload messages
******************/
int lfd_linker(void)
{
    int temp_int;
    int fd4 = lfd_host->ctrl;
    int fd2 = lfd_host->loc_fd;
    char ipstr[INET_ADDRSTRLEN];
    char ipstr2[INET_ADDRSTRLEN];
    register int len, fl;
    struct timeval tv,t1,t2;
    char *buf, *out;
    int opt;
    fd_set rdset;
    fd_set rtset;
    int max_fd, idle = 0, tmplen;
    int tmptag;
    switch_info tempsi;
    struct sockaddr_in si_other,saddr;
    int i,j;
    int all_tx_flag = 0;
    opt = sizeof(saddr);
    if( !(buf = lfd_alloc(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD+VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD+VTUN_EXT_HDR)) )
    {
        vtun_syslog(LOG_ERR,"Can't allocate buffer for the linker");
        return 0;
    }

    gettimeofday(&start_tv,NULL);
    memset(buf,0,sizeof(buf));
    memcpy(buf,&start_tv,sizeof(start_tv));
    sync_flag =1; 
    errno = 0;
    vtun_syslog(LOG_ERR,"flags %d,%d",lfd_host->fs[0].fd_flag,lfd_host->fs[1].fd_flag);
    for(i =0; i< VTUN_MAX_INT; i++)
    	if(lfd_host->fs[i].fd_flag == 1){
    		proto_write(lfd_host->fs[i].fd, buf, VTUN_ECHO_REQ);
    		vtun_syslog(LOG_ERR,"sent ECHO_REQ %s on %d at %lu:%lu",strerror(errno),i,start_tv.tv_sec, start_tv.tv_usec);
                sync_flag --;
	}
    /*
        if((maxfd = fd_max())==0)
    	return 0;
    */
    memset(&t1,0,sizeof(t1));
    memset(&t2,0,sizeof(t2));
    linker_term = 0;
    while( !linker_term )
    {
        //Resetting errno
        errno = 0;
        //Fetch current time
        gettimeofday(&t2,NULL);
//      Wait for data 
        FD_ZERO(&rdset);
        FD_ZERO(&rtset);

        FD_SET(lfd_host->loc_fd, &rdset);
        FD_SET(lfd_host->ctrl, &rdset);

        if(lfd_host->loc_fd>lfd_host->ctrl)
            max_fd = lfd_host->loc_fd;
        else
            max_fd = lfd_host->ctrl;
        
     
        for(i=0; i<VTUN_MAX_INT; i++)
        {
            if(lfd_host->fs[i].fd_flag ==1 || lfd_host->fs[i].fd_flag ==10)
            {       
                FD_SET(lfd_host->fs[i].fd, &rdset);
                FD_SET(lfd_host->fs[i].fd, &rtset);
                if(max_fd<lfd_host->fs[i].fd)
                    max_fd = lfd_host->fs[i].fd;
            }
            lfd_host->fs[i].tx_flag = 0;
            //lfd_host->fs[i].tx_flag = 1;
        }

        for(i=0; i<VTUN_MAX_INT; i++)
        {
            if(lfd_host->fs[i].fd_flag ==2)
            {       
                FD_SET(lfd_host->fs[i].fd, &rdset);
                if(max_fd<lfd_host->fs[i].fd)
                    max_fd = lfd_host->fs[i].fd;
            }
        }
        
        tv.tv_sec  = lfd_host->ka_interval;
        tv.tv_usec = 0;
        if( (len = select(max_fd+1, &rdset, &rtset, NULL, &tv)) < 0 )
        {
            if( errno != EAGAIN && errno != EINTR )
                break;
            else
                continue;
        }
        gettimeofday(&tv,NULL);
//        vtun_syslog(LOG_ERR,"max_fd %d nl %d, ctrl %d, %d, %d",max_fd,lfd_host->nl,lfd_host->ctrl,lfd_host->fs[0].fd,lfd_host->fs[1].fd);
        //vtun_syslog(LOG_ERR,"%d %d %d %d",len, max_fd, lfd_host->ctrl,lfd_host->loc_fd); 

        ctrl_msg cm; 
        //TODO: This is for self triggering of Offloading
        if(1)
        if(mux.rto>0 && diff_tv_us(tv,mux.lastack_tv)>mux.rto)
        {
            //  if(sc.master ==1 && lfd_host->role ==1 )
              if(sc.master ==1 )
              {
//              vtun_syslog(-1,"  link %d has timed out probe report(%d,%d)",sc.state,lfd_host->fs[0].test,lfd_host->fs[1].test);
                   if(sc.state == -1){
		     // find whether any of active link is more than 2 
                     temp_int = 0;
                     for (i =0; i<VTUN_MAX_INT;i++)
			{
				if(lfd_host->fs[i].fd_flag ==1 &&lfd_host->fs[i].test>1)
				{
					temp_int =1;
					break;	
				}
			}
			if(temp_int ==1){
                                vtun_syslog(-1,"[%d] switched to Probing RTO %lu",i,mux.rto);
		        	lfd_host->fs[i].fd_flag =10;	
			}
			
		   }
                   else if(sc.state < VTUN_MAX_INT && sc.state >= 0)
                   {
                            // find appropriate link to transmit
                            // TODO : select best QoS providing link
//                            if(lfd_host->fs[sc.state].test>1){
			    if(sc.state != (temp_int =get_next_fd(sc.state)))
                            { 
			    tmplen = sc.state;
		            sc.state = temp_int;	
                            gettimeofday(&tv,NULL);
                            mux.lastack_tv = tv;
                            tempsi.type =1;
                            tempsi.state =sc.state;
                            tempsi.master =sc.master;
                            cm.type = SWITCH_INFO;
                            cm.si = tempsi;
 
                            sendfromto(lfd_host->ctrl,(char *)&cm,sizeof(cm),0,(struct sockaddr *)&(lfd_host->fs[sc.state].saddr), sizeof(lfd_host->fs[sc.state].saddr),(struct sockaddr *)&(lfd_host->fs[sc.state].daddr), sizeof(lfd_host->fs[sc.state].daddr));
                           inet_ntop(AF_INET, &(lfd_host->fs[sc.state].daddr.sin_addr), ipstr, INET_ADDRSTRLEN); 
                           inet_ntop(AF_INET, &(lfd_host->fs[sc.state].saddr.sin_addr), ipstr2, INET_ADDRSTRLEN); 
                            vtun_syslog(-1," switching info sent to %s:%s->%s %d ",strerror(errno),ipstr2,ipstr,ntohs(lfd_host->fs[sc.state].daddr.sin_port));
                            // updating lastack_tv 
                            mux.lastack_tv = tv;
                            flush_link(tmplen);
                            mux.rto = 6*mux.rto;
                            }
			

                   }
		
             }
       }
                if(1) 
                if(sync_flag == 1)
                {
                    memset(buf,0,sizeof(buf));

                    for(i =0; i<VTUN_MAX_INT;i++)

                    if(lfd_host->fs[i].idle_timer > 0)
                    if((lfd_host->fs[i].fd_flag ==1 && diff_tv(tv,lfd_host->fs[i].rx_fs.last_tv)>lfd_host->fs[i].idle_timer/1000) || (lfd_host->fs[i].fd_flag ==10 && diff_tv(tv,lfd_host->fs[i].rx_fs.last_tv)> lfd_host->fs[i].idle_timer/500))
                    {
                      
                        vtun_syslog(-1,"Probed %d %lu:%lu - %lu:%lu> %d {%d,%d}", i,tv.tv_sec,tv.tv_usec,lfd_host->fs[i].rx_fs.last_tv.tv_sec,lfd_host->fs[i].rx_fs.last_tv.tv_usec,lfd_host->fs[i].idle_timer,lfd_host->fs[0].test,lfd_host->fs[1].test);
                        lfd_host->fs[i].rx_fs.last_tv =tv;
                        lfd_host->fs[i].test++;
                        temp_probe->i = i;
                        temp_probe->tag ='P';
                        temp_probe->stamp = tv.tv_usec%1000;
                        memcpy(buf,temp_probe,sizeof(probe_t));
			// Disabling probing
                        proto_write(lfd_host->fs[i].fd, buf, sizeof(probe_t));
			vtun_syslog(-1,"IDLE Probing %d flag %d ",i,lfd_host->fs[i].fd_flag);

			if(lfd_host->fs[i].fd_flag ==1 && lfd_host->fs[i].test >5 && sc.state == -1){
				temp_int = 0;
				for(j=0;j<VTUN_MAX_INT;j++)
				{	
					if(lfd_host->fs[j].fd_flag==1)
					temp_int++;
				}
				if(temp_int >1)
				{

				lfd_host->fs[i].fd_flag =10;
				vtun_syslog(-1,"Removing link %d from agg ctrl %d,idle_timer %lu, flag %d",i,get_ctrl_index(lfd_host),lfd_host->fs[i].idle_timer, lfd_host->fs[i].fd_flag);
                                send_flag_info(lfd_host,get_ctrl_index(lfd_host));
                                flush_link(i);

				}
				//VTUN_DEBUG = 1;
			}

                    }//else if(state.expected >0 && lfd_host->fs[i].fd_flag ==1)
                    

               }

        
        /*
               TODO:convention: fds[0] will be a default interface for simplicity at this stage
        */

        if( !len )
        {
	    //vtun_syslog(-1,"before len <0");
            if (send_a_packet)
            {
	    //vtun_syslog(-1,"send_a_packet");
                send_a_packet = 0;
                tmplen = 1;
                lfd_host->stat.byte_out += tmplen;
                if( (tmplen=lfd_run_down(tmplen,buf,&out)) == -1 )
                    break;
                //if( tmplen && proto_write(fd1, out, tmplen) < 0 )
                if( tmplen && proto_write(lfd_host->fs[0].fd, out, tmplen) < 0 )
                    break;
                lfd_host->stat.comp_out += tmplen;
            }
            /* We are idle, lets check connection */
            if( lfd_host->flags & VTUN_KEEP_ALIVE )
            {
	    //vtun_syslog(-1,"keep a live");
                if( ++idle > lfd_host->ka_failure )
                {
                    vtun_syslog(LOG_INFO,"Session %s network timeout", lfd_host->host);
                    break;
                }
                /* Send ECHO request */
                //if( proto_write(fd1, buf, VTUN_ECHO_REQ) < 0 )
                if( proto_write(lfd_host->fs[0].fd, buf, VTUN_ECHO_REQ) < 0 )
                    break;
            }
            continue;
        }
        /*
                TODO:No priority as of now
        */
        else
        {
	    //vtun_syslog(-1,"before len >0");
            if(FD_ISSET(lfd_host->ctrl, &rdset))
            {
		//vtun_syslog(-1,"before ctrl");
                tmplen = recvfrom(lfd_host->ctrl,buf,1024,0,(struct sockaddr*)&saddr,&opt);
                if(tmplen >0)parse_ctrl_msg(buf,tmplen,lfd_host,saddr);
            }
         
            all_tx_flag =0;
            for(i =0; i<VTUN_MAX_INT; i++)
            {
                 if((lfd_host->fs[i].fd_flag ==1 | lfd_host->fs[i].fd_flag ==10)&& FD_ISSET(lfd_host->fs[i].fd, &rtset))
                   lfd_host->fs[i].tx_flag = 1;
//                   vtun_syslog(LOG_ERR,"%d",lfd_host->fs[i].fd); 
                 all_tx_flag = all_tx_flag + lfd_host->fs[i].tx_flag;
            }

            for(i =0; i<VTUN_MAX_INT; i++)
            {
		//vtun_syslog(-1,"before n2t");
                if((lfd_host->fs[i].fd_flag ==1 || lfd_host->fs[i].fd_flag ==10) && FD_ISSET(lfd_host->fs[i].fd, &rdset) && lfd_check_up())
                {
                    if(n2t(lfd_host->fs[i].fd,lfd_host->loc_fd,buf)==1)
                        continue;
                    else
                        break;
                }
            }
            if( FD_ISSET(lfd_host->loc_fd, &rdset) && lfd_check_down() && (all_tx_flag > 0))
            {
		//vtun_syslog(-1,"before t2n");
                if(t2n(lfd_host->loc_fd,buf)==1)
                    continue;
                else
                    break;
            }
            for (i =0;i<VTUN_MAX_INT;i++)
            {
		//vtun_syslog(-1,"before ctrl2");
		if(lfd_host->fs[i].fd_flag ==2 && FD_ISSET(lfd_host->fs[i].fd, &rdset))
		{
			tmplen = recvfrom(lfd_host->fs[i].fd,buf,1024,0,(struct sockaddr*)&saddr,&opt);
                	if(tmplen >=0)parse_ctrl_msg(buf,tmplen,lfd_host,saddr);
		
		}
	    }
        
        //vtun_syslog(-1,"before before end of big loop");
	}

        //vtun_syslog(-1,"before end of big loop");
    } // The Big loop ends here
    //vtun_syslog(-1,"after big loop");
    if( !linker_term && errno )
        vtun_syslog(LOG_INFO,"%s (%d)", strerror(errno), errno);

    if (linker_term == VTUN_SIG_TERM)
    {
        lfd_host->persist = 0;
    }

    /* Notify other end about our close */
    proto_write(lfd_host->fs[0].fd, buf, VTUN_CONN_CLOSE);
    lfd_free(buf);
    lfd_free(temp_probe);

    return 0;
}
/*********************************
	A function which will be called by pthread and which will do some rate control on tx side
********************************/
void *dummy2(void *args)
{
    int i = 0;
    while(1){
    //vtun_syslog(LOG_ERR,"MYLOG: %lu %d %d %d %d %d %d",lfd_host->stat.byte_in+lfd_host->stat.byte_out,mux.srtt,sc.srtt[0],sc.srtt[1],state.final_loss, lfd_host->fs[0].lost_count, lfd_host->fs[0].lost_count);
//    vtun_syslog(LOG_ERR,"MYLOG: B(%lu:%lu) I(%lu:%lu) O(%lu:%lu) RTT(%d %d %d) VAR(%d,%d) Loss(%d %d %d) FLAG(%d,%d) TIMEOUT(%d,%d,%d)",lfd_host->stat.byte_in,lfd_host->stat.byte_out,lfd_host->fs[0].in_data,lfd_host->fs[1].in_data,lfd_host->fs[0].out_data,lfd_host->fs[1].out_data,mux.rto,lfd_host->fs[0].srtt,lfd_host->fs[1].srtt,lfd_host->fs[0].rttvar,lfd_host->fs[1].rttvar, state.final_loss, lfd_host->fs[0].lost_count, lfd_host->fs[1].lost_count,lfd_host->fs[0].fd_flag,lfd_host->fs[1].fd_flag,state.block_loss,lfd_host->fs[0].timeout_count,lfd_host->fs[1].timeout_count);
    if(i==1)
	log_xml();
    usleep(500000);
    respond_back(2,state.expected,ACK);
    i++;
    i = i % 120;
    }
/*    while(1)
    {
        struct timespec ts,next;
        clock_gettime(CLOCK_REALTIME,&ts);
        //mux_write2(ts, *((int *)args));
        mux_write2(ts, 0);
        mux_write2(ts, 1);

        if(mux.q[1].start == mux.q[1].end && mux.q[0].start == mux.q[0].end)
        {
            next.tv_nsec = ts.tv_nsec + 500000;
            if(next.tv_nsec > 1000000000)
            {
                next.tv_nsec = next.tv_nsec -1000000000;
                next.tv_sec = ts.tv_sec +1;
            }
            else
                next.tv_sec = ts.tv_sec;
        }
        else
        {

            if(mux.q[1].start == mux.q[1].end)
                next = mux.q[0].at[mux.q[0].end].tag;
            else if(mux.q[0].start == mux.q[0].end)
                next = mux.q[1].at[mux.q[1].end].tag;
            else
            {
                next = mux.q[0].at[mux.q[0].end].tag;
                if((next.tv_sec > mux.q[1].at[mux.q[1].end].tag.tv_sec)	|| ((next.tv_sec== mux.q[1].at[mux.q[1].end].tag.tv_sec) &&( next.tv_nsec > mux.q[1].at[mux.q[1].end].tag.tv_nsec)))
                    next = mux.q[1].at[mux.q[1].end].tag;
            }
        }

// Temp hack to decouple two queues
        clock_gettime(CLOCK_REALTIME,&ts);
        if((next.tv_sec -ts.tv_sec)*1000000 +(next.tv_nsec -ts.tv_nsec)/1000 <500)
        {
            next.tv_nsec = ts.tv_nsec + 500000;
            if(next.tv_nsec > 1000000000)
            {
                next.tv_nsec = next.tv_nsec -1000000000;
                next.tv_sec = ts.tv_sec +1;
            }
            else
                next.tv_sec = ts.tv_sec;

        }
        clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME,&next, NULL);
        //	usleep(1);
    }
*/
    pthread_exit(NULL);
}

void *nl_dummy(void *args)
{
    nl_recv();
    pthread_exit(NULL);
}
/****************************
	A function which will be called by another Pthread to send packets from order Queue to tun interface
	It is indeed called delay_write which hides retransmission delays from upper layer.
**************************/
void *dummy(void *args)
{
//    struct timespec ts,next;
    struct timeval tv,next;

    int num =0;
    static int lastreported =0;
    static lastnum = 0;

    int i;
    while(1)
    {
        pthread_mutex_lock( &mutex );
        reorder_send();
        pthread_mutex_unlock( &mutex );
        if(state.expected >0 && (state.expected>(state.last_reported+100)%SEQLEN))
        {
            respond_back(2,state.expected,ACK);
            lastreported = state.expected;
            lastnum = num;
        }
        else if(lastnum == num && state.expected != state.last_reported)
        {
            respond_back(2,state.expected,ACK);
            lastreported = state.expected;
        }
        num ++;
        num = num%100;

        usleep(1000);

    }

    pthread_exit(NULL);
}
/**/
/* Link remote and local file descriptors */
int linkfd(struct vtun_host *host)
{
    struct sigaction sa, sa_oldterm, sa_oldint, sa_oldhup,sa_sigsev;
    int old_prio;
    int rc;
    pthread_t thread_id,thread_id1, thread_id2;
    int opt;
    int i;
    struct sockaddr_in saddr;
    errno =0;
    char ipstr[INET_ADDRSTRLEN];
    char ipstr2[INET_ADDRSTRLEN];
    for(i =0 ; i< VTUN_MAX_INT; i++){
        if(host->fs[i].fd_flag ==1){
		inet_ntop(AF_INET, &(host->fs[i].daddr.sin_addr), ipstr, INET_ADDRSTRLEN);	
		inet_ntop(AF_INET, &(host->fs[i].saddr.sin_addr), ipstr2, INET_ADDRSTRLEN);
        }
    }
    vtun_syslog(LOG_ERR,"fd  %s %s=>%s",strerror(errno),ipstr2,ipstr);
    /*Open a control socket first*/

        for(i =0; i<VTUN_MAX_INT;i++)
	{
        	opt =sizeof(saddr);
        	if(host->fs[i].fd_flag ==1)
		{
    if(host->role ==1){
        	}
		else
                {
		     opt = sizeof(saddr);
                     errno =0;
                     rc =100+i;
                     vtun_syslog(LOG_ERR,"before ctrl probe %s",strerror(errno));
		     sendfromto(host->ctrl, (char*)&rc,sizeof(rc),0, (struct sockaddr *)&(host->fs[i].saddr), opt, (struct sockaddr *)&(host->fs[i].daddr),opt);
                     vtun_syslog(LOG_ERR,"ctrl probe %s",strerror(errno));
                     if(errno !=0){
                           inet_ntop(AF_INET, &(host->fs[i].daddr.sin_addr), ipstr, INET_ADDRSTRLEN);
                           inet_ntop(AF_INET, &(host->fs[i].saddr.sin_addr), ipstr2, INET_ADDRSTRLEN);

                     vtun_syslog(LOG_ERR,"ctrl probe %s %s=>%s",strerror(errno),ipstr2,ipstr);
                     }
                     sleep(1);
		}
	}	

    	}
     
    /* INIT*/
    
    memset((char *) &saddr, 0, sizeof(saddr));
    /* ASSERT SOCKETS*/
    for(i =0; i<VTUN_MAX_INT;i++){
        opt =sizeof(saddr);
        if(host->fs[i].fd_flag ==1){
            if((rc = getsockname(host->fs[i].fd,(struct sockaddr *)&saddr,&opt)) ==-1 )
            {
                vtun_syslog(LOG_ERR,"Can't get socket name");
                return -1;
            }
            vtun_syslog(-1," fd is %s:%d ",inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));
        }
	   
    }
    if((rc = getsockname(host->ctrl,(struct sockaddr *)&saddr,&opt)) ==-1 )
    {
        vtun_syslog(LOG_ERR,"Can't get socket name");
        return -1;
    }
    vtun_syslog(-1," ctrl fd is %s:%d ",inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));

    lfd_host = host;

    vtun_syslog(LOG_ERR, "Intializing structures ");
    mux_init();
    Queue_init();
    if(!host->role)
    nl_init();
    log_xml_init();
    /*PTHREADS*/
    rc =  pthread_create(&thread_id, NULL, dummy,NULL );
    rc =  pthread_create(&thread_id1, NULL, dummy2,NULL );
    if(!host->role)
    rc =  pthread_create(&thread_id2, NULL, nl_dummy,NULL );
    vtun_syslog(LOG_ERR, "Intializing structures  Done");
    old_prio=getpriority(PRIO_PROCESS,0);
    setpriority(PRIO_PROCESS,0,LINKFD_PRIO);

    /* Build modules stack */
    if(host->flags & VTUN_ZLIB)
        lfd_add_mod(&lfd_zlib);

    if(host->flags & VTUN_LZO)
        lfd_add_mod(&lfd_lzo);

    if(host->flags & VTUN_ENCRYPT)
        if(host->cipher == VTUN_LEGACY_ENCRYPT)
        {
            lfd_add_mod(&lfd_legacy_encrypt);
        }
        else
        {
            lfd_add_mod(&lfd_encrypt);
        }

    if(host->flags & VTUN_SHAPE)
        lfd_add_mod(&lfd_shaper);

    if(lfd_alloc_mod(host))
        return 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler=sig_term;
    sigaction(SIGTERM,&sa,&sa_oldterm);
    sigaction(SIGINT,&sa,&sa_oldint);
    sa.sa_handler=sig_hup;
    sigaction(SIGHUP,&sa,&sa_oldhup);
    sa.sa_handler=sig_sigsev;
    sigaction(SIGSEGV,&sa,&sa_sigsev);
   
    vtun_syslog(LOG_ERR,"Before STAT");
    /* Initialize statstic dumps */

    if( host->flags & VTUN_STAT )
    {
	ualarm(500000,0);

        char file[40];

        sa.sa_handler=sig_alarm;
        sigaction(SIGALRM,&sa,NULL);
        sa.sa_handler=sig_usr1;
        sigaction(SIGUSR1,&sa,NULL);
    }
    io_init();
    //sc.state = 2;
    sc.state = -1;
    vtun_syslog(LOG_ERR, "linking now ");
    lfd_linker();

    xmlCleanupParser();
    if( host->flags & VTUN_STAT )
    {
        alarm(0);
        if (host->stat.file)
            fclose(host->stat.file);
    }
    close(host->ctrl);
    lfd_free_mod();
    sigaction(SIGTERM,&sa_oldterm,NULL);
    sigaction(SIGINT,&sa_oldint,NULL);
    sigaction(SIGHUP,&sa_oldhup,NULL);

    setpriority(PRIO_PROCESS,0,old_prio);

    return linker_term;
}
