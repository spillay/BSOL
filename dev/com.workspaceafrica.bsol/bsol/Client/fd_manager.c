#include <stdio.h>
#include <time.h>
#include "fd_manager.h"

fd_state* nextfd()
{
    int static i =0;
    int c;
    fd_state *ret = NULL;
/*c=i;
    do
    {
        if(fds[i].fd>0 && fds[i].fd_flag ==1)
        {
            ret = &fds[i];
            i=(i+1)%NUM_2;
            break;
        }
        i = (i+1)%NUM_2;
    }
    while(i!=c);
*/
    return ret;
}

int fd_max()
{
    int ret =0;
/*    int i =0;
    for (i =0; i++; i<NUM_2)
        if(fds[i].fd_flag ==1&& ret <fds[i].fd)
            ret = fds[i].fd;
*/
    return ret;
}

void fetch_fd(int *num_fd, int *fd_list, int *max_fd )
{
    int i;
    *num_fd = 0;
 /*   *max_fd = 0;
    fd_list = temp;
    for(i=0; i<NUM_2; i++)
    {
        if(fds[i].fd>0 && fds[i].fd_flag ==1)
        {
            temp[*num_fd] = fds[i].fd;
            *num_fd=  *num_fd +1;
            if(*max_fd <fds[i].fd)
                *max_fd = fds[i].fd;
        }
    }
*/
}
