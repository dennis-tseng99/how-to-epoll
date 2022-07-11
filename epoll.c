/************************************************
 * epoll.c
 ************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/ioctl.h>
#include <netinet/in.h> /* get local ip */ 
#include <net/if.h>     /* get local ip */
#include <linux/if_packet.h>
#include </usr/include/linux/filter.h>
#include <linux/if_ether.h>
#include <arpa/inet.h> /* inet_addr(), struct sockaddr_in */
#include <netdb.h>

#define IF_NAME	"eth15"
void PRINT_MESSAGE();

struct ifreq	ethreq;
static struct   sockaddr_ll 	sll;                    
fd_set			ospf_io_ready;
int				tcp_io_fd;

int tcp_sock_init() 
{
	struct sock_fprog  	Filter;
	struct ifreq		ethreq;

    static struct sock_filter  BPF_code[]={ 
		{ 0x30, 0, 0,  0x00000017 }, //23th byte
		{ 0x15, 0, 1,  0x00000006 }, //is TCP ?
		{ 0x06, 0, 0,  0x000005be }, //ok! return 1470 bytes
		{ 0x06, 0, 0,  0x00000000 }, //error! return nothing
	};
	
	Filter.len = sizeof(BPF_code)/sizeof(struct sock_filter);
	Filter.filter = BPF_code;
	
    if ((tcp_io_fd=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0){
	    printf("socket");
	    return -1;
	}
	
    FD_ZERO(&ospf_io_ready);
    FD_SET(tcp_io_fd,&ospf_io_ready);
    
	/* Set the network card in promiscuous mode */
  	strncpy(ethreq.ifr_name, IF_NAME, IFNAMSIZ);
  	if (ioctl(tcp_io_fd, SIOCGIFFLAGS, &ethreq)==-1) {
    	perror("ioctl (SIOCGIFCONF) 1\n");
    	close(tcp_io_fd);
    	return -1;
  	}
  	
  	ethreq.ifr_flags |= IFF_PROMISC;
  	if (ioctl(tcp_io_fd, SIOCSIFFLAGS, &ethreq)==-1) {
    	printf("ioctl (SIOCGIFCONF) 2\n");
    	close(tcp_io_fd);
    	return -1;
  	}
  	
  	/* Attach the filter to the socket */
  	if (setsockopt(tcp_io_fd, SOL_SOCKET, SO_ATTACH_FILTER, &Filter, sizeof(Filter))<0){
    	perror("setsockopt: SO_ATTACH_FILTER");
    	close(tcp_io_fd);
    	return -1;
  	}
  	
    //--------------- configure TX ------------------
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_halen = 6;
		
	ioctl(tcp_io_fd, SIOCGIFINDEX, &ethreq); //ifr_name must be set to "eth?" ahead
	sll.sll_ifindex = ethreq.ifr_ifindex;
	
	return 0;
}

static void epoll_ctl_add(int epfd, int fd, uint32_t events)
{
	struct epoll_event ev;
	
	ev.events = events;
	ev.data.fd = fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		perror("epoll_ctl()\n");
		exit(1);
	}
}

int main(void)
{
    struct  epoll_event events[128];
    char    buf[256];
    int     i;
	int     n;
	int     epfd;
	int     nfds;
	
	ospf_sock_init();
    epfd = epoll_create(1);
	epoll_ctl_add(epfd, tcp_io_fd, EPOLLIN | EPOLLOUT | EPOLLET);

	for(;;) {
		nfds = epoll_wait(epfd, events, 128, -1);
		for(i = 0; i < nfds; i++) {
			if (events[i].data.fd == tcp_io_fd) {
			    if (events[i].events & EPOLLIN) {
			        n = read(events[i].data.fd, buf, sizeof(buf));
			        PRINT_MESSAGE(buf,n);
			    }
			}
		}
	}
    return 0;
}

/********************************************************************
 * PRINT_MESSAGE()
 *
 ********************************************************************/
void PRINT_MESSAGE(msg,len)
const char  msg[];
int         len;
{
#	define PRN_Q_WWDTH	2048

#   define BYTE_CAN_BE_SEEN(c)   ((c>0x20 && c<=0x7e) ? 1:0)
    int  xi,ci;
    char prnB[PRN_Q_WWDTH];
    char prnb[20];
    int  row_cnt,rows,rest_bytes,hex_cnt,ch_cnt,cnt;


    if (msg == NULL){
        printf("%s","PRINT_MESSAGE(): NULL message ?\n");
        return;
    }

    if ((len*5) > PRN_Q_WWDTH){ /* 5 format bytes for one raw data byte */ 
        printf("Too large[len(%d) > max(%d)] to print out!\n",len,PRN_Q_WWDTH);
        return;
    }
    prnB[0] = '\0';
    /*sprintf(prnb,"len=0x%02x\n",len);
    strcat(prnB,prnb);*/

    rest_bytes = len % 16;
    rows = len / 16;
    ci = xi = 0;

    for(row_cnt=0; row_cnt<rows; row_cnt++){
    	/*------------- print label for each row --------------*/
    	sprintf(prnb,"%04x:  ",(row_cnt+1)<<4);
    	strcat(prnB,prnb);
    	
        /*------------- print hex-part --------------*/
        for(hex_cnt=1; hex_cnt<=8; hex_cnt++){
            if (hex_cnt < 8)
                sprintf(prnb,"%02x ",(unsigned char)msg[xi++]); /* Must be unsigned, otherwise garbage displayed */
            else
                sprintf(prnb,"%02x",(unsigned char)msg[xi++]); /* Must be unsigned, otherwise garbage displayed */
            strcat(prnB,prnb);
        }

        /* delimiters space for each 8's Hex char */
        strcat(prnB,"  ");

        for(hex_cnt=9; hex_cnt<=16; hex_cnt++){
            if (hex_cnt < 16)
                sprintf(prnb,"%02x ",(unsigned char)msg[xi++]);
            else
                sprintf(prnb,"%02x",(unsigned char)msg[xi++]);
            strcat(prnB,prnb);
        }

        /* delimiters space bet. Hex and Character row */
        strcat(prnB,"    ");

        /*------------- print character-part --------------*/
        for(ch_cnt=1; ch_cnt<=16; ch_cnt++,ci++){
            if (BYTE_CAN_BE_SEEN((unsigned char)msg[ci])){
                sprintf(prnb,"%c",msg[ci]);
                strcat(prnB,prnb);
            }
            else
                strcat(prnB,".");
        }
        strcat(prnB,"\n");
    } /* for */
    
    /*================ print the rest bytes(hex & char) ==================*/
    if (rest_bytes == 0){
        strcat(prnB,"\n");
        printf("%s",prnB);
        return;
    }

	/*------------- print label for last row --------------*/
    sprintf(prnb,"%04x:  ",(row_cnt+1)<<4);
    strcat(prnB,prnb);
    	
    /*------------- print hex-part(rest) --------------*/
    if (rest_bytes < 8){
        for(hex_cnt=0; hex_cnt<=rest_bytes; hex_cnt++){
            sprintf(prnb,"%02x ",(unsigned char)msg[xi++]);
            strcat(prnB,prnb);
        }

        /* fill in the space for 16's Hex-part alignment */
        for(cnt=rest_bytes+1; cnt<=8; cnt++){ /* from rest_bytes+1 to 8 */
            if (cnt < 8)
                strcat(prnB,"   ");
            else
                strcat(prnB,"  ");
        }

        /* delimiters bet. hex and char */
        strcat(prnB,"  ");

        for(cnt=9; cnt<=16; cnt++){
            if (cnt < 16)
                strcat(prnB,"   ");
            else
                strcat(prnB,"  ");
        }
        strcat(prnB,"    ");
    }
    else if (rest_bytes == 8){
        for(hex_cnt=1; hex_cnt<=rest_bytes; hex_cnt++){
            if (hex_cnt < 8)
                sprintf(prnb,"%02x ",(unsigned char)msg[xi++]);
            else
                sprintf(prnb,"%02x",(unsigned char)msg[xi++]);
            strcat(prnB,prnb);
        }
        strcat(prnB,"  ");

        for(cnt=9; cnt<=16; cnt++){
            if (cnt < 16)
                strcat(prnB,"   ");
            else
                strcat(prnB,"  ");
        }
        strcat(prnB,"    ");
    }
    else{ /* rest_bytes > 8 */
        for(hex_cnt=1; hex_cnt<=8; hex_cnt++){
            if (hex_cnt < 8)
                sprintf(prnb,"%02x ",(unsigned char)msg[xi++]);
            else
                sprintf(prnb,"%02x",(unsigned char)msg[xi++]);
            strcat(prnB,prnb);
        }

        /* delimiters space for each 8's Hex char */
        strcat(prnB,"  ");

        for(hex_cnt=9; hex_cnt<=rest_bytes; hex_cnt++){ /* 9 - rest_bytes */
            if (hex_cnt < 16)
                sprintf(prnb,"%02x ",(unsigned char)msg[xi++]);
            else
                sprintf(prnb,"%02x",(unsigned char)msg[xi++]);
            strcat(prnB,prnb);
        }

        for(cnt=rest_bytes+1; cnt<=16; cnt++){
            if (cnt < 16)
                strcat(prnB,"   ");
            else
                strcat(prnB,"  ");
        }
        /* delimiters space bet. Hex and Character row */
        strcat(prnB,"    ");
    } /* else */

    /*------------- print character-part --------------*/
    for(ch_cnt=1; ch_cnt<=rest_bytes; ch_cnt++,ci++){
        if (BYTE_CAN_BE_SEEN((unsigned char)msg[ci])){
            sprintf(prnb,"%c",msg[ci]);
            strcat(prnB,prnb);
        }
        else
            strcat(prnB,".");
    }
    strcat(prnB,"\n");

    printf(prnB);
}
