/*
 * clientmanager.c
 *
 *  Created on: 08 Nov 2015
 *      Author: suresh
 */

#include "clientmanager.h"


static volatile sig_atomic_t client_term;
static void sig_term(int sig) {
	vtun_syslog(LOG_INFO, "Terminated");
	client_term = VTUN_SIG_TERM;
}
//}
int fetch_rmtfd2(char *remote_ip, char *local_ip, short local_port,
		short remote_port) {
	int rmtfd2 = 0;
	struct sockaddr_in serv_addr;
	struct sockaddr_in my_addr;
	int sockfd;
	int i;
	int slen = sizeof(serv_addr);

	vtun_syslog(LOG_INFO, "opening alternate socket %s,%s,%d,%d", remote_ip,
			local_ip, local_port, remote_port);
	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		vtun_syslog(LOG_INFO, "unable to open alternate socket");
		exit(1);
	}

	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(local_port);

	if (inet_aton(local_ip, &my_addr.sin_addr) == 0) {
		vtun_syslog(LOG_INFO, "inet_aton() failed");
		exit(1);
	}
	if (bind(sockfd, (struct sockaddr*) &my_addr, sizeof(my_addr)) == -1) {
		vtun_syslog(LOG_INFO, "bind failed ");
		exit(1);
	} else
		vtun_syslog(LOG_INFO, "Alternate socket bind() successful");

	bzero(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(remote_port);
	vtun_syslog(LOG_INFO, "1Alternate socket bind() successful");
	if (inet_aton(remote_ip, &serv_addr.sin_addr) == 0) {
		vtun_syslog(LOG_INFO, "inet_aton() failed");
		exit(1);
	}

	vtun_syslog(LOG_INFO, "2Alternate socket bind() successful");
	while (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))
			< 0)
		vtun_syslog(LOG_INFO, "connect() failed %s", strerror(errno));
	vtun_syslog(LOG_INFO, "3Alternate socket bind() successful");
	rmtfd2 = sockfd;
	getpeername(sockfd, (struct sockaddr *) &serv_addr, &slen);
	vtun_syslog(LOG_INFO, "accepted from %s", inet_ntoa(serv_addr.sin_addr));

	return rmtfd2;
}

void spclient(struct vtun_host *host) {
	struct sockaddr_in my_addr, svr_addr;
	struct sigaction sa;
	int s, opt, reconnect;
	int i;

	vtun_syslog(LOG_INFO, "SpiderNet client ver %s started", SPCLIENT_VER);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_NOCLDWAIT;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGCHLD, &sa, NULL);

	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	client_term = 0;
	reconnect = 0;
	while ((!client_term) || (client_term == VTUN_SIG_HUP)) {
		if (reconnect && (client_term != VTUN_SIG_HUP)) {
			if (vtun.persist || host->persist) {
				/* Persist mode. Sleep and reconnect. */
				sleep(5);
			} else {
				/* Exit */
				break;
			}
		} else {
			reconnect = 1;
		}

		set_title("%s init initializing", host->host);

		/* Set server address */
		if (server_addr(&svr_addr, host) < 0)
			continue;

		/* Set local address */
		if (local_addr(&my_addr, host, 0) < 0)
			continue;

		/* We have to create socket again every time
		 * we want to connect, since STREAM sockets
		 * can be successfully connected only once.
		 */
		if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			vtun_syslog(LOG_ERR, "Can't create socket. %s(%d)", strerror(errno),
					errno);
			continue;
		}

		/* Required when client is forced to bind to specific port */
		opt = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

		if (bind(s, (struct sockaddr *) &my_addr, sizeof(my_addr))) {
			vtun_syslog(LOG_ERR, "Can't bind socket. %s(%d)", strerror(errno),
					errno);
			continue;
		}

		/*
		 * Clear speed and flags which will be supplied by server.
		 */
		host->spd_in = host->spd_out = 0;
		host->flags &= VTUN_CLNT_MASK;

		io_init();

		set_title("%s connecting to %s", host->host, vtun.svr_name);
		vtun_syslog(LOG_INFO, "Connecting to %s on port %d", vtun.svr_name,svr_addr.sin_port);
		vtun_syslog(LOG_INFO, "Connecting to %s on port %d", svr_addr.sin_addr,svr_addr.sin_port);


		if (connect_t(s, (struct sockaddr *) &svr_addr, host->timeout)) {
			vtun_syslog(LOG_INFO, "Connect to %s failed. %s(%d)", vtun.svr_name,
					strerror(errno), errno);
		} else {
			if (auth_client(s, host)) {
				host->rmt_fd = s;
				vtun_syslog(LOG_INFO, "Session %s[%s] opened", host->host,
						vtun.svr_name);
				if (readn_t(host->rmt_fd, (char *) &host->ctrl_port,
						sizeof(int), host->timeout) < 0) {
					vtun_syslog(LOG_ERR, "Can't read port number %s",
							strerror(errno));
					exit(1);
				} else {
					vtun_syslog(LOG_ERR, "SPClient: Host Ctrl Port %d",host->ctrl_port);
				}

				host->rmt_fd = s;

				/* Start the tunnel */
				host->role = 0;
				conf_parse(host);
				fill_ip_src(host);

				if (write_n(host->rmt_fd, (char *) &host->fscount, sizeof(int))
						< 0) {
					vtun_syslog(LOG_ERR, "Can't write number of interfaces");
					exit(1);
				}

//CHANGE HERE
				/*
				 //host->saddr[0].ip = strdup("192.168.2.120");
				 host->saddr[0].ip = strdup("192.168.2.3");
				 //host->saddr[1].ip = strdup("10.162.172.1");
				 host->saddr[1].ip = strdup("192.168.3.2");
				 host->sport[0] = 4887;
				 host->sport[1] = 4888;
				 host->daddr[0].ip = strdup("155.246.74.98");
				 host->daddr[1].ip = strdup("155.246.74.98");
				 //host->daddr[0].ip = strdup("23.22.170.14");
				 //host->daddr[1].ip = strdup("23.22.170.14");
				 host->dport[0] = 5887;
				 host->dport[1] = 5888;
				 */
				vtun_syslog(LOG_INFO, "Before CTRL");
				host->ctrl = fetch_control(host);
				close(host->rmt_fd);
				vtun_syslog(LOG_INFO, "After CTRL");
				for (i = 0; i < host->fscount; i++)
					fetch_client_data(host, i, 0);
//                fetch_client_data(host,0,0);
				//               fetch_client_data(host,1,0);
//                fetch_client_data(host,2,0);
				vtun_syslog(LOG_INFO, "After Primary Data");
				int i;
				char ipstr[INET_ADDRSTRLEN];
				char ipstr2[INET_ADDRSTRLEN];
				for (i = 0; i < VTUN_MAX_INT; i++) {
					if (host->fs[i].fd_flag == 1) {
						inet_ntop(AF_INET, &(host->fs[i].daddr.sin_addr), ipstr,
								INET_ADDRSTRLEN);
						inet_ntop(AF_INET, &(host->fs[i].saddr.sin_addr),
								ipstr2, INET_ADDRSTRLEN);
						vtun_syslog(LOG_ERR, "fd  %s %s=>%s", strerror(errno),
								ipstr2, ipstr);
					}
				}

//vtun_syslog(LOG_INFO,"opening alternate socket %s,%s,%d,%d",host->daddr[1].ip, host->saddr[1].ip, host->sport[1], host->dport[1]);
//                host->rmt_fd2 =fetch_rmtfd2(host->daddr[1].ip, host->saddr[1].ip, host->sport[1], host->dport[1]);

				client_term = tunnel(host);

				vtun_syslog(LOG_INFO, "Session %s[%s] closed", host->host,
						vtun.svr_name);
			} else {
				vtun_syslog(LOG_INFO, "Connection denied by %s", vtun.svr_name);
			}
		}
		close(s);
		free_sopt(&host->sopt);
	}

	vtun_syslog(LOG_INFO, "Exit");
	return;
}
