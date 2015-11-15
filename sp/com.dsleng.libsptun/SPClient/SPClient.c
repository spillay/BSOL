/*
 ============================================================================
 Name        : SPClient.c
 Author      : Suresh Pillay
 Version     :
 Copyright   : DSLEng
 Description : Uses shared library libsptun to create a client implementation
 ============================================================================
 */

#include <config.h>
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

#include "config.h"
#include "vtun.h"

#define VTUN_PID_FILE "/usr/local/var/run/vtund.pid"
#define VTUN_CONFIG_FILE "/usr/local/etc/vtund.conf"

struct vtun_opts vtun;
struct vtun_host default_host;

void write_pid(void);
void reread_config(int sig);
void usage(void);
void init();
void clean();

extern int optind, opterr, optopt;
extern char *optarg;

/* for the NATHack bit.  Is our UDP session connected? */
int is_rmt_fd_connected = 1;

int main(int argc, char *argv[], char *env[]) {
	vtun_syslog(LOG_INFO, "Starting SPClient");
	int svr, daemon, sock, dofork, fd, opt;
	struct vtun_host *host = NULL;
	struct sigaction sa;
	char *hst;

	/* Configure default settings */
	svr = 0;
	daemon = 1;
	sock = 0;
	dofork = 1;

	vtun.cfg_file = VTUN_CONFIG_FILE;
	vtun.persist = -1;
	vtun.timeout = -1;

	init();
	// SP: In this code SVR is always 0
	svr = 0;
	while ((opt = getopt(argc, argv, "misf:P:L:t:npq")) != EOF) {
		switch (opt) {
		case 'm':
			if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
				perror("Unable to mlockall()");
				exit(-1);
			}
			break;
		case 'i':
			vtun.svr_type = VTUN_INETD;
			break;
		case 's':
			svr = 1;
			break;
		case 'L':
			vtun.svr_addr = strdup(optarg);
			break;
		case 'P':
			vtun.bind_addr.port = atoi(optarg);
			break;
		case 'f':
			vtun.cfg_file = strdup(optarg);
			break;
		case 'n':
			daemon = 0;
			break;
		case 'p':
			vtun.persist = 1;
			break;
		case 't':
			vtun.timeout = atoi(optarg);
			break;
		case 'q':
			vtun.quiet = 1;
			break;
		default:
			usage();
			exit(1);
		}
	}
	reread_config(0);
	if (argc - optind < 2) {
		usage();
		exit(1);
	}
	hst = argv[optind++];

	if (!(host = find_host(hst))) {
		vtun_syslog(LOG_ERR, "Host %s not found in %s", hst, vtun.cfg_file);
		exit(1);
	}
	vtun.svr_name = strdup(argv[optind]);
	if (vtun.bind_addr.port == -1)
		vtun.bind_addr.port = VTUN_PORT;
	if (vtun.persist == -1)
		vtun.persist = 0;
	if (vtun.timeout == -1)
		vtun.timeout = VTUN_TIMEOUT;
	switch (vtun.svr_type) {
	case -1:
		vtun.svr_type = VTUN_STAND_ALONE;
		break;
	case VTUN_INETD:
		sock = dup(0);
		dofork = 0;
		break;
	}
	if (vtun.syslog != LOG_DAEMON) {
		/* Restart logging to syslog using specified facility  */
		closelog();
		openlog("vtund", LOG_PID | LOG_NDELAY | LOG_PERROR, vtun.syslog);
	}

	clear_nat_hack_flags(svr);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = reread_config;
	sigaction(SIGHUP, &sa, NULL);

	init_title(argc, argv, env, "SPClient: ");
	client(host);
	closelog();
	clean();
	return 0;
}
void clean() {
	free(vtun.ppp);
	free(vtun.ifcfg);
	free(vtun.route);
	free(vtun.fwall);
	free(vtun.iproute);
}
void init() {
	/* Dup strings because parser will try to free them */
	vtun.ppp = strdup("/usr/sbin/pppd");
	vtun.ifcfg = strdup("/sbin/ifconfig");
	vtun.route = strdup("/sbin/route");
	vtun.fwall = strdup("/sbin/ipchains");
	vtun.iproute = strdup("/sbin/ip");

	vtun.svr_name = NULL;
	vtun.svr_addr = NULL;
	vtun.bind_addr.port = -1;
	vtun.svr_type = -1;
	vtun.syslog = LOG_DAEMON;

	memset(&default_host, 0, sizeof(default_host));
	default_host.flags = VTUN_TTY | VTUN_TCP;
	default_host.multi = VTUN_MULTI_ALLOW;
	default_host.timeout = VTUN_CONNECT_TIMEOUT;
	default_host.ka_interval = 30;
	default_host.ka_maxfail = 4;
	default_host.loc_fd = default_host.rmt_fd = -1;

}

void write_pid(void) {
	FILE *f;

	if (!(f = fopen(VTUN_PID_FILE, "w"))) {
		vtun_syslog(LOG_ERR, "Can't write PID file");
		return;
	}

	fprintf(f, "%d", (int) getpid());
	fclose(f);
}

void reread_config(int sig) {
	if (!read_config(vtun.cfg_file)) {
		vtun_syslog(LOG_ERR, "No hosts defined");
		exit(1);
	}
}

void usage(void) {
	printf("SPTun ver %s\n", VTUN_VER);
	printf("Usage: \n");
	printf("  Client:\n");
	/* I don't think these work. I'm disabling the suggestion - bish 20050601*/
	printf("\tvtund [-f file] " /* [-P port] [-L local address] */
			"[-p] [-m] [-t timeout] <host profile> <server address>\n");
}


