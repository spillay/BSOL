/*
 * main.cpp
 *
 *  Created on: 08 Jan 2015
 *      Author: suresh
 */
#include "../common/spconfig.h"
#include "clientmanager.h"
/* Global options for the server and client */
struct vtun_opts vtun;
struct vtun_host default_host;

void write_pid(void);
void reread_config(int sig);
void usage(void);

extern int optind, opterr, optopt;
extern char *optarg;

/* for the NATHack bit.  Is our UDP session connected? */
int is_rmt_fd_connected = 1;

void init() {
	vtun_syslog(LOG_INFO, "SPClient::init()");

	vtun.cfg_file = CONFIG_FILE;
	vtun.persist = -1;
	vtun.timeout = -1;

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

	/* Initialize default host options */
	memset(&default_host, 0, sizeof(default_host));
	default_host.flags = VTUN_TTY | VTUN_TCP;
	default_host.multi = VTUN_MULTI_ALLOW;
	default_host.timeout = VTUN_CONNECT_TIMEOUT;
	default_host.ka_interval = 30;
	//default_host.ka_failure = 4;
	default_host.loc_fd = default_host.rmt_fd = -1;

}
void setOptions(int argc, char *argv[]) {
	int opt;
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
			//svr = 1;
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
			//daemon = 0;
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
}
int main(int argc, char *argv[], char *env[]) {
	int svr, daemon, sock, dofork, fd, opt;
	struct vtun_host *host = NULL;
	struct sigaction sa;
	char *hst;

	/* Configure default settings */
	svr = 0;
	daemon = 1;
	sock = 0;
	dofork = 1;

	vtun_syslog(LOG_INFO, "Starting SPClient");
	init();
	setOptions(argc, argv);
	reread_config(0);
	if (vtun.bind_addr.port == -1)
		vtun.bind_addr.port = VTUN_PORT;
	if (vtun.persist == -1)
		vtun.persist = 0;
	if (vtun.timeout == -1)
		vtun.timeout = VTUN_TIMEOUT;
	clear_nat_hack_flags(0);
	if (argc - optind < 2) {
		usage();
		exit(1);
	}
	hst = argv[optind++];
	vtun_syslog(LOG_ERR, "Host %s and port %d",hst,vtun.bind_addr.port);
	if (!(host = find_host(hst))) {
		vtun_syslog(LOG_ERR, "Host %s not found in %s", hst, vtun.cfg_file);
		exit(1);
	}

	vtun.svr_name = strdup(argv[optind]);

	init_title(argc, argv, env, "spclient[c]: ");
	spclient(host);
	closelog();

}
/*
 * Very simple PID file creation function. Used by server.
 * Overrides existing file.
 */
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
	printf("SPClient ver %s\n", SPCLIENT_VER);
	printf("  SPClient:\n");
	/* I don't think these work. I'm disabling the suggestion - bish 20050601*/
	printf("SPClient [-f file] " /* [-P port] [-L local address] */
			"[-p] [-m] [-t timeout] <host profile> <server address>\n");
}

