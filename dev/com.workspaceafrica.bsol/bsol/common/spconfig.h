/*
 * spconfig.h
 *
 *  Created on: 08 Jan 2015
 *      Author: suresh
 */

#ifndef BSOL_COMMON_SPCONFIG_H_
#define BSOL_COMMON_SPCONFIG_H_

#include "../../config.h"

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

#include "../../vtun.h"
#include "../../lib.h"
#include "../../compat.h"

#define CONFIG_FILE "/usr/local/etc/vtund-client.conf"
#define SPCLIENT_VER "0.3 10/01/2015"

#endif /* BSOL_COMMON_SPCONFIG_H_ */
