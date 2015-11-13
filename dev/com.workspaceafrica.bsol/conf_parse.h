/*
VTun - Virtual Tunnel over TCP/IP network.

Copyright (C) 1998-2008  Maxim Krasnyansky <max_mk@yahoo.com>

VTun has been derived from VPPP package by Maxim Krasnyansky.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/

/*
* $Id: conf_parse.h,v 0.01 2013/06/14 2:35:51 Kai $
*/

#ifndef _VTUN_CONF_PARSE_H
#define _VTUN_CONF_PARSE_H

#include "vtun.h"
#include "lib.h"
#include "lock.h"
#include "auth.h"

int conf_parse(struct vtun_host *host);

#endif /* _VTUN_CONF_PARSE_H */
