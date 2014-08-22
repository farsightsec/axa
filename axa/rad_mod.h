/*
 * Realtime Anomaly Detector (RAD) modules
 *
 * Before including this file,
 *	#define RAD_MOD_PREFIX xxx
 * to declare axa_rad_##prefix##_open() axa_rad_##prefix##_whit(),
 *	and axa_rad_##prefix##_close()
 *
 *  Copyright (c) 2014 by Farsight Security, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef RAD_MOD_H
#define RAD_MOD_H

#include <axa/wire.h>


#define RAD_PREFIX "axa_rad_"

/* The module is given, uparams, string of parameters from the users file, and
 *	cparms, a string of parameters from the RAD client.
 * On a successful return,
 *	If it needs one, the module creates and returns a pointer to a context.
 *	and sra_cmds, a string of SRA channels and watches, separated by ','
 *	ctxt and sra_cmds must be freed by the module when it is closed.
 *	Channels to be enabled are strings that match "chN".
 *	Watches are strings that match "ip=addr/prefix", "dns=[*]?example.com",
 *	    or "ch=chN".
 * false=fatal error with errmsg set to NULL or an error message
 *	that must be freed by the caller. */
typedef bool (rad_open_t)(void **ctxt, char **errmsg,
			  const char *uparms, const char *cparms,
			  char **sra_cmds);

/* -1=error, 0=no, 1=yes */
typedef int (rad_whit_t)(void *ctxt, char **errmsg,
			 axa_p_whit_t *whit, size_t whit_len);

typedef void (rad_close_t)(void *ctxt, char *sra_cmds);


#define RAD_CPARMS_OK	"+"		/* allow RAD client parameters */


#ifdef RAD_MOD
/* ensure that the exported functions have the right types */
rad_open_t RAD_MOD_OPEN;
rad_whit_t RAD_MOD_WHIT;
rad_close_t RAD_MOD_CLOSE;
#endif


#endif /* RAD_MOD_H */
