/*
 * Tunnel SIE data from an SRA or RAD server.
 *
 *  Copyright (c) 2014-2017 by Farsight Security, Inc.
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

#include "sratunnel.h"

/* extern: main.c */
extern FILE *fp_pidfile;
extern const char *pidfile;  

/* from nmsgtool */
FILE *
pidfile_open(void) {
    FILE *fp;

    if (pidfile == NULL)
        return (NULL);

    fp = fopen(pidfile, "w");
    if (fp == NULL) {
        fprintf(stderr, "unable to open pidfile %s: %s\n", pidfile,
            strerror(errno));
        return (NULL);
    }

    return (fp);
}

/* from nmsgtool */
void
pidfile_write(void) {
    pid_t pid;

    if (fp_pidfile == NULL)
        return;

    pid = getpid();
    fprintf(fp_pidfile, "%d\n", pid);
    fclose(fp_pidfile);
}
