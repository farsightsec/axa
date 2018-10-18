/*
 * {rad,sra}tunnel kickfile functions. Much of this code copied from
 * nmsgtool.
 *
 * Copyright (c) 2018 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <axa/axa.h>
#include <axa/kickfile.h>

#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif

static char *
kickfile_time(void)
{
	char *kt;
	char when[32];
	struct timeval tv;
	struct tm tm;
	time_t t;

	gettimeofday(&tv, NULL);
	t = (time_t) tv.tv_sec;
	gmtime_r(&t, &tm);
	strftime(when, sizeof(when), "%Y%m%d.%H%M.%s", &tm);
	axa_asprintf(&kt, "%s.%09ld", when, tv.tv_usec);

	return (kt);
}

void
axa_kickfile_destroy(struct axa_kickfile **kf)
{
	free((*kf)->axa_basename);
	free((*kf)->curname);
	free((*kf)->tmpname);
	free((*kf)->suffix);
	free((*kf));
	*kf = NULL;
}

void
axa_kickfile_exec(struct axa_kickfile *kf)
{
	char *cmd;

	if (kf != NULL && kf->tmpname != NULL && kf->curname != NULL) {
		if (rename(kf->tmpname, kf->curname) < 0) {
			perror("rename");
			unlink(kf->tmpname);
		} else if (kf->cmd != NULL && *kf->cmd != '\0') {
			int rc;

			axa_asprintf(&cmd, "%s %s &", kf->cmd, kf->curname);
			rc = system(cmd);
			if (rc != 0)
				fprintf(stderr, "WARNING: system() failed\n");
			free(cmd);
		}
	}
}

void
axa_kickfile_rotate(struct axa_kickfile *kf)
{
	char *kt;
	char *dup_for_basename, *s_basename;
	char *dup_for_dirname, *s_dirname;

	kt = kickfile_time();
	dup_for_basename = strdup(kf->axa_basename);
	dup_for_dirname = strdup(kf->axa_basename);
	s_basename = basename(dup_for_basename);
	s_dirname = dirname(dup_for_dirname);
	assert(s_basename != NULL);
	assert(s_dirname != NULL);

	free(kf->tmpname);
	free(kf->curname);
	axa_asprintf(&kf->tmpname, "%s/.%s.%s.part", s_dirname, s_basename, kt);
	axa_asprintf(&kf->curname, "%s/%s.%s%s", s_dirname, s_basename, kt,
		      kf->suffix != NULL ? kf->suffix : "");
	free(kt);
	free(dup_for_basename);
	free(dup_for_dirname);
}
