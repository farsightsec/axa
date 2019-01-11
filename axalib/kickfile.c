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
	free((*kf)->file_basename);
	free((*kf)->file_curname);
	free((*kf)->file_tmpname);
	free((*kf)->file_suffix);
	free((*kf));
	*kf = NULL;
}

void
axa_kickfile_exec(struct axa_kickfile *kf)
{
	char *cmd;

	if (kf != NULL && kf->file_tmpname != NULL && kf->file_curname != NULL) {
		if (rename(kf->file_tmpname, kf->file_curname) < 0) {
			perror("rename");
			unlink(kf->file_tmpname);
		} else if (kf->cmd != NULL && *kf->cmd != '\0') {
			int rc;

			axa_asprintf(&cmd, "%s %s &", kf->cmd, kf->file_curname);
			rc = system(cmd);
			if (rc != 0)
				fprintf(stderr, "WARNING: system() failed\n");
			free(cmd);
		}
	}
}

void
axa_kickfile_rotate(struct axa_kickfile *kf, const char *name)
{
	char *kt;
	char *dup_for_basename, *s_basename;
	char *dup_for_dirname, *s_dirname;

	kt = name != NULL ? (char *)name : kickfile_time();
	dup_for_basename = strdup(kf->file_basename);
	dup_for_dirname = strdup(kf->file_basename);
	s_basename = basename(dup_for_basename);
	s_dirname = dirname(dup_for_dirname);
	AXA_ASSERT(s_basename != NULL);
	AXA_ASSERT(s_dirname != NULL);

	free(kf->file_tmpname);
	free(kf->file_curname);
	axa_asprintf(&kf->file_tmpname, "%s/.%s.%s.part", s_dirname, s_basename, kt);
	axa_asprintf(&kf->file_curname, "%s/%s.%s%s", s_dirname, s_basename, kt,
		      kf->file_suffix != NULL ? kf->file_suffix : "");
	if (name == NULL)
		free(kt);
	free(dup_for_basename);
	free(dup_for_dirname);

	if (kf->cb != NULL)
		kf->cb((void *)"rumi");
}

void
axa_kickfile_register_cb(struct axa_kickfile *kf, void (*cb)(void *))
{
	AXA_ASSERT(kf != NULL);

	kf->cb = cb;
}
