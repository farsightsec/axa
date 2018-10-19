/*
 * Advanced Exchange Access (AXA) semantics for nmsg fields
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

#include <axa/fields.h>
#include <config.h>

#include <nmsg/base/defs.h>
#include <nmsg/base/encode.pb-c.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>

const axa_nmsg_field_t axa_null_field = {
	.idx = AXA_NMSG_IDX_RSVD,
	.class = {.idx = AXA_NMSG_IDX_NONE},
	.rtype = {.idx = AXA_NMSG_IDX_NONE},
	.owner = {.idx = AXA_NMSG_IDX_NONE},
	.enm = {.idx = AXA_NMSG_IDX_NONE},
};


/**
 *  Vendor IDs and message types of messages that are worth decoding.
 *  Each (vendor,message type) pair has a list of fields that
 *  contain domains or IP addresses.
 */
struct vm_entry {
	struct vm_entry *next;		/**< next vendor message */
	axa_nmsg_idx_t	vid;		/**< nmsg vendor ID */
	axa_nmsg_idx_t	msgtype;	/**< nmsg message type */
	struct nmsg_msgmod *mod;	/**< nmsg message module */
	axa_nmsg_field_t *fields;       /**< linked lisg of nmsg fields */
};

/** Vendor ID Message Type hash table */
typedef struct {
	uint	    num_bins;		/**< number of bins in this hash */
	vm_entry_t  *bins[];		/**< the hash table itself */
} vm_hash_t;
static vm_hash_t *vm_hash_tbl;

static inline vm_entry_t**
vm_hash_fnc(uint vid, uint msgtype)
{
	uint n;

	n = (vid << 12) | msgtype;
	n %= vm_hash_tbl->num_bins;
	return (&vm_hash_tbl->bins[n]);
}

static void
free_field(axa_nmsg_field_t *field)
{
	axa_nmsg_sf_t *sf;

	while ((sf = field->sf) != NULL) {
		field->sf = sf->next;
		free(sf);
	}
	free(field);
}

void
axa_unload_fields(void)
{
	struct vm_entry *vm;
	axa_nmsg_field_t *field;
	uint n;

	if (vm_hash_tbl == NULL)
		return;
	for (n = 0; n < vm_hash_tbl->num_bins; ++n) {
		while ((vm = vm_hash_tbl->bins[n]) != NULL) {
			vm_hash_tbl->bins[n] = vm->next;
			while ((field = vm->fields) != NULL) {
				vm->fields = field->next;
				free_field(field);
			}
			free(vm);
		}
	}
	free(vm_hash_tbl);
	vm_hash_tbl = NULL;
}

/* Do we know a vendor ID and message type? */
const axa_nmsg_field_t *
axa_msg_fields(const nmsg_message_t msg)
{
	axa_nmsg_idx_t vid, msgtype;
	const vm_entry_t  *e;

	if (vm_hash_tbl == NULL)
		return (NULL);

	vid = nmsg_message_get_vid(msg);
	msgtype = nmsg_message_get_msgtype(msg);
	for (e = *vm_hash_fnc(vid, msgtype); e != NULL; e = e->next) {
		if (e->vid == vid && e->msgtype == msgtype)
			return (e->fields);
	}
	return (NULL);
}

static nmsg_message_t
message_init(struct nmsg_msgmod *mod, const char *fname,
	     uint line_num, const char *fields_file)
{
	nmsg_message_t msg;

	msg = nmsg_message_init(mod);
	if (msg == NULL)
		axa_error_msg("nmsg_message_init() failed for \"%s\""
			      " in line %d of \"%s\"",
			      fname, line_num, fields_file);
	return (msg);
}

static bool
get_enum_value(struct nmsg_msgmod *mod, const char *fname,
	       const char *enum_name, uint *valp,
	       uint line_num, const char *fields_file)
{
	nmsg_message_t msg;
	nmsg_res res;

	msg = message_init(mod, fname, line_num, fields_file);
	if (msg == NULL) {
		axa_error_msg("unrecognized %s enum field name \"%s\""
			      " in line %d of \"%s\"",
			      fname, enum_name, line_num, fields_file);
		return (false);
	}

	res = nmsg_message_enum_name_to_value(msg, fname, enum_name, valp);
	nmsg_message_destroy(&msg);

	if (res != nmsg_res_success) {
		axa_error_msg("unrecognized %s enum value \"%s\""
			      " in line %d of \"%s\"",
			      fname, enum_name, line_num, fields_file);
		return (false);
	}
	return (true);
}

/* Get the nmsg index of a field by its name for a line in the fields file. */
static axa_nmsg_idx_t
get_field_idx(struct nmsg_msgmod *mod,	/* This module */
	      const char *ftype,	/* our name for the field type */
	      const char *fname,	/* target field name */
	      uint line_num, const char *fields_file)
{
	uint idx;
	nmsg_message_t msg;
	nmsg_res res;

	msg = message_init(mod, fname, line_num, fields_file);
	if (msg == NULL)
		return (AXA_NMSG_IDX_ERROR);

	res = nmsg_message_get_field_idx(msg, fname, &idx);
	nmsg_message_destroy(&msg);

	if (res != nmsg_res_success) {
		axa_error_msg("unrecognized %s%sfield name \"%s\""
			      " in line %d of \"%s\"",
			      ftype, ftype[0] != '\0' ? " " : "",
			      fname, line_num, fields_file);
		return (AXA_NMSG_IDX_ERROR);
	}

	if (idx >= AXA_NMSG_IDX_RSVD) {
		axa_error_msg("%s%sfield name \"%s\"=%d and > AXA limit %d"
			      " in line %d of \"%s\"",
			      ftype, ftype[0] != '\0' ? " " : "",
			      fname, idx, AXA_NMSG_IDX_RSVD,
			      line_num, fields_file);
		return (AXA_NMSG_IDX_ERROR);
	}

	return (idx);
}

/* Get the nmsg index of a helper field and whether to use val_idx=0 */
static bool
get_help_idx(axa_nmsg_help_t *help,	/* results here */
	     struct nmsg_msgmod *mod,	/* this module */
	     const char *ftype,		/* our name for the field type */
	     const char *fname,		/* helper nmsg field name */
	     uint line_num, const char *fields_file)
{
	help->idx = get_field_idx(mod, ftype, fname, line_num, fields_file);
	return (help->idx < AXA_NMSG_IDX_RSVD);
}

/* Parse the content field of a fields file line to get a content type. */
static axa_fc_t
get_fc(const char *content, uint line_num, const char *fields_file)
{
	typedef struct {
		const char  *s;
		axa_fc_t    fc;
	} fc_tbl_t;
	static fc_tbl_t fc_tbl[] = {
		{"IP-dgram",	    AXA_FC_IP_DGRAM},
		{"IP",		    AXA_FC_IP},
		{"IP-ASCII",	    AXA_FC_IP_ASCII},
		{"domain",	    AXA_FC_DOM},
		{"domain-ASCII",    AXA_FC_DOM_ASCII},
		{"host",	    AXA_FC_HOST},
		{"rdata",	    AXA_FC_RDATA},
		{"dns",		    AXA_FC_DNS},
		{"json",	    AXA_FC_JSON},
	};
	const fc_tbl_t *tp;

	/* This is done only at start-up, so do not worry about speed. */
	for (tp = fc_tbl; tp <= AXA_LAST(fc_tbl); ++tp) {
		if (strcasecmp(content, tp->s) == 0)
			return (tp->fc);
	}

	if (content[0] == '\0') {
		axa_error_msg("missing field content"
			      " in line %d of \"%s\"",
			      line_num, fields_file);
	} else {
		axa_error_msg("unrecognized field content \"%s\""
			      " in line %d of \"%s\"",
			      content, line_num, fields_file);
	}
	return (AXA_FC_UNKNOWN);
}

static char *
get_subsubval(char *subval)
{
	char *p;

	p = strchr(subval, '=');
	if (p == NULL || p[1] == '\0')
		return (NULL);
	*p++ = '\0';
	return (p);
}

/*
 * Read the fields file to build the tables of known vendor IDs,
 * message types, and fields.
 */
void
axa_load_fields(const char *fields_file0)
{
	char *fields_file;
	FILE *f;
	char *line_buf;
	size_t line_buf_size;
	uint line_num;
	const char *line;
	char *p;
	struct nmsg_msgmod *mod;
	vm_entry_t *vm_list, *vm, **vmp;
	axa_nmsg_field_t *field;
	axa_nmsg_sf_t *sf, *sf2;
	char fc[AXA_FIELD_NM_LEN];
	char subtype[AXA_FIELD_NM_LEN];
	char subval[AXA_FIELD_NM_LEN];
	uint vid, msgtype;
	uint num_vm, num_vm_bins;
	size_t len;

	axa_unload_fields();

	/*
	 * Use a specified file, or default to $AXACONF/fields,
	 * or $HOME/.axa/fields, or AXACONFDIR/fields.
	 */
	if (fields_file0 != NULL && *fields_file0 != '\0') {
		fields_file = axa_strdup(fields_file0);
		f = fopen(fields_file, "r");
	} else {
		f = NULL;
		p = getenv("AXACONF");
		if (p == NULL) {
			fields_file = NULL;
		} else {
			axa_asprintf(&fields_file, "%s/%s",
				     p, "fields");
			f = fopen(fields_file, "r");
		}
		if (f == NULL) {
			if (fields_file != NULL)
				free(fields_file);
			p = getenv("HOME");
			if (p == NULL) {
				fields_file = NULL;
			} else {
				axa_asprintf(&fields_file, "%s/%s", p, "fields");
				f = fopen(fields_file, "r");
			}
		}
		if (f == NULL) {
			if (fields_file != NULL)
				free(fields_file);
			fields_file = strdup(AXACONFDIR"/fields");
			f = fopen(fields_file, "r");
		}
	}
	if (f == NULL) {
		axa_error_msg("cannot open \"%s\": %s",
			      fields_file, strerror(errno));
		free(fields_file);
		return;
	}

	line_buf = NULL;
	line_buf_size = 0;

	vm_list = NULL;
	num_vm = 0;
	line_num = 0;
	field = NULL;
	for (;;) {
next_line:
		if (field != NULL) {
			free_field(field);
			field = NULL;
		}

		line = axa_fgetln(f, fields_file, &line_num,
				  &line_buf, &line_buf_size);
		if (line == NULL)
			break;

		field = AXA_SALLOC(axa_nmsg_field_t);
		*field = axa_null_field;
		field->line_num = line_num;

		/* get the vendor name and message type from the line */
		if (0 > axa_get_token(field->vname, sizeof(field->vname),
				      &line, AXA_WHITESPACE)
		    || (vid = nmsg_msgmod_vname_to_vid(field->vname)) == 0) {
			axa_error_msg("unrecognized vendor \"%s\""
				      " in line %d of \"%s\"",
				      field->vname, line_num, fields_file);
			continue;
		}
		if (vid >= AXA_NMSG_IDX_RSVD) {
			axa_error_msg("vendor \"%s\" >= AXA limit %d"
				      " in line %d of \"%s\"",
				      field->vname, AXA_NMSG_IDX_RSVD,
				      line_num, fields_file);
			continue;
		}

		if (*line == '\0') {
			axa_error_msg("missing message type and field name"
				      " in line %d of \"%s\"",
				      line_num, fields_file);
			continue;
		}
		if (0 > axa_get_token(field->mname, sizeof(field->mname),
				      &line, AXA_WHITESPACE)
		    || (msgtype = nmsg_msgmod_mname_to_msgtype(vid,
							field->mname)) == 0) {
			axa_error_msg("unrecognized message type \"%s\""
				      " in line %d of \"%s\"",
				      field->mname, line_num, fields_file);
			continue;
		}
		if (msgtype >= AXA_NMSG_IDX_RSVD) {
			axa_error_msg("message type \"%s\" >= AXA limit %d"
				      " in line %d of \"%s\"",
				      field->mname,
				      AXA_NMSG_IDX_RSVD, line_num, fields_file);
			continue;
		}

		/* Search the list of known (vendor,message type) pairs.
		 * If this pair is new, get their libnmsg ordinals. */
		for (vm = vm_list; vm != NULL; vm = vm->next) {
			if (vm->vid == vid && vm->msgtype == msgtype)
				break;
		}
		if (vm != NULL) {
			mod = vm->mod;
		} else {
			mod = nmsg_msgmod_lookup_byname(field->vname,
							field->mname);
			if (mod == NULL) {
				axa_error_msg("cannot find module for vendor ID"
					      " \"%s\" and message type \"%s\""
					      " in line %d of \"%s\"",
					      field->vname, field->mname,
					      line_num, fields_file);
				continue;
			}
		}

		/* Add the field specified by the rest of the line to the
		 * list of interesting fields of this (vendor, message type)
		 * pair.  Start by parsing the name of the field. */
		if (*line == '\0') {
			axa_error_msg("missing field name"
				      " in line %d of \"%s\"",
				      line_num, fields_file);
			continue;
		}
		if (0 > axa_get_token(field->name, sizeof(field->name),
				      &line, AXA_WHITESPACE)) {
			axa_error_msg("bad field name"
				      " in line %d of \"%s\"",
				      line_num, fields_file);
			continue;
		}
		field->idx = get_field_idx(mod, "", field->name,
					   line_num, fields_file);
		if (field->idx >= AXA_NMSG_IDX_RSVD)
			continue;

		/* parse the content type */
		axa_get_token(fc, sizeof(fc), &line, AXA_WHITESPACE);
		field->fc = get_fc(fc, line_num, fields_file);
		if (field->fc == AXA_FC_UNKNOWN)
			continue;

		while (*line != '\0') {
			/* get next optional "subtype=fname..."
			 * subtype is {rtype|class|...}
			 * subval is the name of the nmsg field with the
			 *	required subtype data. */
			if (0 > axa_get_token(subtype, sizeof(subtype),
					      &line, "=")
			    || strpbrk(subtype, AXA_WHITESPACE) != NULL) {
				axa_error_msg("unrecognized \"%s\""
					      " in line %d of \"%s\"",
					      subtype, line_num, fields_file);
				goto next_line;
			}
			if (0 > axa_get_token(subval, sizeof(subval),
					      &line, AXA_WHITESPACE)
			    || subval[0] == '\0') {
				axa_error_msg("unrecognized \"%s=%s\""
					      " in line %d of \"%s\"",
					      subtype, subval,
					      line_num, fields_file);
				goto next_line;
			}

			if ((field->fc == AXA_FC_RDATA
			     || field->fc == AXA_FC_DOM)
			    && field->class.idx == AXA_NMSG_IDX_NONE
			    && strcasecmp(subtype, "class") == 0) {
				if (!get_help_idx(&field->class,
						  mod, subtype, subval,
						  line_num, fields_file))
					goto next_line;

			} else if (field->fc == AXA_FC_RDATA
				   && field->rtype.idx == AXA_NMSG_IDX_NONE
				   && strcasecmp(subtype, "rtype") == 0) {
				if (!get_help_idx(&field->rtype,
						  mod, subtype, subval,
						  line_num, fields_file))
					goto next_line;

			} else if (field->fc == AXA_FC_RDATA
				   && field->owner.idx == AXA_NMSG_IDX_NONE
				   && strcasecmp(subtype, "oname") == 0) {
				if (!get_help_idx(&field->owner,
						  mod, subtype, subval,
						  line_num, fields_file))
					goto next_line;

			} else if (field->enm.idx == AXA_NMSG_IDX_NONE
				   && strcasecmp(subtype, "enum") == 0
				   && ((p = get_subsubval(subval)) != NULL) && *p != '\0') {
				field->enm.idx = get_field_idx(mod,
							subtype, subval,
							line_num, fields_file);
				if (field->enm.idx >= AXA_NMSG_IDX_RSVD)
					goto next_line;
				if (!get_enum_value(mod, subval,
						    p, &field->enm_val,
						    line_num, fields_file))
					goto next_line;

			} else if (field->fc == AXA_FC_JSON
				   && strcasecmp(subtype, "sfield") == 0
				   && ((p = get_subsubval(subval)) != NULL) && *p != '\0') {
				sf = axa_zalloc(sizeof(axa_nmsg_sf_t)
						+strlen(subval)+1);
				sf->next = field->sf;
				field->sf = sf;
				sf->len = strlen(subval);
				memcpy(sf->name, subval, sf->len);
				sf->fc = get_fc(p, line_num, fields_file);
				switch (sf->fc) {
				case AXA_FC_IP_ASCII:
				case AXA_FC_DOM_ASCII:
				case AXA_FC_HOST:
					break;
				case AXA_FC_UNKNOWN:
				case AXA_FC_IP_DGRAM:
				case AXA_FC_IP:
				case AXA_FC_DOM:
				case AXA_FC_RDATA:
				case AXA_FC_DNS:
				case AXA_FC_JSON:
				default:
					goto next_line;
				}
				for (sf2 = sf->next;
				     sf2 != NULL;
				     sf2 = sf2->next) {
					if (strcmp(sf->name, sf2->name) == 0) {
					    axa_error_msg("duplicate sfield=%s"
							" in line %d of \"%s\"",
							sf->name,
							line_num, fields_file);
					    goto next_line;
					}
				}
			} else {
				axa_error_msg("unrecognized \"%s=%s\""
					      " in line %d of \"%s\"",
					      subtype, subval,
					      line_num, fields_file);
				goto next_line;
			}
		}

		if (field->class.idx == AXA_NMSG_IDX_NONE
		    && (field->fc == AXA_FC_DOM
			|| field->fc == AXA_FC_RDATA)) {
			axa_error_msg("missing \"class=field\""
				      " in line %d of \"%s\"",
				      line_num, fields_file);
			continue;
		}
		if (field->rtype.idx == AXA_NMSG_IDX_NONE
		    && field->fc == AXA_FC_RDATA) {
			axa_error_msg("missing \"rtype=field\""
				      " in line %d of \"%s\"",
				      line_num, fields_file);
			continue;
		}

		/* If we have previously seen this vendor and message type,
		 * ensure that we have not see this field. */
		if (vm != NULL) {
			const axa_nmsg_field_t *field2;

			for (field2 = vm->fields;
			     field2 != NULL;
			     field2 = field2->next) {
				if (field2->idx == field->idx
				    && field->enm.idx == field2->enm.idx
				    && field->enm_val == field2->enm_val)
					break;
			}
			if (field2 != NULL) {
				axa_error_msg("duplicate vendor ID,"
					      " message type, and field name"
					      " in lines %d and %d of \"%s\"",
					      line_num, field2->line_num,
					      fields_file);
				continue;
			}
		} else {
			vm = AXA_SALLOC(vm_entry_t);
			vm->vid = vid;
			vm->msgtype = msgtype;
			vm->mod = mod;
			vm->next = vm_list;
			vm_list = vm;
			++num_vm;
		}
		field->next = vm->fields;
		field->vm = vm;
		vm->fields = field;
		field = NULL;
	}
	if (field != NULL) {
		free_field(field);
		field = NULL;
	}
	fclose(f);
	if (line_buf != NULL)
		free(line_buf);

	if (num_vm == 0) {
		axa_error_msg("no fields defined in \"%s\"", fields_file);
		free(fields_file);
		return;
	}

	/* Move the list of lists of fields into a hash table.
	 * Be generous because this hash table is small. */
	num_vm_bins = axa_hash_divisor(num_vm*2+20, false);
	len = sizeof(*vm_hash_tbl) + sizeof(vm_hash_tbl->bins[0])*num_vm_bins;
	vm_hash_tbl = axa_zalloc(len);

	vm_hash_tbl->num_bins = num_vm_bins;
	while ((vm = vm_list) != NULL) {
		vm_list = vm->next;
		vmp = vm_hash_fnc(vm->vid, vm->msgtype);
		vm->next = *vmp;
		*vmp = vm;
	}

	free(fields_file);
}

/* Get the contents of a "helper" field for a fields file line */
bool
axa_get_helper(axa_emsg_t *emsg, const nmsg_message_t msg,
	       const axa_nmsg_help_t *help, axa_nmsg_idx_t val_idx,
	       void *val, size_t *val_len,
	       size_t min_val_len, size_t max_val_len,
	       axa_helper_cache_t *cache)
{
	void *data;
	size_t data_len;
	uint cn;
	nmsg_res res;

	if (help->idx >= AXA_NMSG_IDX_RSVD) {
		axa_pemsg(emsg, "invalid field index %#x", help->idx);
		return (false);
	}

	/* Be fast about repeated fetches of the helper values */
	if (cache != NULL) {
		for (cn = 0; cn < cache->len; ++cn) {
			if (cache->e[cn].idx == help->idx
			    && cache->e[cn].val_idx == val_idx) {
				if (min_val_len == sizeof(cache->e[cn].val)
				    && max_val_len == sizeof(cache->e[cn].val)) {
					memcpy(val, &cache->e[cn].val,
					       min_val_len);
					if (val_len != NULL)
					    *val_len = sizeof(cache->e[cn].val);
					return (true);
				}
				break;
			}
		}
	}

	res = nmsg_message_get_field_by_idx(msg, help->idx, val_idx,
					    &data, &data_len);
	if (res != nmsg_res_success) {
		axa_pemsg(emsg, "nmsg_message_get_field_by_idx(%s): %s",
			  axa_get_field_name(msg, help->idx),
			  nmsg_res_lookup(res));
		return (false);
	}
	if (data_len < min_val_len || data_len > max_val_len) {
		axa_pemsg(emsg, "%s size=%zd not >=%zd and <=%zd",
			  axa_get_field_name(msg, help->idx), data_len,
			  min_val_len, max_val_len);
		return (false);
	}

	memcpy(val, data, data_len);
	if (val_len != NULL)
		*val_len = data_len;

	if (cache != NULL && (cn = cache->len) < AXA_HELPER_CACHE_LEN
	    && min_val_len == data_len
	    && min_val_len == sizeof(cache->e[cn].val)
	    && max_val_len == sizeof(cache->e[cn].val)) {
		cache->e[cn].idx = help->idx;
		cache->e[cn].val_idx = val_idx;
		memcpy(&cache->e[cn].val, data, sizeof(cache->e[cn].val));
		++cache->len;
	}

	return (true);
}

