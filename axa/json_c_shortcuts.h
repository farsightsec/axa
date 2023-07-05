/*
 * Advanced Exchange Access (AXA) json-c shortcut macros
 *
 *  Copyright (c) 2023 by Farsight Security, Inc.
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

#ifndef AXA_JSON_C_SHORTCUTS_H
#define AXA_JSON_C_SHORTCUTS_H

#define json_c_add_string(g,name,val) do {	\
	int _status;	\
	_status = json_object_object_add(g, name, json_object_new_string(val));	\
        AXA_ASSERT(_status == 0);	\
} while (0)

#define json_c_add_string_len(g,name,val,vlen) do {	\
	int _status;	\
	_status = json_object_object_add(g, name, json_object_new_string_len(val, vlen));	\
        AXA_ASSERT(_status == 0);	\
} while (0)

#define json_c_add_number(g,name,val) do {	\
	int _status;	\
	_status = json_object_object_add(g, name, json_object_new_uint64(val));	\
        AXA_ASSERT(_status == 0);	\
} while (0)

#define json_c_add_double_s(g,name,val,vstr) do {	\
	int _status;	\
	_status = json_object_object_add(g, name, json_object_new_double_s(val, vstr));	\
        AXA_ASSERT(_status == 0);	\
} while (0)

#define json_c_add_bool(g,name,val) do {	\
	int _status;	\
	_status = json_object_object_add(g, name, json_object_new_boolean(val));	\
        AXA_ASSERT(_status == 0);	\
} while (0)

#define json_c_add_null(g,name) do {	\
	int _status;	\
	_status = json_object_object_add(g, name, json_object_new_null());	\
        AXA_ASSERT(_status == 0);	\
} while (0)

#define json_c_add_to_array(g,val) do {	\
	int _status;	\
	_status = json_object_array_add(g, val);	\
	AXA_ASSERT(_status == 0);	\
} while (0)

#define json_c_add_string_to_array(g,val) do {	\
	int _status;	\
	_status = json_object_array_add(g, json_object_new_string(val));	\
	AXA_ASSERT(_status == 0);	\
} while (0)

#endif /* AXA_JSON_C_SHORTCUTS_H */
