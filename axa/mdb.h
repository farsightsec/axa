/*
 * Advanced Exchange Access (AXA) mdb functions
 *
 *  Copyright (c) 2018 by Farsight Security, Inc.
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

#ifndef AXA_MDB_H
#define AXA_MDB_H

/**
 *  \defgroup axa_mdb axa_mdb
 *
 *  `axa_mdb` contains lmdb functions specific to libaxa.
 *
 * @{
 */

#include <lmdb.h>

int axa_tsi_mdb_cmp(const MDB_val *a, const MDB_val *b);

#endif /* AXA_MDB_H */
