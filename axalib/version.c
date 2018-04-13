/*
 * AXA version reporting
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

#include <axa/axa.h>
#include <axa/version.h>

const char *
axa_get_version(void)
{
	return (AXA_LIBRARY_VERSION);
}

uint32_t
axa_get_version_number(void)
{
	return (AXA_LIBRARY_VERSION_NUMBER);
}
