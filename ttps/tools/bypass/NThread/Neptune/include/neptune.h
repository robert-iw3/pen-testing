/**
 * MIT License
 *
 * Copyright (c) 2024, 2025 Serkan Aksoy
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file neptune.h
 * @brief Core configuration and utilities for the Neptune library.
 *
 * This header defines global metadata macros (author, license, version, etc.),
 * macro utilities for argument counting, and portable implementations of
 * common memory search functions (memmem, memstr).
 *
 * Part of the Neptune base library for cross-platform system-level development.
 */

#ifndef __NEPTUNE_H__
#define __NEPTUNE_H__

#ifndef AUTHOR
#define AUTHOR "Serkan Aksoy"
#endif // !AUTHOR

#ifndef LICENSE
#define LICENSE "MIT"
#endif // !LICENSE

#ifndef PROJECT
#define PROJECT "Neptune"
#endif // !PROJECT

#ifndef VERSION
#define VERSION "1.0.0"
#endif // !VERSION

#ifndef DESCRIPTION
#define DESCRIPTION "Neptune for Neptune apps"
#endif // !DESCRIPTION

#ifndef NEPTUNE_MODULERULES_HEADER
#define NEPTUNE_MODULERULES_HEADER "neptune_rules.h"
#endif // !NEPTUNE_MODULERULES_HEADER

#ifdef MODULE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/mutex.h>

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);

#else // !MODULE

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifdef __WIN32
#include <windows.h>
#else // !__WIN32
#include <pthread.h>
#endif // !__WIN32

#endif // !MODULE

#ifndef LOG_FILE_PATH
#ifdef MODULE
#define LOG_FILE_PATH "/var/log/neptune.log"
#else // !MODULE

#ifdef __WIN32
// #define LOG_FILE_PATH L"neptune.log"
#else // !__WIN32
#define LOG_FILE_PATH "neptune.log"
#endif // !__WIN32

#endif // !MODULE
#endif // !LOG_FILE_PATH

#include "nerror.h"

#define NEPTUNE_GET_ARG_COUNT(...) \
	NEPTUNE_GET_ARG_COUNT_HELPER(__VA_ARGS__, NEPTUNE_COUNTDOWN_127_TO_0())
#define NEPTUNE_GET_ARG_COUNT_HELPER(...) NEPTUNE_GET_128TH_ARG(__VA_ARGS__)
#define NEPTUNE_GET_128TH_ARG(                                                 \
	_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, \
	_17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, _30,  \
	_31, _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, _42, _43, _44,  \
	_45, _46, _47, _48, _49, _50, _51, _52, _53, _54, _55, _56, _57, _58,  \
	_59, _60, _61, _62, _63, _64, _65, _66, _67, _68, _69, _70, _71, _72,  \
	_73, _74, _75, _76, _77, _78, _79, _80, _81, _82, _83, _84, _85, _86,  \
	_87, _88, _89, _90, _91, _92, _93, _94, _95, _96, _97, _98, _99, _100, \
	_101, _102, _103, _104, _105, _106, _107, _108, _109, _110, _111,      \
	_112, _113, _114, _115, _116, _117, _118, _119, _120, _121, _122,      \
	_123, _124, _125, _126, _127, N, ...)                                  \
	N
#define NEPTUNE_COUNTDOWN_127_TO_0()                                          \
	127, 126, 125, 124, 123, 122, 121, 120, 119, 118, 117, 116, 115, 114, \
		113, 112, 111, 110, 109, 108, 107, 106, 105, 104, 103, 102,   \
		101, 100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 87, \
		86, 85, 84, 83, 82, 81, 80, 79, 78, 77, 76, 75, 74, 73, 72,   \
		71, 70, 69, 68, 67, 66, 65, 64, 63, 62, 61, 60, 59, 58, 57,   \
		56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42,   \
		41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27,   \
		26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,   \
		11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

#define NEPTUNE_ERROR 0xba00

#define NEPTUNE_INIT_ERROR 0xba01
#define NEPTUNE_INIT_ERROR_E (NEPTUNE_INIT_ERROR + 127)

#define NEPTUNE_ERROR_E (NEPTUNE_INIT_ERROR_E)

/**
* @brief Initialize the Neptune core system.
*
* This function sets up all global and platform-specific subsystems required by the Neptune library.
* It must be called before using any other Neptune-provided functionality.
*
* @return Error code indicating success or failure of initialization.
*/
nerror_t neptune_init(void);

/**
* @brief Shutdown and clean up the Neptune core system.
*
* This function releases all resources allocated during initialization and runtime.
* It should be called once when the application is finished using the Neptune library.
*/
void neptune_destroy(void);

#ifndef memmem

#define NEPTUNE_DEFINE_MEMMEM

void *neptune_memmem(register const void *haystack, size_t haystacklen,
		     const void *needle, size_t needlelen);

#define memmem(haystack, haystacklen, needle, needlelen) \
	neptune_memmem(haystack, haystacklen, needle, needlelen)

#endif // !memmem

#ifndef memstr

#define NEPTUNE_DEFINE_MEMSTR

void *neptune_memstr(const void *haystack, const char *needle,
		     size_t haystacklen);

#define memstr(haystack, needle, needlelen) \
	neptune_memstr(haystack, needle, needlelen)

#endif /* !memstr */

#endif // !__NEPTUNE_H__
