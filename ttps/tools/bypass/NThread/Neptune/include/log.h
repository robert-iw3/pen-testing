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
 * @file log.h
 * @brief Logging interface for the Neptune library.
 *
 * This header provides a minimal and flexible logging system for the Neptune project.
 * It allows outputting messages of different severities (info, warning, error) to one or more
 * registered file streams, with optional formatting features such as timestamps, message types,
 * and colored output.
 *
 * Before using the logging API, the system must be initialized using `log_init()`,
 * and should be cleaned up with `log_destroy()` when no longer needed.
 */

#include "nfile.h"

#if defined(NFILE_DISABLE_WRITE) && NFILE_DISABLE_WRITE == 1

#ifdef LOG_LEVEL_1
#undef LOG_LEVEL_1
#endif // LOG_LEVEL_1

#ifdef LOG_LEVEL_2
#undef LOG_LEVEL_2
#endif // LOG_LEVEL_2

#ifdef LOG_LEVEL_3
#undef LOG_LEVEL_3
#endif // LOG_LEVEL_3

#ifdef LOG_LEVEL
#undef LOG_LEVEL
#endif // LOG_LEVEL

#endif // defined(NFILE_DISABLE_WRITE) && NFILE_DISABLE_WRITE == 1

#include "loghelper.h"

#ifdef LOG_LEVEL_1
#ifndef __LOG_H__
#define __LOG_H__

#include "color.h"
#include "nerror.h"

#ifndef LOG_ON_STDOUT
#ifdef MODULE
#define LOG_ON_STDOUT 0
#else // !MODULE
#define LOG_ON_STDOUT 1
#endif // !MODULE
#endif // !LOG_ON_STDOUT

#define LOG_INFO_COLOR COLOR_CYAN
#define LOG_WARN_COLOR COLOR_YELLOW
#define LOG_ERROR_COLOR COLOR_RED

#define LOG_FILE_DONT_CLOSE 0x01
#define LOG_FILE_DONT_FLUSH 0x02

#define LOG_FILE_PRINT_TIME 0x04
#define LOG_FILE_PRINT_TYPE 0x08
#define LOG_FILE_PRINT_MSG 0x10
#define LOG_FILE_PRINT_ENDL 0x20

#define LOG_FILE_COLORABLE 0x80

#ifndef LOG_SFILE_MASK
#ifdef __WIN32

#define LOG_TEMP_SFILE_MASK                                               \
	(LOG_FILE_PRINT_TIME | LOG_FILE_PRINT_TYPE | LOG_FILE_PRINT_MSG | \
	 LOG_FILE_PRINT_ENDL | LOG_FILE_DONT_CLOSE)

#ifdef LOG_FORCE_COLOR
#define LOG_SFILE_MASK LOG_TEMP_SFILE_MASK | LOG_FILE_COLORABLE
#else // !LOG_FORCE_COLOR
#define LOG_SFILE_MASK LOG_TEMP_SFILE_MASK
#endif // !LOG_FORCE_COLOR

#else // !__WIN32

#define LOG_SFILE_MASK                                                    \
	(LOG_FILE_PRINT_TIME | LOG_FILE_PRINT_TYPE | LOG_FILE_PRINT_MSG | \
	 LOG_FILE_PRINT_ENDL | LOG_FILE_DONT_CLOSE | LOG_FILE_COLORABLE)

#endif // !__WIN32

#endif // !LOG_SFILE_MASK

#ifndef LOG_DFILE_MASK

#define LOG_DFILE_MASK                                                    \
	(LOG_FILE_PRINT_TIME | LOG_FILE_PRINT_TYPE | LOG_FILE_PRINT_MSG | \
	 LOG_FILE_PRINT_ENDL)

#endif // !LOG_DFILE_MASK

#define LOG_ERROR_S 0x6100

#define LOG_ALLOC_ERROR 0x6101
#define LOG_REALLOC_ERROR 0x6102
#define LOG_NFILE_OPEN_W_ERROR 0x6103

#define LOG_ERROR_E LOG_NFILE_OPEN_W_ERROR

#define LOG_INFO_TEXT "INFO"
#define LOG_WARN_TEXT "WARN"
#define LOG_ERROR_TEXT "ERROR"

#define LOG_CLASS_TIME LOG_FILE_PRINT_TIME
#define LOG_CLASS_TYPE LOG_FILE_PRINT_TYPE
#define LOG_CLASS_MSG LOG_FILE_PRINT_MSG
#define LOG_CLASS_ENDL LOG_FILE_PRINT_ENDL

// Bitmask type for specifying logging behavior
typedef int8_t log_file_flags_t;

// Represents a log output target and its formatting flags
struct log_file {
	nfile_t file; // File or stream to write log output to
	log_file_flags_t file_flags; // Bitmask of LOG_CLASS_* flags
};

typedef struct log_file log_file_t;

/**
 * @brief Set the color for subsequent log messages (if supported).
 * @param color The color to apply to the log output.
 */
void log_set_color(color_t color);

/**
 * @brief Register an existing file as a log output target with specific flags.
 * @param file The file to output logs to.
 * @param file_flags Formatting flags.
 * @return Error code.
 */
nerror_t log_reg_file_ex(nfile_t file, log_file_flags_t file_flags);

/**
 * @brief Register a new log file by path with default flags.
 * @param path Path to the file to be used for logging.
 * @return Error code.
 */
nerror_t log_reg_file(nfile_path_t path);

/**
 * @brief Check if logging output is currently enabled.
 * @return true if logging is active, false otherwise.
 */
bool log_can_out(void);

/**
 * @brief Write an informational log message.
 * @param format Format string (printf-style).
 * @param ... Arguments matching the format.
 * @return Error code.
 */
nerror_t log_info(const char *format, ...);

/**
 * @brief Write a warning log message.
 * @param format Format string (printf-style).
 * @param ... Arguments matching the format.
 * @return Error code.
 */
nerror_t log_warn(const char *format, ...);

/**
 * @brief Write an error log message.
 * @param format Format string (printf-style).
 * @param ... Arguments matching the format.
 * @return Error code.
 */
nerror_t log_error(const char *format, ...);

/**
 * @brief Initialize the logging system.
 * @return Error code.
 */
nerror_t log_init(void);

/**
 * @brief Clean up and close any log output targets.
 */
void log_destroy(void);

/**
 * @brief Core function for writing a formatted log message with a va_list.
 * @param color Color of the log message, of type color_t (e.g., for terminal styling).
 * @param type String representing log type (e.g., "INFO", "ERROR").
 * @param format Format string.
 * @param list va_list containing arguments.
 * @return Error code.
 */
nerror_t log_log_v(color_t color, const char *type, const char *format,
		   va_list list);

/**
 * @brief Write a formatted log message with variable arguments.
 * @param color Color of the log message, of type color_t (e.g., for terminal styling).
 * @param type String representing log type (e.g., "INFO", "ERROR").
 * @param format Format string.
 * @param ... Variable arguments.
 * @return Error code.
 */
nerror_t log_log(color_t color, const char *type, const char *format, ...);

// Convenience macros for simplified logging

#define LOG_V(color, type, format, list) \
	log_log_v(color, type, format, list) // Log with va_list

#define LOG(color, type, format, ...) \
	log_log(color, type, format,  \
		##__VA_ARGS__) // Log with variadic arguments

#define LOG_INFO(format, ...) \
	log_info(format, ##__VA_ARGS__) // Shorthand for informational logs

#define LOG_WARN(format, ...) \
	log_warn(format, ##__VA_ARGS__) // Shorthand for warning logs

#define LOG_ERROR(format, ...) \
	log_error(format, ##__VA_ARGS__) // Shorthand for error logs

#endif // !__LOG_H__
#else // !LOG_LEVEL_1
#define log_can_out() (false)
#endif // !LOG_LEVEL_1
