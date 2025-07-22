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
 * @file log_helper.h
 * @brief Logging level control macros for the Neptune logging system.
 *
 * This file defines the logging level hierarchy used by Neptune, allowing
 * developers to control the verbosity of logging at compile time using the
 * `LOG_LEVEL` macro.
 *
 * Logging levels:
 *   - LOG_LEVEL_1: Basic logging — only critical errors are reported.
 *   - LOG_LEVEL_2: Moderate logging — provides sufficient detail for most runtime diagnostics.
 *   - LOG_LEVEL_3: Verbose logging — outputs everything, typically used during development and testing.
 *
 * Logging can be completely disabled by defining `DISABLE_LOGS`.
 *
 * This header ensures consistency and simplifies conditional logging across
 * different modules of the project.
 */

#ifdef DISABLE_LOGS

// If logs are disabled, undefine all logging levels
#ifdef LOG_LEVEL
#undef LOG_LEVEL
#define LOG_LEVEL 0
#endif // LOG_LEVEL

#ifdef LOG_LEVEL_3
#undef LOG_LEVEL_3
#endif // LOG_LEVEL_3

#ifdef LOG_LEVEL_2
#undef LOG_LEVEL_2
#endif // LOG_LEVEL_2

#ifdef LOG_LEVEL_1
#undef LOG_LEVEL_1
#endif // LOG_LEVEL_1

#else // !DISABLE_LOGS

// Default logging level (no logs) if not specified
#ifndef LOG_LEVEL
#define LOG_LEVEL 0
#endif // !LOG_LEVEL

// Sanitize LOG_LEVEL to avoid negative values
#if LOG_LEVEL < 0
#undef LOG_LEVEL
#define LOG_LEVEL 0
#endif // LOG_LEVEL < 0

// Define the appropriate macro for the selected log level

#if LOG_LEVEL == 3
#ifndef LOG_LEVEL_3
#define LOG_LEVEL_3
#endif // !LOG_LEVEL_3
#endif // LOG_LEVEL == 3

#if LOG_LEVEL == 2
#ifndef LOG_LEVEL_2
#define LOG_LEVEL_2
#endif // !LOG_LEVEL_2
#endif // LOG_LEVEL == 2

#if LOG_LEVEL == 1
#ifndef LOG_LEVEL_1
#define LOG_LEVEL_1
#endif // !LOG_LEVEL_1
#endif // LOG_LEVEL == 1

// Ensure lower levels are also defined when higher level is enabled

#ifdef LOG_LEVEL_3

#ifndef LOG_LEVEL_2
#define LOG_LEVEL_2
#endif // !LOG_LEVEL_2

#if LOG_LEVEL < 3
#undef LOG_LEVEL
#define LOG_LEVEL 3
#endif // LOG_LEVEL < 3

#endif // LOG_LEVEL_3

#ifdef LOG_LEVEL_2
#ifndef LOG_LEVEL_1
#define LOG_LEVEL_1
#endif // !LOG_LEVEL_1

#if LOG_LEVEL < 2
#undef LOG_LEVEL
#define LOG_LEVEL 2
#endif // LOG_LEVEL < 2

#endif // LOG_LEVEL_2

#ifdef LOG_LEVEL_1
#if LOG_LEVEL < 1
#undef LOG_LEVEL
#define LOG_LEVEL 1
#endif // LOG_LEVEL < 1
#endif // LOG_LEVEL_1

#endif // !DISABLE_LOGS
