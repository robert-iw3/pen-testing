/*
 * @file Log.hpp
 * @brief Log functions
 */

#include "Include.hpp"

// If you want log spam, turn on this
// #define VERBOSE_LOGGING

#define LogDbgViewInfo(Format, ...) DbgPrintEx(0, 0, "[Kurasagi] INFO: " Format "\n", __VA_ARGS__)
#define LogDbgViewError(Format, ...) DbgPrintEx(0, 0, "[Kurasagi] ERROR: " Format "\n", __VA_ARGS__)

#if DBG

#define LogInfo(Format, ...) LogDbgViewInfo(Format, __VA_ARGS__)
#define LogError(Format, ...) LogDbgViewError(Format, __VA_ARGS__)

#ifdef VERBOSE_LOGGING
#define LogVerbose(Format, ...) LogInfo(Format, __VA_ARGS__)
#else
#define LogVerbose(Format, ...)
#endif

#else

#define LogInfo(Format, ...)
#define LogError(Format, ...) LogDbgViewError(Format, __VA_ARGS__)
#define LogVerbose(Format, ...)

#endif