#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int  spy_start(const wchar_t* window_name_w,
               uint32_t pid,
               int timeout_sec,
               int set_no_uia_events,
               int set_no_property_events,
               int enable_debug);

void spy_stop(void);
size_t spy_read_line_w(wchar_t* out, size_t out_cap);

#ifdef __cplusplus
}
#endif
