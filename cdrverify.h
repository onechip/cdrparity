#ifndef __CDRVERIFY_H
#define __CDRVERIFY_H

#include <stddef.h>

ssize_t find_marker_v1(const void* src, size_t len);
int verify_v1(int in, size_t ofs, void* buf, size_t buf_size);

ssize_t find_marker_v2(const void* src, size_t len);
int verify_v2(int in, size_t ofs, void* buf, size_t buf_size);

#endif
