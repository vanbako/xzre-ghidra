#ifndef XZRE_TYPES_IMPORT_H
#define XZRE_TYPES_IMPORT_H

/* Minimize external dependencies for Ghidra's C parser */
#define XZRE_SLIM 1

/* Drop static assertions that aren't required for type creation */
#ifndef static_assert
#define static_assert(...)
#endif
#define assert_offset(...)

/* Provide minimal stdint/stddef definitions to keep preprocessing small */
typedef long ptrdiff_t;
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned long uintptr_t;
typedef long intptr_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;

/* Bring in the project headers whose types should be imported */
#include "../xzre/util.h"
#include "../xzre/xzre.h"

#endif /* XZRE_TYPES_IMPORT_H */
