// /home/kali/xzre-ghidra/xzregh/107050_c_strnlen.c
// Function: c_strnlen @ 0x107050
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall c_strnlen(char * str, size_t max_len)


/*
 * AutoDoc: Bounded strlen variant used on attacker-controlled buffers. It counts until it has inspected `max_len` bytes or hits a NUL,
 * returning `max_len` unchanged when the string is unterminated so callers can treat that as a failure.
 */

#include "xzre_types.h"

ssize_t c_strnlen(char *str,size_t max_len)

{
  size_t bytes_checked;
  
  bytes_checked = 0;
  // AutoDoc: Zero-length caps return immediately so callers can treat `max_len == 0` as a trivial pass.
  if (max_len == 0) {
    return max_len;
  }
  do {
    // AutoDoc: Stop as soon as a terminator arrives before the bound; the helper returns how many bytes were actually consumed.
    if (str[bytes_checked] == '\0') {
      return bytes_checked;
    }
    bytes_checked = bytes_checked + 1;
  // AutoDoc: If the loop walks the entire bound it reports `max_len` unchanged so callers know the string never terminated.
  } while (max_len != bytes_checked);
  return max_len;
}

