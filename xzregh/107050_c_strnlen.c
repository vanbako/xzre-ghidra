// /home/kali/xzre-ghidra/xzregh/107050_c_strnlen.c
// Function: c_strnlen @ 0x107050
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall c_strnlen(char * str, size_t max_len)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief returns length of c string with a maximum length
 *
 *   @param str pointer to c string
 *   @param max_len maximum length of c string
 *   @return ssize_t length of c string
 *
 * Upstream implementation excerpt (xzre/xzre_code/c_strnlen.c):
 *     ssize_t c_strnlen(char *str, size_t max_len) {
 *         ssize_t len = 0;
 *         if (max_len == 0)
 *             return max_len;
 *         do {
 *             if (*(str + len) == '\0')
 *                 return len;
 *             ++len;
 *         } while (max_len != len);
 *         return max_len;
 *     }
 */

ssize_t c_strnlen(char *str,size_t max_len)

{
  ssize_t len;
  
  len = 0;
  if (max_len == 0) {
    return max_len;
  }
  do {
    if (str[len] == '\0') {
      return len;
    }
    len = len + 1;
  } while (max_len != len);
  return max_len;
}

