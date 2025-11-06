// /home/kali/xzre-ghidra/xzregh/107030_c_strlen.c
// Function: c_strlen @ 0x107030
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall c_strlen(char * str)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief returns length of c string
 *
 *   @param str pointer to c string
 *   @return ssize_t length of c string
 *
 * Upstream implementation excerpt (xzre/xzre_code/c_strlen.c):
 *     ssize_t c_strlen(char *str) {
 *         if (*str != '\0') {
 *             ssize_t len = 0;
 *             do {
 *                 ++len;
 *             } while (*(str + len) != '\0');
 *             return len;
 *         }
 *         return 0;
 *     }
 */

ssize_t c_strlen(char *str)

{
  ssize_t len;
  
  if (*str != '\0') {
    len = 0;
    do {
      len = len + 1;
    } while (str[len] != '\0');
    return len;
  }
  return 0;
}

