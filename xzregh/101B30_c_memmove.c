// /home/kali/xzre-ghidra/xzregh/101B30_c_memmove.c
// Function: c_memmove @ 0x101B30
// Calling convention: __stdcall
// Prototype: void * __stdcall c_memmove(char * dest, char * src, size_t cnt)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief copies memory
 *
 *   @param dest destination buffer
 *   @param src source buffer
 *   @param cnt number of bytes to copy
 *
 * Upstream implementation excerpt (xzre/xzre_code/c_memmove.c):
 *     void *c_memmove(char *dest, char *src, size_t cnt) {
 *         if ((src < dest) && (dest < (src + cnt))) {
 *             size_t curr = cnt - 1;
 *             if (cnt != 0) {
 *                 do {
 *                     *(dest + curr) = *(src + curr);
 *                     --curr;
 *                 } while (curr != -1);
 *                 return dest;
 *             }
 *         } else {
 *             if (cnt == 0)
 *                 return dest;
 *             size_t curr = 0;
 *             do {
 *                 *(dest + curr) = *(src + curr);
 *                 ++curr;
 *             } while (cnt != curr);
 *         }
 *         return dest;
 *     }
 */

void * c_memmove(char *dest,char *src,size_t cnt)

{
  size_t curr;
  size_t curr_1;
  
  if ((src < dest) && (dest < src + cnt)) {
    curr = cnt - 1;
    if (cnt != 0) {
      do {
        dest[curr] = src[curr];
        curr = curr - 1;
      } while (curr != 0xffffffffffffffff);
      return dest;
    }
  }
  else {
    curr_1 = 0;
    if (cnt == 0) {
      return dest;
    }
    do {
      dest[curr_1] = src[curr_1];
      curr_1 = curr_1 + 1;
    } while (cnt != curr_1);
  }
  return dest;
}

