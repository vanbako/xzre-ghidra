// /home/kali/xzre-ghidra/xzregh/101B30_c_memmove.c
// Function: c_memmove @ 0x101B30
// Calling convention: __stdcall
// Prototype: void * __stdcall c_memmove(char * dest, char * src, size_t cnt)


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

