// /home/kali/xzre-ghidra/xzregh/107050_c_strnlen.c
// Function: c_strnlen @ 0x107050
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall c_strnlen(char * str, size_t max_len)


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

