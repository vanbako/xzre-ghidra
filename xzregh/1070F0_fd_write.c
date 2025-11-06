// /home/kali/xzre-ghidra/xzregh/1070F0_fd_write.c
// Function: fd_write @ 0x1070F0
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall fd_write(int fd, void * buffer, size_t count, libc_imports_t * funcs)


ssize_t fd_write(int fd,void *buffer,size_t count,libc_imports_t *funcs)

{
  ssize_t sVar1;
  int *piVar2;
  size_t count_00;
  
  if (count == 0) {
    return 0;
  }
  if ((((funcs == (libc_imports_t *)0x0 || fd < 0) || (buffer == (void *)0x0)) ||
      (funcs->write == (_func_23 *)0x0)) ||
     (count_00 = count, funcs->__errno_location == (_func_26 *)0x0)) {
LAB_0010711f:
    count = 0xffffffffffffffff;
  }
  else {
    do {
      while( true ) {
        sVar1 = (*funcs->write)(fd,buffer,count_00);
        if (-1 < sVar1) break;
        piVar2 = (*funcs->__errno_location)();
        if (*piVar2 != 4) goto LAB_0010711f;
      }
      if (sVar1 == 0) goto LAB_0010711f;
      buffer = (void *)((long)buffer + sVar1);
      count_00 = count_00 - sVar1;
    } while (count_00 != 0);
  }
  return count;
}

