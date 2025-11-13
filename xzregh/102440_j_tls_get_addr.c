// /home/kali/xzre-ghidra/xzregh/102440_j_tls_get_addr.c
// Function: j_tls_get_addr @ 0x102440
// Calling convention: unknown
// Prototype: undefined j_tls_get_addr(void)


/*
 * AutoDoc: Jumps straight into the real `__tls_get_addr` resolver. The backdoor keeps both this wrapper and the trapping stub exported so it can redirect GOT entries during setup: hooks call `j_tls_get_addr` when they want the legit resolver, while the relocation constants point at the trapping version until the loader patches things up.
 */
#include "xzre_types.h"


void j_tls_get_addr(undefined8 param_1)

{
  __tls_get_addr(param_1);
  return;
}

