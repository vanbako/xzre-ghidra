// /home/kali/xzre-ghidra/xzregh/10D008_tls_get_addr.c
// Function: __tls_get_addr @ 0x10D008
// Calling convention: __stdcall
// Prototype: void * __stdcall __tls_get_addr(tls_index * ti)


/* WARNING: Control flow encountered bad instruction data */
/* Same trap pattern as `lzma_check_init`: the compiled object ships a dummy `__tls_get_addr` that
   halts if invoked. The loader
   adjusts the GOT to point at `j_tls_get_addr` (and eventually the host's resolver); leaving this
   stub in place makes unexpected
   execution obvious and prevents the payload from silently calling an incomplete resolver. */

void * __tls_get_addr(tls_index *ti)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

