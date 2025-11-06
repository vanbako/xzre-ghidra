// /home/kali/xzre-ghidra/xzregh/103F60_update_cpuid_got_index.c
// Function: update_cpuid_got_index @ 0x103F60
// Calling convention: __stdcall
// Prototype: void __stdcall update_cpuid_got_index(elf_entry_ctx_t * ctx)


void update_cpuid_got_index(elf_entry_ctx_t *ctx)

{
  (ctx->got_ctx).cpuid_fn = tls_get_addr_reloc_consts;
  return;
}

