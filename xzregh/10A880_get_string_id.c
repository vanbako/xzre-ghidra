// /home/kali/xzre-ghidra/xzregh/10A880_get_string_id.c
// Function: get_string_id @ 0x10A880
// Calling convention: __stdcall
// Prototype: EncodedStringId __stdcall get_string_id(char * string_begin, char * string_end)


/*
 * AutoDoc: Trie walker that maps printable strings to `EncodedStringId` values without ever storing plaintext literals. Each lookup logs
 * itself through `secret_data_append_from_address`, caps the scan at 0x2c bytes (or a caller-supplied string_end), and walks the packed
 * `string_mask_data`/`string_action_data` tables. Every byte selects one half of the bitmap pair, uses `count_bits` to compute its rank,
 * and looks up a two-word node entry whose flags either return the encoded ID or supply signed deltas that descend to the next bitmap row.
 * Missing bits or non-printable characters immediately bail with ID 0.
 */

#include "xzre_types.h"

EncodedStringId get_string_id(char *string_begin,char *string_end)

{
  ushort *child_entry;
  long bit_cursor;
  ushort bitmap_delta;
  ushort child_row_delta;
  BOOL logged_probe;
  uint child_rank;
  byte current_char;
  ushort child_header;
  ulong *bitmap_pair;
  byte *max_scan;
  long trie_row_offset;
  ulong candidate_bits;
  
  // AutoDoc: Record the string probe in the shift log so the attestation data captures which lookups touched the trie.
  logged_probe = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0xa,8,1);
  if (logged_probe != FALSE) {
    // AutoDoc: Clamp the walk to 0x2c bytes and shrink it further when the caller hands us an explicit upper bound.
    max_scan = (byte *)(string_begin + 0x2c);
    if ((string_end != (char *)0x0) && (string_end < max_scan)) {
      max_scan = (byte *)string_end;
    }
    trie_row_offset = 0x10c2a8;
    bitmap_pair = (ulong *)(_Lcrc64_clmul_1 + 0x760);
    // AutoDoc: Advance through printable ASCII until either the cap or a negative/NUL byte terminates the search.
    for (; (string_begin <= max_scan && (current_char = *string_begin, -1 < (char)current_char));
        string_begin = (char *)((byte *)string_begin + 1)) {
      // AutoDoc: Split the bitmap pair at 0x40—low bytes test the first 64-bit word, while high bytes subtract 0x40 and add the popcount of the first half.
      if (current_char < 0x40) {
        candidate_bits = *bitmap_pair;
        child_rank = 0;
        if ((candidate_bits >> (current_char & 0x3f) & 1) == 0) {
          return 0;
        }
      }
      else {
        candidate_bits = bitmap_pair[1];
        current_char = current_char - 0x40;
        if ((candidate_bits >> (current_char & 0x3f) & 1) == 0) {
          return 0;
        }
        child_rank = count_bits(*bitmap_pair);
      }
      // AutoDoc: Scan the bitmap word until the desired bit index surfaces so the accumulated rank matches the child slot we need.
      while( TRUE ) {
        bit_cursor = 0;
        if (candidate_bits != 0) {
          for (; (candidate_bits >> bit_cursor & 1) == 0; bit_cursor = bit_cursor + 1) {
          }
        }
        if ((uint)bit_cursor == (uint)current_char) break;
        child_rank = child_rank + 1;
        candidate_bits = candidate_bits & candidate_bits - 1;
      }
      child_entry = (ushort *)(trie_row_offset + (ulong)child_rank * 4);
      child_header = *child_entry;
      child_row_delta = child_entry[1];
      // AutoDoc: Flag 0x4 marks a terminal node, so the stored `child_row_delta` doubles as the EncodedStringId return value.
      if ((child_header & 4) != 0) {
        return (int)(short)child_row_delta;
      }
      if ((child_header & 2) == 0) {
        child_row_delta = -child_row_delta;
      }
      else {
        child_header = child_header & 0xfffd;
      }
      bitmap_delta = child_header & 0xfffe;
      if ((child_header & 1) == 0) {
        bitmap_delta = -child_header;
      }
      // AutoDoc: Use the remaining flag bits as signed deltas that hop to the next packed row inside `string_action_data`.
      trie_row_offset = trie_row_offset + (short)(child_row_delta - 4);
      // AutoDoc: Mirror the same signed delta math on the bitmap cursor so the next iteration reads the correct mask pair.
      bitmap_pair = (ulong *)((long)bitmap_pair + (long)(short)(bitmap_delta - 0x10));
    }
  }
  return 0;
}

