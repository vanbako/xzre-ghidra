// Standalone decoder for the obfuscated string trie embedded in
// liblzma_la-crc64-fast.o. It walks the trie/mask blobs exported to
// ghidra_scripts/generated/string_rodata.c and prints every reachable
// plaintext string alongside its EncodedStringId.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern const uint32_t string_action_data[1304];
extern const uint64_t string_mask_data[238];

static uint32_t count_bits(uint64_t x) {
  uint32_t cnt = 0;
  for (; x != 0; x &= (x - 1)) {
    cnt++;
  }
  return cnt;
}

typedef struct {
  int trie_off;
  int bitmap_off;
  int len;
  char buf[0x2d];
} State;

int main(void) {
  // Derived from get_string_id absolute addresses:
  //   string_action_data starts at 0x10af00, trie cursor begins at 0x10c2a8.
  //   string_mask_data   starts at 0x10c360, bitmap row is _Lcrc64_clmul_1 + 0x760.
  const int start_trie = 0x10c2a8 - 0x10af00; // 0x13a8
  const int start_bitmap = 0x10cac0 - 0x10c360; // 0x760

  State stack[8192];
  int sp = 0;
  memset(stack, 0, sizeof(stack));
  stack[sp++] = (State){start_trie, start_bitmap, 0, {0}};

  while (sp > 0) {
    State st = stack[--sp];
    if (st.len >= 0x2c) continue;
    if (st.bitmap_off < 0 || st.bitmap_off + 16 > (int)sizeof(string_mask_data)) continue;
    if (st.trie_off < 0 || st.trie_off + 4 > (int)sizeof(string_action_data)) continue;

    const uint64_t *bitmap_row = (const uint64_t *)((const uint8_t *)string_mask_data + st.bitmap_off);
    uint64_t row0 = bitmap_row[0];
    uint64_t row1 = bitmap_row[1];

    for (int ch = 32; ch < 127; ch++) { // printable ASCII
      uint64_t word = (ch < 64) ? row0 : row1;
      int bit = ch & 63;
      if (((word >> bit) & 1) == 0) continue;

      uint32_t bitmap_rank = 0;
      if (ch >= 64) bitmap_rank = count_bits(row0);
      uint64_t lower = (bit == 0) ? 0 : (((uint64_t)1 << bit) - 1);
      bitmap_rank += count_bits(word & lower);

      int entry_off = st.trie_off + (int)bitmap_rank * 4;
      if (entry_off + 4 > (int)sizeof(string_action_data)) continue;
      const uint16_t *node = (const uint16_t *)(((const uint8_t *)string_action_data) + entry_off);
      int node_flags = node[0];
      int child_offset = node[1];

      char next_buf[0x2d];
      memcpy(next_buf, st.buf, st.len);
      next_buf[st.len] = (char)ch;
      next_buf[st.len + 1] = '\0';

      if (node_flags & 4) {
        int enc_id = child_offset;
        printf("EncodedStringId=%#04x | %s\n", enc_id, next_buf);
        continue;
      }

      if ((node_flags & 2) == 0) {
        child_offset = -child_offset;
      } else {
        node_flags &= ~2;
      }
      int child_flags = node_flags & 0xfffe;
      if ((node_flags & 1) == 0) {
        child_flags = -node_flags;
      }

      int next_trie = st.trie_off + (int16_t)(child_offset - 4);
      int next_bitmap = st.bitmap_off + (int16_t)(child_flags - 0x10);

      if (sp < (int)(sizeof(stack) / sizeof(stack[0]))) {
        State nxt;
        memset(&nxt, 0, sizeof(nxt));
        nxt.trie_off = next_trie;
        nxt.bitmap_off = next_bitmap;
        nxt.len = st.len + 1;
        memcpy(nxt.buf, next_buf, nxt.len + 1);
        stack[sp++] = nxt;
      }
    }
  }
  return 0;
}
