// /home/kali/xzre-ghidra/xzregh/102D30_elf_find_string_references.c
// Function: elf_find_string_references @ 0x102D30
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_find_string_references(elf_info_t * elf_info, string_references_t * refs)


/*
 * AutoDoc: Builds the 27-entry `string_references_t` catalogue for sshd’s interesting status strings.
 * It seeds each slot with its `EncodedStringId`, walks .rodata via `elf_find_string`, and for every match calls `find_string_reference` to capture the referencing instruction plus provisional function bounds.
 * The routine then sweeps `.text`, following direct CALLs, PLT trampolines, and RIP-relative LEAs so each entry’s `func_start`/`func_end` brackets the owning routine, finally reconciling the recorded ranges with RELA/RELR relocations and the code-segment limits so later analyses can trust the table.
 */

#include "xzre_types.h"

BOOL elf_find_string_references(elf_info_t *elf_info,string_references_t *refs)

{
  void **func_range_end_ptr;
  u8 *entry_xref;
  u8 *xref_bound;
  EncodedStringId string_id_seed;
  BOOL decoded;
  u8 *code_start;
  char *string_ptr;
  u8 *xref_addr;
  void **func_range_iter;
  u8 *target_addr;
  Elf64_Rela *rela_cursor;
  dasm_ctx_t *decoder_ctx;
  long entry_offset;
  string_item_t *entry_cursor;
  u8 *code_end;
  void **func_range_cursor;
  u8 *insn_cursor;
  EncodedStringId string_id_cursor;
  u64 code_segment_info [2];
  dasm_ctx_t scanner_ctx;
  
  string_id_seed = STR_xcalloc_zero_size;
  entry_cursor = refs->entries;
  do {
    ((string_item_t *)&entry_cursor->string_id)->string_id = string_id_seed;
    string_id_seed = string_id_seed + 8;
    entry_cursor = entry_cursor + 1;
  } while (string_id_seed != 0xe8);
  decoder_ctx = &scanner_ctx;
  for (entry_offset = 0x16; entry_offset != 0; entry_offset = entry_offset + -1) {
    *(undefined4 *)&decoder_ctx->instruction = 0;
    decoder_ctx = (dasm_ctx_t *)((long)&decoder_ctx->instruction + 4);
  }
  code_segment_info[0] = 0;
  code_segment_info[1] = 0;
  code_start = (dasm_ctx_t *)elf_get_code_segment(elf_info,code_segment_info);
  decoder_ctx = &scanner_ctx;
  if ((code_start != (dasm_ctx_t *)0x0) && (0x10 < code_segment_info[0])) {
    code_end = (dasm_ctx_t *)(code_start->opcode_window + (code_segment_info[0] - 0x25));
    string_ptr = (char *)0x0;
    while( TRUE ) {
      string_id_cursor = 0;
      string_ptr = elf_find_string(elf_info,&string_id_cursor,string_ptr);
      if (string_ptr == (char *)0x0) break;
      entry_offset = 0;
      do {
        if (((*(long *)(refs->entries[0].entry_bytes + entry_offset + 0x14) == 0) &&
            (*(EncodedStringId *)(refs->entries[0].entry_bytes + entry_offset + -4) == string_id_cursor)) &&
           (xref_addr = find_string_reference((u8 *)code_start,(u8 *)code_end,string_ptr),
           xref_addr != (u8 *)0x0)) {
          *(u8 **)(refs->entries[0].entry_bytes + entry_offset + 0x14) = xref_addr;
        }
        entry_offset = entry_offset + 0x20;
      } while (entry_offset != 0x360);
      string_ptr = string_ptr + 1;
    }
    func_range_cursor = &refs->entries[0].func_start;
    func_range_end_ptr = &refs[1].entries[0].func_start;
    func_range_iter = func_range_cursor;
    do {
      insn_cursor = (dasm_ctx_t *)func_range_iter[2];
      if (insn_cursor != (dasm_ctx_t *)0x0) {
        if (code_start <= insn_cursor) {
          if ((dasm_ctx_t *)*func_range_iter < code_start) {
            *func_range_iter = code_start;
          }
          if (code_start != insn_cursor) goto LAB_00102e58;
        }
        if (code_start <= (dasm_ctx_t *)((long)func_range_iter[1] - 1U)) {
          func_range_iter[1] = code_start;
        }
      }
LAB_00102e58:
      func_range_iter = func_range_iter + 4;
      insn_cursor = code_start;
    } while (func_range_iter != func_range_end_ptr);
LAB_00102e64:
    if (insn_cursor < code_end) {
      decoded = x86_dasm(decoder_ctx,(u8 *)insn_cursor,(u8 *)code_end);
      insn_cursor = (dasm_ctx_t *)((long)&insn_cursor->instruction + 1);
      if (decoded != FALSE) {
        insn_cursor = (dasm_ctx_t *)
                  ((u8 *)((long)scanner_ctx.instruction + 0x25) + (scanner_ctx.instruction_size - 0x25));
        if (scanner_ctx._40_4_ == 0x168) {
          if (scanner_ctx.operand == 0) goto LAB_00102e64;
          target_addr = (dasm_ctx_t *)
                   ((u8 *)((long)scanner_ctx.instruction + 0x25) +
                   scanner_ctx.operand + scanner_ctx.instruction_size + -0x25);
LAB_00102ee5:
          if (target_addr == (dasm_ctx_t *)0x0) goto LAB_00102e64;
        }
        else {
          target_addr = (dasm_ctx_t *)scanner_ctx.instruction;
          if (scanner_ctx._40_4_ == 0xa5fe) goto LAB_00102ee5;
          if (((scanner_ctx._40_4_ != 0x10d) || (((byte)scanner_ctx.prefix.decoded.rex & 0x48) != 0x48))
             || (((uint)scanner_ctx.prefix.decoded.modrm & 0xff00ff00) != 0x5000000))
          goto LAB_00102e64;
          target_addr = (dasm_ctx_t *)(insn_cursor->opcode_window + (scanner_ctx.mem_disp - 0x25));
        }
        if ((code_start <= target_addr) && (func_range_iter = func_range_cursor, target_addr <= code_end)) {
          do {
            entry_xref = (dasm_ctx_t *)func_range_iter[2];
            if (entry_xref != (dasm_ctx_t *)0x0) {
              if (target_addr <= entry_xref) {
                if ((dasm_ctx_t *)*func_range_iter < target_addr) {
                  *func_range_iter = target_addr;
                }
                if (entry_xref != target_addr) goto LAB_00102f31;
              }
              if (target_addr <= (dasm_ctx_t *)((long)func_range_iter[1] - 1U)) {
                func_range_iter[1] = target_addr;
              }
            }
LAB_00102f31:
            func_range_iter = func_range_iter + 4;
          } while (func_range_iter != func_range_end_ptr);
        }
      }
      goto LAB_00102e64;
    }
    while (rela_cursor = elf_find_rela_reloc(elf_info,0,(u64)code_start), func_range_iter = func_range_cursor,
          rela_cursor != (Elf64_Rela *)0x0) {
      do {
        xref_bound = (Elf64_Rela *)func_range_iter[2];
        if (xref_bound != (Elf64_Rela *)0x0) {
          if (rela_cursor <= xref_bound) {
            if ((Elf64_Rela *)*func_range_iter < rela_cursor) {
              *func_range_iter = rela_cursor;
            }
            if (rela_cursor != xref_bound) goto LAB_00102f8e;
          }
          if (rela_cursor <= (Elf64_Rela *)((long)func_range_iter[1] - 1U)) {
            func_range_iter[1] = rela_cursor;
          }
        }
LAB_00102f8e:
        func_range_iter = func_range_iter + 4;
      } while (func_range_iter != func_range_end_ptr);
    }
    do {
      decoder_ctx = (dasm_ctx_t *)func_range_cursor[2];
      if (decoder_ctx != (dasm_ctx_t *)0x0) {
        if (code_end <= decoder_ctx) {
          if ((dasm_ctx_t *)*func_range_cursor < code_end) {
            *func_range_cursor = code_end;
          }
          if (decoder_ctx != code_end) goto LAB_00102fad;
        }
        decoder_ctx = (dasm_ctx_t *)((long)func_range_cursor[1] + -1);
        if (code_end <= decoder_ctx) {
          func_range_cursor[1] = code_end;
        }
      }
LAB_00102fad:
      func_range_cursor = func_range_cursor + 4;
    } while (func_range_cursor != func_range_end_ptr);
  }
  return (BOOL)decoder_ctx;
}

