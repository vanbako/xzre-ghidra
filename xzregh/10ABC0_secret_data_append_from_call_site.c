// /home/kali/xzre-ghidra/xzregh/10ABC0_secret_data_append_from_call_site.c
// Function: secret_data_append_from_call_site @ 0x10ABC0
// Calling convention: unknown
// Prototype: undefined secret_data_append_from_call_site(void)


/*
 * AutoDoc: Validates the caller site, shifts the requested bits, and returns TRUE (or the bypass flag). It is sprinkled at sensitive call sites so the secret_data ledger captures that execution passed through trusted glue.
 */
#include "xzre_types.h"


uint secret_data_append_from_call_site
               (undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4)

{
  uint uVar1;
  undefined8 unaff_retaddr;
  
  uVar1 = secret_data_append_singleton(0,unaff_retaddr,param_1,param_2,param_3);
  return uVar1 | param_4;
}

