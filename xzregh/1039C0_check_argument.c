// /home/kali/xzre-ghidra/xzregh/1039C0_check_argument.c
// Function: check_argument @ 0x1039C0
// Calling convention: unknown
// Prototype: undefined check_argument(void)


/*
 * AutoDoc: Walks a dash-prefixed argv entry two bytes at a time, mirroring each character so it can flag
 * both upper- and lower-case variants of '-d', '-D', '-E', '-Q', or any option that includes '='
 * or '/'. It returns the offending pointer so `process_is_sshd` can treat those switches as a
 * hard stop and avoid touching sshd instances launched in debug or non-daemon modes.
 */
#include "xzre_types.h"


ushort * check_argument(char param_1,ushort *param_2)

{
  ushort uVar1;
  ushort uVar2;
  ushort uVar3;
  
  if (param_1 == '-') {
    while( TRUE ) {
      uVar1 = *param_2;
      uVar3 = uVar1 << 8;
      uVar2 = uVar1 & 0xff00;
      if ((uVar2 == 0x6400) || (uVar3 == 0x6400)) break;
      if ((((uVar1 & 0xdf00) == 0) ||
          (((uVar2 == 0x900 || (uVar2 == 0x3d00)) || ((uVar3 & 0xdf00) == 0)))) ||
         ((uVar3 == 0x3d00 || (uVar3 == 0x900)))) goto LAB_00103a17;
      param_2 = param_2 + 1;
    }
  }
  else {
LAB_00103a17:
    param_2 = (ushort *)0x0;
  }
  return param_2;
}

