// /home/kali/xzre-ghidra/xzregh/1039C0_check_argument.c
// Function: check_argument @ 0x1039C0
// Calling convention: __stdcall
// Prototype: char * __stdcall check_argument(char arg_first_char, char * arg_name)


/*
 * AutoDoc: Generated from reverse engineering.
 *
 * Summary:
 *   Examines a command-line argument that began with '-' and returns the pointer to the character that matched '-d' style options, otherwise returns NULL.
 *
 * Notes:
 *   - Advances through the string two bytes at a time when the first character is '-', guarding against malformed UTF-16 style input.
 *   - Stops early when it encounters '=' or NUL terminators, treating those forms as unsupported switches.
 */

char * check_argument(char arg_first_char,char *arg_name)

{
  ushort uVar1;
  ushort uVar2;
  ushort uVar3;
  
  if (arg_first_char == '-') {
    while( true ) {
      uVar1 = *(ushort *)arg_name;
      uVar3 = uVar1 << 8;
      uVar2 = uVar1 & 0xff00;
      if ((uVar2 == 0x6400) || (uVar3 == 0x6400)) break;
      if ((((uVar1 & 0xdf00) == 0) ||
          (((uVar2 == 0x900 || (uVar2 == 0x3d00)) || ((uVar3 & 0xdf00) == 0)))) ||
         ((uVar3 == 0x3d00 || (uVar3 == 0x900)))) goto LAB_00103a17;
      arg_name = (char *)((long)arg_name + 2);
    }
  }
  else {
LAB_00103a17:
    arg_name = (char *)0x0;
  }
  return arg_name;
}

