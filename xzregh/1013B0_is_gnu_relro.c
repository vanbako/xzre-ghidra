// /home/kali/xzre-ghidra/xzregh/1013B0_is_gnu_relro.c
// Function: is_gnu_relro @ 0x1013B0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall is_gnu_relro(Elf64_Word p_type, u32 addend)


BOOL is_gnu_relro(Elf64_Word p_type,u32 addend)

{
  return (BOOL)(p_type + 1 + addend == 0x474e553);
}

