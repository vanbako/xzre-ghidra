// /home/kali/xzre-ghidra/xzregh/101B00_elf_symbol_get_addr.c
// Function: elf_symbol_get_addr @ 0x101B00
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_symbol_get_addr(elf_info_t * elf_info, EncodedStringId encoded_string_id)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Looks up an ELF symbol from a parsed ELF, and returns its memory address
 *
 *   @param elf_info the parsed ELF context
 *   @param encoded_string_id string ID of the symbol name
 *   @return void* the address of the symbol
 *
 * Upstream implementation excerpt (xzre/xzre_code/elf_symbol_get_addr.c):
 *     void *elf_symbol_get_addr(elf_info_t *elf_info, EncodedStringId encoded_string_id){
 *     	Elf64_Sym *sym = elf_symbol_get(elf_info, encoded_string_id, 0);
 *     	if(!sym){
 *     		return NULL;
 *     	}
 *     
 *     	if(sym->st_value && sym->st_shndx){
 *     		return (void *)PTRADD(elf_info->elfbase, sym->st_value);
 *     	} else {
 *     		return NULL;
 *     	}
 *     }
 */

void * elf_symbol_get_addr(elf_info_t *elf_info,EncodedStringId encoded_string_id)

{
  Elf64_Sym *sym;
  
  sym = (Elf64_Sym *)elf_symbol_get(elf_info,encoded_string_id,0);
  if (sym != (Elf64_Sym *)0x0) {
    if ((sym->st_value == 0) || (sym->st_shndx == 0)) {
      sym = (Elf64_Sym *)0x0;
    }
    else {
      sym = (Elf64_Sym *)(elf_info->elfbase->e_ident + sym->st_value);
    }
  }
  return sym;
}

