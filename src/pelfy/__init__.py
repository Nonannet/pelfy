"""
pelfy is an ELF parser written in python.

Example usage:
    >>> import pelfy
    >>> elf = pelfy.open_elf_file('tests/obj/test-c-riscv64-linux-gnu-gcc-12-O3.o')
    >>> elf.sections
"""

from ._main import open_elf_file, elf_symbol, elf_section, \
    elf_relocation, elf_list, section_list, symbol_list, relocation_list, elf_file

__all__ = [
    'open_elf_file', 'elf_symbol', 'elf_section', 'elf_relocation',
    'elf_list', 'section_list', 'symbol_list', 'relocation_list', 'elf_file']
