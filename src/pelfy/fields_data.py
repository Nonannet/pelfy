elf_header_field = {
    "e_ident[EI_MAG]": {
        "32": "0x00", "64": "0x00", "size32": "4", "size64": "4", "field_name": "e_ident[EI_MAG]",
        "description": "0x7F followed by ELF(45 4c 46) in ASCII; these four bytes constitute the magic number"
    },
    "e_ident[EI_CLASS]": {
        "32": "0x04", "64": "0x04", "size32": "1", "size64": "1", "field_name": "e_ident[EI_CLASS]",
        "description": "This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively"
    },
    "e_ident[EI_DATA]": {
        "32": "0x05", "64": "0x05", "size32": "1", "size64": "1", "field_name": "e_ident[EI_DATA]",
        "description": "This byte is set to either 1 or 2 to signify little or big endianness, respectively This affects interpretation of multi-byte fields starting with offset 0x10"
    },
    "e_ident[EI_VERSION]": {
        "32": "0x06", "64": "0x06", "size32": "1", "size64": "1", "field_name": "e_ident[EI_VERSION]",
        "description": "Set to 1 for the original and current version of ELF"
    },
    "e_ident[EI_OSABI]": {
        "32": "0x07", "64": "0x07", "size32": "1", "size64": "1", "field_name": "e_ident[EI_OSABI]",
        "description": "Identifies the target operating system ABI"
    },
    "e_ident[EI_ABIVERSION]": {
        "32": "0x08", "64": "0x08", "size32": "1", "size64": "1", "field_name": "e_ident[EI_ABIVERSION]",
        "description": "Further specifies the ABI version"
    },
    "e_ident[EI_PAD]": {
        "32": "0x09", "64": "0x09", "size32": "7", "size64": "7", "field_name": "e_ident[EI_PAD]",
        "description": "Reserved padding bytes Currently unused Should be filled with zeros and ignored when read"
    },
    "e_type": {
        "32": "0x10", "64": "0x10", "size32": "2", "size64": "2", "field_name": "e_type",
        "description": "Identifies object file type"
    },
    "e_machine": {
        "32": "0x12", "64": "0x12", "size32": "2", "size64": "2", "field_name": "e_machine",
        "description": "Specifies target instruction set architecture"
    },
    "e_version": {
        "32": "0x14", "64": "0x14", "size32": "4", "size64": "4", "field_name": "e_version",
        "description": "Set to 1 for the original version of ELF"
    },
    "e_entry": {
        "32": "0x18", "64": "0x18", "size32": "4", "size64": "8", "field_name": "e_entry",
        "description": "This is the memory address of the entry point from where the process starts executing This field is either 32 or 64 bits long, depending on the format defined earlier (byte 0x04) If the file doesn't have an associated entry point, then this holds zero"
    },
    "e_phoff": {
        "32": "0x1C", "64": "0x20", "size32": "4", "size64": "8", "field_name": "e_phoff",
        "description": "Points to the start of the program header table It usually follows the file header immediately following this one, making the offset 0x34 or 0x40 for 32- and 64-bit ELF executables, respectively"
    },
    "e_shoff": {
        "32": "0x20", "64": "0x28", "size32": "4", "size64": "8", "field_name": "e_shoff",
        "description": "Points to the start of the section header table"
    },
    "e_flags": {
        "32": "0x24", "64": "0x30", "size32": "4", "size64": "4", "field_name": "e_flags",
        "description": "Interpretation of this field depends on the target architecture"
    },
    "e_ehsize": {
        "32": "0x28", "64": "0x34", "size32": "2", "size64": "2", "field_name": "e_ehsize",
        "description": "Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format"
    },
    "e_phentsize": {
        "32": "0x2A", "64": "0x36", "size32": "2", "size64": "2", "field_name": "e_phentsize",
        "description": "Contains the size of a program header table entry As explained below, this will typically be 0x20 (32 bit) or 0x38 (64 bit)"
    },
    "e_phnum": {
        "32": "0x2C", "64": "0x38", "size32": "2", "size64": "2", "field_name": "e_phnum",
        "description": "Contains the number of entries in the program header table"
    },
    "e_shentsize": {
        "32": "0x2E", "64": "0x3A", "size32": "2", "size64": "2", "field_name": "e_shentsize",
        "description": "Contains the size of a section header table entry As explained below, this will typically be 0x28 (32 bit) or 0x40 (64 bit)"
    },
    "e_shnum": {
        "32": "0x30", "64": "0x3C", "size32": "2", "size64": "2", "field_name": "e_shnum",
        "description": "Contains the number of entries in the section header table"
    },
    "e_shstrndx": {
        "32": "0x32", "64": "0x3E", "size32": "2", "size64": "2", "field_name": "e_shstrndx",
        "description": "Contains index of the section header table entry that contains the section names"
    }
}

section_header = {
    "sh_name": {
        "32": "0x00", "64": "0x00", "size32": "4", "size64": "4", "field_name": "sh_name",
        "description": "An offset to a string in the .shstrtab section that represents the name of this section."
    },
    "sh_type": {
        "32": "0x04", "64": "0x04", "size32": "4", "size64": "4", "field_name": "sh_type",
        "description": "Identifies the type of this header."
    },
    "sh_flags": {
        "32": "0x08", "64": "0x08", "size32": "4", "size64": "8", "field_name": "sh_flags",
        "description": "Identifies the attributes of the section."
    },
    "sh_addr": {
        "32": "0x0C", "64": "0x10", "size32": "4", "size64": "8", "field_name": "sh_addr",
        "description": "Virtual address of the section in memory, for sections that are loaded."
    },
    "sh_offset": {
        "32": "0x10", "64": "0x18", "size32": "4", "size64": "8", "field_name": "sh_offset",
        "description": "Offset of the section in the file image."
    },
    "sh_size": {
        "32": "0x14", "64": "0x20", "size32": "4", "size64": "8", "field_name": "sh_size",
        "description": "Size in bytes of the section in the file image. May be 0."
    },
    "sh_link": {
        "32": "0x18", "64": "0x28", "size32": "4", "size64": "4", "field_name": "sh_link",
        "description": "Contains the section index of an associated section. This field is used for several purposes, depending on the type of section."
    },
    "sh_info": {
        "32": "0x1C", "64": "0x2C", "size32": "4", "size64": "4", "field_name": "sh_info",
        "description": "Contains extra information about the section. This field is used for several purposes, depending on the type of section."
    },
    "sh_addralign": {
        "32": "0x20", "64": "0x30", "size32": "4", "size64": "8", "field_name": "sh_addralign",
        "description": "Contains the required alignment of the section. This field must be a power of two."
    },
    "sh_entsize": {
        "32": "0x24", "64": "0x38", "size32": "4", "size64": "8", "field_name": "sh_entsize",
        "description": "Contains the size, in bytes, of each entry, for sections that contain fixed-size entries. Otherwise, this field contains zero."
    }
}

section_header_types = {
    0: {"value": "0x0", "name": "SHT_NULL", "description": "Section header table entry unused"},
    1: {"value": "0x1", "name": "SHT_PROGBITS", "description": "Program data"},
    2: {"value": "0x2", "name": "SHT_SYMTAB", "description": "Symbol table"},
    3: {"value": "0x3", "name": "SHT_STRTAB", "description": "String table"},
    4: {"value": "0x4", "name": "SHT_RELA", "description": "Relocation entries with addends"},
    5: {"value": "0x5", "name": "SHT_HASH", "description": "Symbol hash table"},
    6: {"value": "0x6", "name": "SHT_DYNAMIC", "description": "Dynamic linking information"},
    7: {"value": "0x7", "name": "SHT_NOTE", "description": "Notes"},
    8: {"value": "0x8", "name": "SHT_NOBITS", "description": "Program space with no data (bss)"},
    9: {"value": "0x9", "name": "SHT_REL", "description": "Relocation entries, no addends"},
    10: {"value": "0x0A", "name": "SHT_SHLIB", "description": "Reserved"},
    11: {"value": "0x0B", "name": "SHT_DYNSYM", "description": "Dynamic linker symbol table"},
    14: {"value": "0x0E", "name": "SHT_INIT_ARRAY", "description": "Array of constructors"},
    15: {"value": "0x0F", "name": "SHT_FINI_ARRAY", "description": "Array of destructors"},
    16: {"value": "0x10", "name": "SHT_PREINIT_ARRAY", "description": "Array of pre-constructors"},
    17: {"value": "0x11", "name": "SHT_GROUP", "description": "Section group"},
    18: {"value": "0x12", "name": "SHT_SYMTAB_SHNDX", "description": "Extended section indices"},
    19: {"value": "0x13", "name": "SHT_NUM", "description": "Number of defined types."},
    1610612736: {"value": "0x60000000", "name": "SHT_LOOS", "description": "Start OS-specific."},
    1879048182: {"value": "0x6ffffff6", "name": "SHT_GNU_HASH", "description": "GNU-style hash table."}
}

st_info_values = {
    0: {"name": "STT_NOTYPE", "description": "Type is unspecified"},
    1: {"name": "STT_OBJECT", "description": "Data object (variable, array, etc.)"},
    2: {"name": "STT_FUNC", "description": "Function or executable code"},
    3: {"name": "STT_SECTION", "description": "Associated with a section"},
    4: {"name": "STT_FILE", "description": "Represents a file name"},
    5: {"name": "STT_COMMON", "description": "Common data object (uninit. storage)"},
    6: {"name": "STT_TLS", "description": "Thread-local storage (TLS)"},
    7: {"name": "STT_NUM", "description": "Number of defined types"},
    10: {"name": "STT_GNU_IFUNC", "description": "Indirect function (GNU extension)"},
    12: {"name": "STT_HIPROC", "description": "Processor-specific symbol type"},
}

stb_values = {
    0: {"name": "STB_LOCAL", "description": "Local, not visible outside the object file"},
    1: {"name": "STB_GLOBAL", "description": "Global, visible to all object files"},
    2: {"name": "STB_WEAK", "description": "Weak, like global but with lower precedence"},
    10: {"name": "STB_GNU_UNIQUE", "description": "Unique in the entire process (GNU extension)"},
    12: {"name": "STB_HIPROC", "description": "Processor-specific binding type"},
}

relocation_table_types = {
    0: {"name": "R_X86_64_NONE", "description": "No relocation"},
    1: {"name": "R_X86_64_64", "description": "Direct 64-bit relocation"},
    2: {"name": "R_X86_64_PC32", "description": "32-bit PC-relative relocation"},
    3: {"name": "R_X86_64_GOT32", "description": "32-bit Global Offset Table (GOT) entry"},
    4: {"name": "R_X86_64_PLT32", "description": "32-bit Procedure Linkage Table (PLT) entry"},
    5: {"name": "R_X86_64_COPY", "description": "Copy data from shared object"},
    6: {"name": "R_X86_64_GLOB_DAT", "description": "Set GOT entry to the address of a symbol"},
    7: {"name": "R_X86_64_JUMP_SLOT", "description": "Set GOT entry to the address of a function (dynamic linking)"},
    8: {"name": "R_X86_64_RELATIVE", "description": "Adjust relative to the load address"},
    9: {"name": "R_X86_64_GOTPCREL", "description": "PC-relative address for GOT entry"},
    10: {"name": "R_X86_64_32", "description": "32-bit absolute relocation"},
    11: {"name": "R_X86_64_32S", "description": "32-bit signed absolute relocation"},
    12: {"name": "R_X86_64_16", "description": "16-bit absolute relocation"},
    13: {"name": "R_X86_64_8", "description": "8-bit absolute relocation"}
}

e_machine_dict = {
    0x0001: {"name": "EM_386", "description": "Intel 80386 (x86)"},
    0x0002: {"name": "EM_MIPS", "description": "MIPS (32-bit)"},
    0x0003: {"name": "EM_SPARC", "description": "SPARC (32-bit)"},
    0x0008: {"name": "EM_MIPS_RS3_LE", "description": "MIPS (Big Endian)"},
    0x0014: {"name": "EM_ARM", "description": "ARM (32-bit)"},
    0x0028: {"name": "EM_PPC", "description": "PowerPC (32-bit)"},
    0x0032: {"name": "EM_S390", "description": "IBM S/390"},
    0x003E: {"name": "EM_X86_64", "description": "x86-64 (64-bit)"},
    0x00F3: {"name": "EM_AARCH64", "description": "ARM64 (64-bit)"},
    0x0103: {"name": "EM_RISCV", "description": "RISC-V (32/64-bit)"}
}
