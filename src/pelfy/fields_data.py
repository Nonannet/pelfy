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

e_machine_dict = {
    0: ("EM_NONE", "No machine"),
    1: ("EM_M32", "AT&T WE 32100"),
    2: ("EM_SPARC", "SUN SPARC"),
    3: ("EM_386", "Intel 80386"),
    4: ("EM_68K", "Motorola m68k family"),
    5: ("EM_88K", "Motorola m88k family"),
    6: ("EM_IAMCU", "Intel MCU"),
    7: ("EM_860", "Intel 80860"),
    8: ("EM_MIPS", "MIPS R3000 big-endian"),
    9: ("EM_S370", "IBM System/370"),
    10: ("EM_MIPS_RS3_LE", "MIPS R3000 little-endian"),
    15: ("EM_PARISC", "HPPA"),
    17: ("EM_VPP500", "Fujitsu VPP500"),
    18: ("EM_SPARC32PLUS", "Sun's v8plus"),
    19: ("EM_960", "Intel 80960"),
    20: ("EM_PPC", "PowerPC"),
    21: ("EM_PPC64", "PowerPC 64-bit"),
    22: ("EM_S390", "IBM S390"),
    23: ("EM_SPU", "IBM SPU/SPC"),
    36: ("EM_V800", "NEC V800 series"),
    37: ("EM_FR20", "Fujitsu FR20"),
    38: ("EM_RH32", "TRW RH-32"),
    39: ("EM_RCE", "Motorola RCE"),
    40: ("EM_ARM", "ARM"),
    41: ("EM_FAKE_ALPHA", "Digital Alpha"),
    42: ("EM_SH", "Hitachi SH"),
    43: ("EM_SPARCV9", "SPARC v9 64-bit"),
    44: ("EM_TRICORE", "Siemens Tricore"),
    45: ("EM_ARC", "Argonaut RISC Core"),
    46: ("EM_H8_300", "Hitachi H8/300"),
    47: ("EM_H8_300H", "Hitachi H8/300H"),
    48: ("EM_H8S", "Hitachi H8S"),
    49: ("EM_H8_500", "Hitachi H8/500"),
    50: ("EM_IA_64", "Intel Merced"),
    51: ("EM_MIPS_X", "Stanford MIPS-X"),
    52: ("EM_COLDFIRE", "Motorola Coldfire"),
    53: ("EM_68HC12", "Motorola M68HC12"),
    54: ("EM_MMA", "Fujitsu MMA Multimedia Accelerator"),
    55: ("EM_PCP", "Siemens PCP"),
    56: ("EM_NCPU", "Sony nCPU embedded RISC"),
    57: ("EM_NDR1", "Denso NDR1 microprocessor"),
    58: ("EM_STARCORE", "Motorola Start*Core processor"),
    59: ("EM_ME16", "Toyota ME16 processor"),
    60: ("EM_ST100", "STMicroelectronic ST100 processor"),
    61: ("EM_TINYJ", "Advanced Logic Corp. Tinyj emb.fam"),
    62: ("EM_X86_64", "AMD x86-64 architecture"),
    63: ("EM_PDSP", "Sony DSP Processor"),
    64: ("EM_PDP10", "Digital PDP-10"),
    65: ("EM_PDP11", "Digital PDP-11"),
    66: ("EM_FX66", "Siemens FX66 microcontroller"),
    67: ("EM_ST9PLUS", "STMicroelectronics ST9+ 8/16 mc"),
    68: ("EM_ST7", "STMicroelectronics ST7 8-bit mc"),
    75: ("EM_VAX", "Digital VAX"),
    76: ("EM_CRIS", "Axis Communications 32-bit emb.proc"),
    80: ("EM_MMIX", "Donald Knuth's educational 64-bit proc"),
    83: ("EM_AVR", "Atmel AVR 8-bit microcontroller"),
    87: ("EM_V850", "NEC v850"),
    88: ("EM_M32R", "Mitsubishi M32R"),
    89: ("EM_MN10300", "Matsushita MN10300"),
    90: ("EM_MN10200", "Matsushita MN10200"),
    91: ("EM_PJ", "picoJava"),
    92: ("EM_OPENRISC", "OpenRISC 32-bit embedded processor"),
    94: ("EM_XTENSA", "Tensilica Xtensa Architecture"),
    95: ("EM_VIDEOCORE", "Alphamosaic VideoCore"),
    96: ("EM_TMM_GPP", "Thompson Multimedia General Purpose Proc"),
    97: ("EM_NS32K", "National Semi. 32000"),
    98: ("EM_TPC", "Tenor Network TPC"),
    99: ("EM_SNP1K", "Trebia SNP 1000"),
    100: ("EM_ST200", "STMicroelectronics ST200"),
    101: ("EM_IP2K", "Ubicom IP2xxx"),
    102: ("EM_MAX", "MAX processor"),
    103: ("EM_CR", "National Semi. CompactRISC"),
    104: ("EM_F2MC16", "Fujitsu F2MC16"),
    105: ("EM_MSP430", "Texas Instruments msp430"),
    106: ("EM_BLACKFIN", "Analog Devices Blackfin DSP"),
    107: ("EM_SE_C33", "Seiko Epson S1C33 family"),
    108: ("EM_SEP", "Sharp embedded microprocessor"),
    109: ("EM_ARCA", "Arca RISC"),
    110: ("EM_UNICORE", "PKU-Unity & MPRC Peking Uni. mc series"),
    111: ("EM_EXCESS", "eXcess configurable cpu"),
    112: ("EM_DXP", "Icera Semi. Deep Execution Processor"),
    113: ("EM_ALTERA_NIOS2", "Altera Nios II"),
    114: ("EM_CRX", "National Semi. CompactRISC CRX"),
    115: ("EM_XGATE", "Motorola XGATE"),
    116: ("EM_C166", "Infineon C16x/XC16x"),
    117: ("EM_M16C", "Renesas M16C"),
    118: ("EM_DSPIC30F", "Microchip Technology dsPIC30F"),
    119: ("EM_CE", "Freescale Communication Engine RISC"),
    120: ("EM_M32C", "Renesas M32C"),
    131: ("EM_TSK3000", "Altium TSK3000"),
    132: ("EM_RS08", "Freescale RS08"),
    133: ("EM_SHARC", "Analog Devices SHARC family"),
    134: ("EM_ECOG2", "Cyan Technology eCOG2"),
    135: ("EM_SCORE7", "Sunplus S+core7 RISC"),
    136: ("EM_DSP24", "New Japan Radio (NJR) 24-bit DSP"),
    137: ("EM_VIDEOCORE3", "Broadcom VideoCore III"),
    138: ("EM_LATTICEMICO32", "RISC for Lattice FPGA"),
    139: ("EM_SE_C17", "Seiko Epson C17"),
    140: ("EM_TI_C6000", "Texas Instruments TMS320C6000 DSP"),
    141: ("EM_TI_C2000", "Texas Instruments TMS320C2000 DSP"),
    142: ("EM_TI_C5500", "Texas Instruments TMS320C55x DSP"),
    143: ("EM_TI_ARP32", "Texas Instruments App. Specific RISC"),
    144: ("EM_TI_PRU", "Texas Instruments Prog. Realtime Unit"),
    160: ("EM_MMDSP_PLUS", "STMicroelectronics 64bit VLIW DSP"),
    161: ("EM_CYPRESS_M8C", "Cypress M8C"),
    162: ("EM_R32C", "Renesas R32C"),
    163: ("EM_TRIMEDIA", "NXP Semi. TriMedia"),
    164: ("EM_QDSP6", "QUALCOMM DSP6"),
    165: ("EM_8051", "Intel 8051 and variants"),
    166: ("EM_STXP7X", "STMicroelectronics STxP7x"),
    167: ("EM_NDS32", "Andes Tech. compact code emb. RISC"),
    168: ("EM_ECOG1X", "Cyan Technology eCOG1X"),
    169: ("EM_MAXQ30", "Dallas Semi. MAXQ30 mc"),
    170: ("EM_XIMO16", "New Japan Radio (NJR) 16-bit DSP"),
    171: ("EM_MANIK", "M2000 Reconfigurable RISC"),
    172: ("EM_CRAYNV2", "Cray NV2 vector architecture"),
    173: ("EM_RX", "Renesas RX"),
    174: ("EM_METAG", "Imagination Tech. META"),
    175: ("EM_MCST_ELBRUS", "MCST Elbrus"),
    176: ("EM_ECOG16", "Cyan Technology eCOG16"),
    177: ("EM_CR16", "National Semi. CompactRISC CR16"),
    178: ("EM_ETPU", "Freescale Extended Time Processing Unit"),
    179: ("EM_SLE9X", "Infineon Tech. SLE9X"),
    180: ("EM_L10M", "Intel L10M"),
    181: ("EM_K10M", "Intel K10M"),
    183: ("EM_AARCH64", "ARM AARCH64"),
    185: ("EM_AVR32", "Amtel 32-bit microprocessor"),
    186: ("EM_STM8", "STMicroelectronics STM8"),
    187: ("EM_TILE64", "Tileta TILE64"),
    188: ("EM_TILEPRO", "Tilera TILEPro"),
    189: ("EM_MICROBLAZE", "Xilinx MicroBlaze"),
    190: ("EM_CUDA", "NVIDIA CUDA"),
    191: ("EM_TILEGX", "Tilera TILE-Gx"),
    192: ("EM_CLOUDSHIELD", "CloudShield"),
    193: ("EM_COREA_1ST", "KIPO-KAIST Core-A 1st gen."),
    194: ("EM_COREA_2ND", "KIPO-KAIST Core-A 2nd gen."),
    195: ("EM_ARC_COMPACT2", "Synopsys ARCompact V2"),
    196: ("EM_OPEN8", "Open8 RISC"),
    197: ("EM_RL78", "Renesas RL78"),
    198: ("EM_VIDEOCORE5", "Broadcom VideoCore V"),
    199: ("EM_78KOR", "Renesas 78KOR"),
    200: ("EM_56800EX", "Freescale 56800EX DSC"),
    201: ("EM_BA1", "Beyond BA1"),
    202: ("EM_BA2", "Beyond BA2"),
    203: ("EM_XCORE", "XMOS xCORE"),
    204: ("EM_MCHP_PIC", "Microchip 8-bit PIC(r)"),
    210: ("EM_KM32", "KM211 KM32"),
    211: ("EM_KMX32", "KM211 KMX32"),
    212: ("EM_EMX16", "KM211 KMX16"),
    213: ("EM_EMX8", "KM211 KMX8"),
    214: ("EM_KVARC", "KM211 KVARC"),
    215: ("EM_CDP", "Paneve CDP"),
    216: ("EM_COGE", "Cognitive Smart Memory Processor"),
    217: ("EM_COOL", "Bluechip CoolEngine"),
    218: ("EM_NORC", "Nanoradio Optimized RISC"),
    219: ("EM_CSR_KALIMBA", "CSR Kalimba"),
    220: ("EM_Z80", "Zilog Z80"),
    221: ("EM_VISIUM", "Controls and Data Services VISIUMcore"),
    222: ("EM_FT32", "FTDI Chip FT32"),
    223: ("EM_MOXIE", "Moxie processor"),
    224: ("EM_AMDGPU", "AMD GPU"),
    243: ("EM_RISCV", "RISC-V"),
    247: ("EM_BPF", "Linux BPF -- in-kernel virtual machine"),
    252: ("EM_CSKY", "C-SKY")
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
    0: ("SHT_NULL", "Section header table entry unused"),
    1: ("SHT_PROGBITS", "Program data"),
    2: ("SHT_SYMTAB", "Symbol table"),
    3: ("SHT_STRTAB", "String table"),
    4: ("SHT_RELA", "Relocation entries with addends"),
    5: ("SHT_HASH", "Symbol hash table"),
    6: ("SHT_DYNAMIC", "Dynamic linking information"),
    7: ("SHT_NOTE", "Notes"),
    8: ("SHT_NOBITS", "Program space with no data (bss)"),
    9: ("SHT_REL", "Relocation entries, no addends"),
    10: ("SHT_SHLIB", "Reserved"),
    11: ("SHT_DYNSYM", "Dynamic linker symbol table"),
    14: ("SHT_INIT_ARRAY", "Array of constructors"),
    15: ("SHT_FINI_ARRAY", "Array of destructors"),
    16: ("SHT_PREINIT_ARRAY", "Array of pre-constructors"),
    17: ("SHT_GROUP", "Section group"),
    18: ("SHT_SYMTAB_SHNDX", "Extended section indices"),
    19: ("SHT_NUM", "Number of defined types.")
}

section_header_types_ex = {0x60000000: 'OS-specific',
                           0x70000000: 'Processor-specific',
                           0x80000000: 'Application-specific'}

st_info_values = {
    0: ("STT_NOTYPE", "Symbol type is unspecified"),
    1: ("STT_OBJECT", "Symbol is a data object"),
    2: ("STT_FUNC", "Symbol is a code object"),
    3: ("STT_SECTION", "Symbol associated with a section"),
    4: ("STT_FILE", "Symbol's name is file name"),
    5: ("STT_COMMON", "Symbol is a common data object"),
    6: ("STT_TLS", "Symbol is thread-local data object"),
    7: ("STT_NUM", "Number of defined types"),
    10: ("STT_GNU_IFUNC", "Symbol is indirect code object")
}

stb_values = {
    0: ("STB_LOCAL", "Local, not visible outside the object file"),
    1: ("STB_GLOBAL", "Global, visible to all object files"),
    2: ("STB_WEAK", "Weak, like global but with lower precedence"),
    10: ("STB_GNU_UNIQUE", "Unique in the entire process (GNU extension)"),
    12: ("STB_HIPROC", "Processor-specific binding type")
}

relocation_table_types = {
    "EM_386": {
        0: ("R_386_NONE", 0, ""),
        1: ("R_386_32", 32, "S + A"),
        2: ("R_386_PC32", 32, "S + A - P"),
        3: ("R_386_GOT32", 32, "G + A"),
        4: ("R_386_PLT32", 32, "L + A - P"),
        5: ("R_386_COPY", 0, ""),
        6: ("R_386_GLOB_DAT", 32, "S"),
        7: ("R_386_JMP_SLOT", 32, "S"),
        8: ("R_386_RELATIVE", 32, "B + A"),
        9: ("R_386_GOTOFF", 32, "S + A - GOT"),
        10: ("R_386_GOTPC", 32, "GOT + A - P"),
        11: ("R_386_32PLT", 32, "L + A"),
        20: ("R_386_16", 16, "S + A"),
        21: ("R_386_PC16", 16, "S + A - P"),
        22: ("R_386_8", 8, "S + A"),
        23: ("R_386_PC8", 8, "S + A - P"),
        38: ("R_386_SIZE32", 32, "Z + A")
    },
    "EM_X86_64": {
        0: ("R_AMD64_NONE", 0, ""),
        1: ("R_AMD64_64", 64, "S + A"),
        2: ("R_AMD64_PC32", 32, "S + A - P"),
        3: ("R_AMD64_GOT32", 32, "G + A"),
        4: ("R_AMD64_PLT32", 32, "L + A - P"),
        5: ("R_AMD64_COPY", 0, ""),
        6: ("R_AMD64_GLOB_DAT", 64, "S"),
        7: ("R_AMD64_JUMP_SLOT", 64, "S"),
        8: ("R_AMD64_RELATIVE", 64, "B + A"),
        9: ("R_AMD64_GOTPCREL", 32, "G + GOT + A - P"),
        10: ("R_AMD64_32", 32, "S + A"),
        11: ("R_AMD64_32S", 32, "S + A"),
        12: ("R_AMD64_16", 16, "S + A"),
        13: ("R_AMD64_PC16", 16, "S + A - P"),
        14: ("R_AMD64_8", 8, "S + A"),
        15: ("R_AMD64_PC8", 8, "S + A - P"),
        24: ("R_AMD64_PC64", 64, "S + A - P"),
        25: ("R_AMD64_GOTOFF64", 64, "S + A - GOT"),
        26: ("R_AMD64_GOTPC32", 32, "GOT + A + P"),
        32: ("R_AMD64_SIZE32", 32, "Z + A"),
        33: ("R_AMD64_SIZE64", 64, "Z + A"),
    },
    "EM_ARM": {
        0: ("R_ARM_NONE", 0, ""),
        1: ("R_ARM_PC24", 24, "S - P + A"),
        2: ("R_ARM_ABS32", 32, "S + A"),
        3: ("R_ARM_REL32", 32, "S - P + A"),
        4: ("R_ARM_PC13", 13, "S - P + A"),
        5: ("R_ARM_ABS16", 16, "S + A"),
        6: ("R_ARM_ABS12", 12, "S + A"),
        7: ("R_ARM_THM_ABS5", 5, "S + A"),
        8: ("R_ARM_ABS8", 8, "S + A"),
        9: ("R_ARM_SBREL32", 32, "S - B + A"),
        10: ("R_ARM_THM_PC22", 22, "S - P + A"),
        11: ("R_ARM_THM_PC8", 8, "S - P + A"),
        12: ("Reserved", 0, ""),
        13: ("R_ARM_SWI24", 24, "S + A"),
        14: ("R_ARM_THM_SWI8", 8, "S + A"),
        15: ("R_ARM_XPC25", 25, ""),
        16: ("R_ARM_THM_XPC22", 22, ""),
        30: ("R_ARM_TLS_DESC", 0, ""),
        32: ("R_ARM_ALU_PCREL_7_0", 7, "(S - P + A) & 0x000000FF"),
        33: ("R_ARM_ALU_PCREL_15_8", 15, "(S - P + A) & 0x0000FF00"),
        34: ("R_ARM_ALU_PCREL_23_15", 23, "(S - P + A) & 0x00FF0000"),
        35: ("R_ARM_LDR_SBREL_11_0", 11, "(S - B + A) & 0x00000FFF"),
        36: ("R_ARM_ALU_SBREL_19_12", 19, "(S - B + A) & 0x000FF000"),
        37: ("R_ARM_ALU_SBREL_27_20", 27, "(S - B + A) & 0x0FF00000"),
        38: ("R_ARM_RELABS32", 32, "S + A or S - P + A"),
        39: ("R_ARM_ROSEGREL32", 32, "S - E + A"),
        40: ("R_ARM_V4BX", 0, ""),
        41: ("R_ARM_STKCHK", 0, ""),
        42: ("R_ARM_THM_STKCHK", 0, ""),
    },
    "EM_AARCH64": {
        0: ("R_AARCH64_NONE", 0, ""),
        257: ("R_AARCH64_ABS64", 64, "S + A"),
        258: ("R_AARCH64_ABS32", 32, "S + A"),
        259: ("R_AARCH64_ABS16", 16, "S + A"),
        260: ("R_AARCH64_PREL64", 64, "S + A - P"),
        261: ("R_AARCH64_PREL32", 32, "S + A - P"),
        262: ("R_AARCH64_PREL16", 16, "S + A - P"),
        263: ("R_AARCH64_MOVW_UABS_G0", 16, "S + A"),
        264: ("R_AARCH64_MOVW_UABS_G0_NC", 16, "S + A"),
        265: ("R_AARCH64_MOVW_UABS_G1", 32, "S + A"),
        266: ("R_AARCH64_MOVW_UABS_G1_NC", 32, "S + A"),
        267: ("R_AARCH64_MOVW_UABS_G2", 48, "S + A"),
        268: ("R_AARCH64_MOVW_UABS_G2_NC", 48, "S + A"),
        269: ("R_AARCH64_MOVW_UABS_G3", 64, "S + A"),
        270: ("R_AARCH64_MOVW_SABS_G0", 16, "S + A"),
        271: ("R_AARCH64_MOVW_SABS_G1", 32, "S + A"),
        272: ("R_AARCH64_MOVW_SABS_G2", 48, "S + A"),
        273: ("R_AARCH64_LD_PREL_LO19", 19, "S + A - P"),
        274: ("R_AARCH64_ADR_PREL_LO21", 21, "S + A - P"),
        275: ("R_AARCH64_ADR_PREL_PG_HI21", 21, "Page(S+A) - Page(P)"),
        276: ("R_AARCH64_ADR_PREL_PG_HI21_NC", 21, "Page(S+A) - Page(P)"),
        277: ("R_AARCH64_ADD_ABS_LO12_NC", 12, "S + A"),
        278: ("R_AARCH64_LDST8_ABS_LO12_NC", 12, "S + A"),
        279: ("R_AARCH64_TSTBR14", 14, "S + A - P"),
        280: ("R_AARCH64_CONDBR19", 19, "S + A - P"),
        282: ("R_AARCH64_JUMP26", 26, "S + A - P"),
        283: ("R_AARCH64_CALL26", 26, "S + A - P"),
        284: ("R_AARCH64_LDST16_ABS_LO12_NC", 16, "S + A"),
        285: ("R_AARCH64_LDST32_ABS_LO12_NC", 32, "S + A"),
        286: ("R_AARCH64_LDST64_ABS_LO12_NC", 64, "S + A"),
        287: ("R_AARCH64_MOVW_PREL_G0", 16, "S + A - P"),
        288: ("R_AARCH64_MOVW_PREL_G0_NC", 16, "S + A - P"),
        289: ("R_AARCH64_MOVW_PREL_G1", 32, "S + A - P"),
        290: ("R_AARCH64_MOVW_PREL_G1_NC", 32, "S + A - P"),
        291: ("R_AARCH64_MOVW_PREL_G2", 48, "S + A - P"),
        292: ("R_AARCH64_MOVW_PREL_G2_NC", 48, "S + A - P"),
        293: ("R_AARCH64_MOVW_PREL_G3", 64, "S + A - P"),
        299: ("R_AARCH64_LDST128_ABS_LO12_NC", 128, "S + A"),
        300: ("R_AARCH64_MOVW_GOTOFF_G0", 16, "G(GDAT(S+A)) - GOT"),
        301: ("R_AARCH64_MOVW_GOTOFF_G0_NC", 16, "G(GDAT(S+A)) - GOT"),
        302: ("R_AARCH64_MOVW_GOTOFF_G1", 32, "G(GDAT(S+A)) - GOT"),
        303: ("R_AARCH64_MOVW_GOTOFF_G1_NC", 32, "G(GDAT(S+A)) - GOT"),
        304: ("R_AARCH64_MOVW_GOTOFF_G2", 48, "G(GDAT(S+A)) - GOT"),
        305: ("R_AARCH64_MOVW_GOTOFF_G2_NC", 48, "G(GDAT(S+A)) - GOT"),
        306: ("R_AARCH64_MOVW_GOTOFF_G3", 64, "G(GDAT(S+A)) - GOT"),
        307: ("R_AARCH64_GOTREL64", 64, "S + A - GOT"),
        308: ("R_AARCH64_GOTREL32", 32, "S + A - GOT"),
        309: ("R_AARCH64_GOT_LD_PREL19", 19, "G(GDAT(S+A)) - P"),
        310: ("R_AARCH64_LD64_GOTOFF_LO15", 15, "G(GDAT(S+A)) - GOT"),
        311: ("R_AARCH64_ADR_GOT_PAGE", 21, "Page(G(GDAT(S+A))) - Page(P)"),
        312: ("R_AARCH64_LD64_GOT_LO12_NC", 12, "G(GDAT(S+A))"),
        313: ("R_AARCH64_LD64_GOTPAGE_LO15", 15, "G(GDAT(S+A)) - Page(GOT)"),
    },
    "EM_MIPS": {
        0: ("R_MIPS_NONE", 0, ""),
        1: ("R_MIPS_16", 16, "S + A"),
        2: ("R_MIPS_32", 32, "S + A"),
        3: ("R_MIPS_REL32", 32, "A + S - P"),
        4: ("R_MIPS_26", 26, "((A << 2) | (P & 0xF0000000)) + S"),
        5: ("R_MIPS_HI16", 16, "((A + S) >> 16) & 0xFFFF"),
        6: ("R_MIPS_LO16", 16, "(A + S) & 0xFFFF"),
        7: ("R_MIPS_GPREL16", 16, "S + A - GP"),
        8: ("R_MIPS_LITERAL", 16, ""),
        9: ("R_MIPS_GOT16", 16, "G + A"),
        10: ("R_MIPS_PC16", 16, "S + A - P"),
        11: ("R_MIPS_CALL16", 16, "G + A"),
        12: ("R_MIPS_GPREL32", 32, "S + A - GP"),
        16: ("R_MIPS_SHIFT5", 5, ""),
        17: ("R_MIPS_SHIFT6", 6, ""),
        18: ("R_MIPS_64", 64, "S + A"),
        19: ("R_MIPS_GOT_DISP", 16, "G + A - GP"),
        20: ("R_MIPS_GOT_PAGE", 16, "(G + A - GP) >> 16"),
        21: ("R_MIPS_GOT_OFST", 16, "(G + A - GP) & 0xFFFF"),
        22: ("R_MIPS_GOT_HI16", 16, "((G + A) >> 16) & 0xFFFF"),
        23: ("R_MIPS_GOT_LO16", 16, "(G + A) & 0xFFFF"),
        24: ("R_MIPS_SUB", 64, "S - A"),
        25: ("R_MIPS_INSERT_A", 0, ""),
        26: ("R_MIPS_INSERT_B", 0, ""),
        27: ("R_MIPS_DELETE", 0, ""),
        28: ("R_MIPS_HIGHER", 16, "(A + S) >> 32"),
        29: ("R_MIPS_HIGHEST", 16, "(A + S) >> 48"),
        30: ("R_MIPS_SCN_DISP", 16, ""),
        31: ("R_MIPS_REL16", 16, ""),
        32: ("R_MIPS_ADD_IMMEDIATE", 16, ""),
        33: ("R_MIPS_PJUMP", 26, ""),
        34: ("R_MIPS_RELGOT", 32, ""),
        35: ("R_MIPS_JALR", 0, ""),
        36: ("R_MIPS_TLS_DTPMOD32", 32, "TLSMODULE"),
        37: ("R_MIPS_TLS_DTPREL32", 32, "S + A - TLS_DTV_OFFSET"),
        38: ("R_MIPS_TLS_DTPMOD64", 64, "TLSMODULE"),
        39: ("R_MIPS_TLS_DTPREL64", 64, "S + A - TLS_DTV_OFFSET"),
        40: ("R_MIPS_TLS_GD", 16, "G"),
        41: ("R_MIPS_TLS_LDM", 16, "G"),
        42: ("R_MIPS_TLS_DTPREL_HI16", 16, "((S + A - TLS_DTV_OFFSET) >> 16) & 0xFFFF"),
        43: ("R_MIPS_TLS_DTPREL_LO16", 16, "(S + A - TLS_DTV_OFFSET) & 0xFFFF"),
        44: ("R_MIPS_TLS_GOTTPREL", 16, "G"),
        45: ("R_MIPS_TLS_TPREL32", 32, "S + A + TLSOFFSET"),
        46: ("R_MIPS_TLS_TPREL64", 64, "S + A + TLSOFFSET"),
        47: ("R_MIPS_TLS_TPREL_HI16", 16, "((S + A + TLSOFFSET) >> 16) & 0xFFFF"),
        48: ("R_MIPS_TLS_TPREL_LO16", 16, "(S + A + TLSOFFSET) & 0xFFFF")
    },
    "EM_RISCV": {
        0: ("R_RISCV_NONE", 0, ""),
        1: ("R_RISCV_32", 32, "S + A"),
        2: ("R_RISCV_64", 64, "S + A"),
        3: ("R_RISCV_RELATIVE", 255, "B + A"),
        4: ("R_RISCV_COPY", 0, ""),
        5: ("R_RISCV_JUMP_SLOT", 255, "S"),
        6: ("R_RISCV_TLS_DTPMOD32", 32, "TLSMODULE"),
        7: ("R_RISCV_TLS_DTPMOD64", 64, "TLSMODULE"),
        8: ("R_RISCV_TLS_DTPREL32", 32, "S + A - TLS_DTV_OFFSET"),
        9: ("R_RISCV_TLS_DTPREL64", 64, "S + A - TLS_DTV_OFFSET"),
        10: ("R_RISCV_TLS_TPREL32", 32, "S + A + TLSOFFSET"),
        11: ("R_RISCV_TLS_TPREL64", 64, "S + A + TLSOFFSET"),
        12: ("R_RISCV_TLSDESC", 0, "TLSDESC(S+A)"),
        16: ("R_RISCV_BRANCH", 254, "S + A - P"),
        17: ("R_RISCV_JAL", 248, "S + A - P"),
        18: ("R_RISCV_CALL", 246, "S + A - P"),
        19: ("R_RISCV_CALL_PLT", 246, "S + A - P"),
        20: ("R_RISCV_GOT_HI20", 249, "G + GOT + A - P"),
        21: ("R_RISCV_TLS_GOT_HI20", 249, ""),
        22: ("R_RISCV_TLS_GD_HI20", 249, ""),
        23: ("R_RISCV_PCREL_HI20", 249, "S + A - P"),
        24: ("R_RISCV_PCREL_LO12_I", 251, "S - P"),
        25: ("R_RISCV_PCREL_LO12_S", 250, "S - P"),
        26: ("R_RISCV_HI20", 249, "S + A"),
        27: ("R_RISCV_LO12_I", 251, "S + A"),
        28: ("R_RISCV_LO12_S", 250, "S + A"),
        29: ("R_RISCV_TPREL_HI20", 249, ""),
        30: ("R_RISCV_TPREL_LO12_I", 251, ""),
        31: ("R_RISCV_TPREL_LO12_S", 250, ""),
        32: ("R_RISCV_TPREL_ADD", 0, ""),
        33: ("R_RISCV_ADD8", 8, "V + S + A"),
        34: ("R_RISCV_ADD16", 16, "V + S + A"),
        35: ("R_RISCV_ADD32", 32, "V + S + A"),
        36: ("R_RISCV_ADD64", 64, "V + S + A"),
        37: ("R_RISCV_SUB8", 8, "V - S - A"),
        38: ("R_RISCV_SUB16", 16, "V - S - A"),
        39: ("R_RISCV_SUB32", 32, "V - S - A"),
        40: ("R_RISCV_SUB64", 64, "V - S - A"),
        41: ("R_RISCV_GOT32_PCREL", 32, "G + GOT + A - P"),
        42: ("R_RISCV_Reserved", 0, ""),
        43: ("R_RISCV_ALIGN", 0, ""),
        44: ("R_RISCV_RVC_BRANCH", 253, "S + A - P"),
        45: ("R_RISCV_RVC_JUMP", 252, "S + A - P"),
        46: ("R_RISCV_Reserved", 0, ""),
        51: ("R_RISCV_RELAX", 0, ""),
        52: ("R_RISCV_SUB6", 6, "V - S - A"),
        53: ("R_RISCV_SET6", 6, "S + A"),
        54: ("R_RISCV_SET8", 8, "S + A"),
        55: ("R_RISCV_SET16", 16, "S + A"),
        56: ("R_RISCV_SET32", 32, "S + A"),
        57: ("R_RISCV_32_PCREL", 32, "S + A - P"),
        58: ("R_RISCV_IRELATIVE", 255, "ifunc_resolver(B + A)"),
        59: ("R_RISCV_PLT32", 32, "S + A - P"),
        60: ("R_RISCV_SET_ULEB128", 247, "S + A"),
        61: ("R_RISCV_SUB_ULEB128", 247, "V - S - A"),
        62: ("R_RISCV_TLSDESC_HI20", 249, "S + A - P"),
        63: ("R_RISCV_TLSDESC_LOAD_LO12", 251, "S - P"),
        64: ("R_RISCV_TLSDESC_ADD_LO12", 251, "S - P"),
        65: ("R_RISCV_TLSDESC_CALL", 0, ""),
        191: ("R_RISCV_VENDOR", 0, "")
    }
}
