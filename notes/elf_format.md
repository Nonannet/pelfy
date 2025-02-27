# ELF for ARM
http://netwinder.osuosl.org/pub/netwinder/docs/arm/ARMELFA06.pdf (page 32)
From https://simplemachines.it/doc/aaelf.pdf

The computation that must be performed in order to determine the relocation result. The following
nomenclature is used
- S denotes the value of symbol referenced in ELF32_R_SYM component of the r_info field.
- A denotes the initial addend. For a RELA type relocation the value is used unmodified. For a REL type
relocation the value must be extracted from the place in a manner that is determined by the type of the
place.
- P denotes the address of the place being relocated. It is the sum of the r_offset field and the base
address of the section being relocated (note that all relocations involving P are of the form S – P, where
the symbol referenced is in the same consolidated output section as P, so it is not necessary to know the
absolute address of the section being relocated).
ELF for the ARM Architecture
GENC-003538 v0.3 DRAFT Page 14 of 17
- B is the nominal base address used for accessing objects in the read-write data areas.
- E is the nominal base address used for accessing objects in the executable and read-only areas.
The precise definition of a nominal base address is platform defined, but it must be possible for the application to
retrieve the value at run time by one of the following methods:
! A pre-determined value
! A value in a known register
! A suitable symbol
! A library call
The platform documentation must describe the appropriate model for each of B and E (they need not be the
same).

# RISC V
https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc