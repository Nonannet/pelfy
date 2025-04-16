# pelfy

## Description
Pelfy (Python Executable and Linkable Format analyzer) is an ELF parser written
in python. It shows header fields, sections, symbols and relocation and gives
access to all raw data as well as human readable representations. 

### Key Features
- Provide names for fields and values as well as descriptions
- Relocation types for x86, MIPS, ARM and RISC-V all in 32 and 64 bit
- Outputs tables in nicely formatted HTML, markdown or text
- Uses HTML outputs for Jupyter Notebook integration
- Compact code base
- Pure fully static typed python and no other dependencies

### Usage Scenarios
- Reverse engineering tools
- Testing
- Documentation

## Installation
The package has no additional dependencies. It can be installed with pip:

```bash
pip install pelfy
```

## Usage
Example code and its outputs:

```python
import pelfy

elf = pelfy.open_elf_file('tests/obj/test-c-riscv64-linux-gnu-gcc-12-O3.o')
elf.sections
```
| index | name              | type         | description                       |
|------:|-------------------|--------------|-----------------------------------|
|     0 |                   | SHT_NULL     | Section header table entry unused |
|     1 | .text             | SHT_PROGBITS | Program data                      |
|     2 | .rela.text        | SHT_RELA     | Relocation entries with addends   |
|     3 | .data             | SHT_PROGBITS | Program data                      |
|     4 | .bss              | SHT_NOBITS   | Program space with no data (bss)  |
|     5 | .comment          | SHT_PROGBITS | Program data                      |
|     6 | .note.GNU-stack   | SHT_PROGBITS | Program data                      |
|     7 | .riscv.attributes | 0x70000003   | Application-specific              |
|     8 | .symtab           | SHT_SYMTAB   | Symbol table                      |
|     9 | .strtab           | SHT_STRTAB   | String table                      |
|    10 | .shstrtab         | SHT_STRTAB   | String table                      |
```python
elf.functions
```
| index | name               | info     | size | stb        | description             |
|------:|--------------------|----------|-----:|------------|-------------------------|
|    11 | result_float       | STT_FUNC |    8 | STB_GLOBAL | Symbol is a code object |
|    12 | result_float_float | STT_FUNC |   12 | STB_GLOBAL | Symbol is a code object |
|    13 | add_float_float    | STT_FUNC |   12 | STB_GLOBAL | Symbol is a code object |
|    14 | mul_float_float    | STT_FUNC |   12 | STB_GLOBAL | Symbol is a code object |
|    15 | read_float         | STT_FUNC |   16 | STB_GLOBAL | Symbol is a code object |
```python
elf.symbols['read_float'].relocations
```
| index | symbol name        | type                 | calculation |
|------:|--------------------|----------------------|-------------|
|     4 | .LANCHOR0          | R_RISCV_PCREL_HI20   | S + A - P   |
|     5 |                    | R_RISCV_RELAX        |             |
|     6 | .L0                | R_RISCV_PCREL_LO12_I | S - P       |
|     7 |                    | R_RISCV_RELAX        |             |
|     8 | result_float_float | R_RISCV_CALL_PLT     | S + A - P   |
|     9 |                    | R_RISCV_RELAX        |             |

## Contributing
Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## Developer Guide
To get started with developing the `pelfy` package, follow these steps:

First, clone the repository to your local machine using Git:

```bash
git clone https://github.com/Nonannet/pelfy.git
cd pelfy
```

Install the package while keeping files in the current dev directory:

```bash
pip install -e .
```

Install pytest (unit testing), mypy (type checking) and flake8 (style guide checking):

```bash
pip install pytest mypy flake8
```

Ensure that everything is set up correctly by running the tests:

```bash
pytest
```

For creating additional test object files place the source c-files in the `tests/src/` directory,
change the current directory to `tests/src/` and run `bash run_cross_compilation.sh`. This
script uses a docker container to cross compile all c-files to object files and outputs
them in the tests/obj directory.
   
## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.