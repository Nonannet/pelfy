import pelfy._main as _main


def test_readme_example() -> None:
    elf = _main.open_elf_file('tests/obj/test-c-riscv64-linux-gnu-gcc-12-O3.o')

    assert ' description ' in elf.sections.to_markdown()
    assert ' stb ' in elf.functions.to_markdown()
    assert ' symbol name ' in elf.symbols['read_float'].relocations.to_markdown()
