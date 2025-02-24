import pelfy


def test_simple_c():
    elf = pelfy.open_elf_file('tests/obj/test3_o3.o')

    print(elf.sections)
    print(elf.symbols)
    print(elf.code_relocations)


if __name__ == '__main__':
    test_simple_c()
