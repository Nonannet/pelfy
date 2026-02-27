import pelfy._main as _main
import os

def test_arm_addend_extraction():
    # Path to the test object file
    obj_path = os.path.join('tests', 'obj', 'stencils_armv7_O3.o')
    elf = _main.open_elf_file(obj_path)

    # Collect all ARM relocations
    reloc_addends: list[tuple[str, int, int, str]] = []
    for reloc in elf.get_relocations():
        if reloc.type.startswith('R_ARM'):
            reloc_addends.append((reloc.type, reloc['r_offset'], reloc['r_addend'], reloc.symbol.name))

    # Reference values from stencils_armv7_O3.asm (addend = 0 for V4BX, -8 for JUMP24/CALL)
    reference = [
        ('R_ARM_V4BX', 0xB4, 0, ''),
        ('R_ARM_V4BX', 0xC0, 0, ''),
        ('R_ARM_V4BX', 0xD0, 0, ''),
        ('R_ARM_V4BX', 0x114, 0, ''),
        ('R_ARM_V4BX', 0x144, 0, ''),
        ('R_ARM_V4BX', 0x148, 0, ''),
        ('R_ARM_JUMP24', 0x124, -8, '__aeabi_idiv0'),
        ('R_ARM_JUMP24', 0x14, -8, 'auxsub_get_42'),
        ('R_ARM_CALL', 0x10, -8, 'result_int'),
        ('R_ARM_JUMP24', 0xC, -8, 'result_float_int'),
        ('R_ARM_JUMP24', 0xC, -8, 'result_float_float'),
        ('R_ARM_JUMP24', 0xC, -8, 'result_int_int'),
        ('R_ARM_JUMP24', 0xC, -8, 'result_int_float'),
        ('R_ARM_CALL', 0xC, -8, 'aux_get_42'),
        ('R_ARM_JUMP24', 0x14, -8, 'result_float'),
        ('R_ARM_CALL', 0x4, -8, 'aux_get_42'),
        ('R_ARM_JUMP24', 0xC, -8, 'result_float'),
        ('R_ARM_JUMP24', 0x4, -8, 'result_int'),
        ('R_ARM_JUMP24', 0x4, -8, 'result_float'),
        ('R_ARM_JUMP24', 0x2C, -8, 'result_float'),
        ('R_ARM_CALL', 0x30, -8, 'sqrtf'),
        ('R_ARM_JUMP24', 0x24, -8, 'result_float'),
        ('R_ARM_CALL', 0x28, -8, 'sqrtf'),
        ('R_ARM_CALL', 0xC, -8, 'expf'),
        ('R_ARM_JUMP24', 0x14, -8, 'result_float'),
        ('R_ARM_CALL', 0x4, -8, 'expf'),
        ('R_ARM_JUMP24', 0xC, -8, 'result_float'),
        ('R_ARM_CALL', 0xC, -8, 'logf'),
        ('R_ARM_JUMP24', 0x14, -8, 'result_float'),
        ('R_ARM_CALL', 0x4, -8, 'logf'),
        ('R_ARM_JUMP24', 0xC, -8, 'result_float'),
        ('R_ARM_CALL', 0xC, -8, 'sinf'),
        ('R_ARM_JUMP24', 0x14, -8, 'result_float'),
        ('R_ARM_CALL', 0x4, -8, 'sinf'),
        ('R_ARM_JUMP24', 0xC, -8, 'result_float'),
    ]
    # For each reference, check that at least one matching relocation has the expected addend
    for ref_type, ref_offset, ref_addend, ref_symbol in reference:
        found = False
        addend = None
        for typ, offset, addend, symbol in reloc_addends:
            if typ == ref_type and offset == ref_offset and symbol == ref_symbol and addend == ref_addend:
                found = True
                break
        assert found, f"Missing or incorrect addend for {ref_type} offset=0x{ref_offset:X} symbol={ref_symbol} (value={addend}, expected {ref_addend})"

        print(found, f"Missing or incorrect addend for {ref_type} offset=0x{ref_offset:X} symbol={ref_symbol} (value={addend}, expected {ref_addend})")

    assert False