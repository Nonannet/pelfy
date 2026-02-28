import pelfy._main as _main
import os
from typing import Union


def test_thumb_addend_extraction() -> None:
    # Path to the test object file
    obj_path = os.path.join('tests', 'obj', 'stencils_armv7thumb_O3_THM_MOVW.o')
    elf = _main.open_elf_file(obj_path)

    # Collect all relocations of interest
    reloc_addends: list[tuple[str, int, int, str]] = []
    for reloc in elf.get_relocations():
        if reloc.type.startswith('R_ARM_THM'):
            reloc_addends.append((reloc.type, reloc['r_offset'], reloc['r_addend'], reloc.symbol.name))

    # Reference values from the .asm file (addend = 0 for all Thumb relocations)
    reference: list[tuple[str, Union[int, None], int, str]] = [
        ('R_ARM_THM_MOVW_ABS_NC', None, 0, 'dummy_int'),
        ('R_ARM_THM_MOVT_ABS', None, 0, 'dummy_int'),
        ('R_ARM_THM_MOVW_ABS_NC', None, 0, 'dummy_float'),
        ('R_ARM_THM_MOVT_ABS', None, 0, 'dummy_float'),
        ('R_ARM_THM_JUMP24', 0x14, -4, 'auxsub_get_42'),
        ('R_ARM_THM_CALL', 0xA, -4, 'result_int'),
        ('R_ARM_THM_JUMP24', 0xA, -4, 'result_float_int'),
        ('R_ARM_THM_JUMP24', 0xC, -4, 'result_float_float'),
        ('R_ARM_THM_JUMP24', 0xA, -4, 'result_int_int'),
        ('R_ARM_THM_JUMP24', 0xC, -4, 'result_int_float'),
        ('R_ARM_THM_CALL', 0xA, -4, 'aux_get_42'),
        ('R_ARM_THM_JUMP24', 0x12, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0x2, -4, 'aux_get_42'),
        ('R_ARM_THM_JUMP24', 0xA, -4, 'result_float'),
        ('R_ARM_THM_JUMP24', 0x2, -4, 'result_int'),
        ('R_ARM_THM_JUMP24', 0x4, -4, 'result_float'),
        ('R_ARM_THM_JUMP24', 0x28, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0x2C, -4, 'sqrtf'),
        ('R_ARM_THM_JUMP24', 0x20, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0x24, -4, 'sqrtf'),
        ('R_ARM_THM_CALL', 0xA, -4, 'expf'),
        ('R_ARM_THM_JUMP24', 0x12, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0x2, -4, 'expf'),
        ('R_ARM_THM_JUMP24', 0xA, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0xA, -4, 'logf'),
        ('R_ARM_THM_JUMP24', 0x12, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0x2, -4, 'logf'),
        ('R_ARM_THM_JUMP24', 0xA, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0xA, -4, 'sinf'),
        ('R_ARM_THM_JUMP24', 0x12, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0x2, -4, 'sinf'),
        ('R_ARM_THM_JUMP24', 0xA, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0xA, -4, 'cosf'),
        ('R_ARM_THM_JUMP24', 0x12, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0x2, -4, 'cosf'),
        ('R_ARM_THM_JUMP24', 0xA, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0xA, -4, 'tanf'),
        ('R_ARM_THM_JUMP24', 0x12, -4, 'result_float'),
        ('R_ARM_THM_CALL', 0x2, -4, 'tanf'),
    ]
    # For each reference, check that at least one matching relocation has the expected addend
    for ref_type, _, ref_addend, ref_symbol in reference:
        found = False
        addend = 0
        for typ, offset, addend, symbol in reloc_addends:
            if typ == ref_type and symbol == ref_symbol and addend == ref_addend:
                found = True
                break
        assert found, f"Missing or incorrect addend for {ref_type} {ref_symbol} (value={addend:X}, expected {ref_addend})"
