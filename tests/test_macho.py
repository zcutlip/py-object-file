from pyobjfile.mach_o import Mach
import os

DATA_PATH = os.path.join("tests", "data")

HELLO_X86_64 = os.path.join(DATA_PATH, "hello-x86_64")
HELLO_FAT = os.path.join(DATA_PATH, "hello-fat")
HELLO_ARM64 = os.path.join(DATA_PATH, "hello-arm64")


def setup_macho_generic(filename):
    macho = Mach(path=filename)
    return macho


def setup_macho_x86_64():
    macho = setup_macho_generic(HELLO_X86_64)
    return macho


def setup_macho_fat():
    macho = setup_macho_generic(HELLO_FAT)
    return macho


def setup_macho_arm64():
    macho = setup_macho_generic(HELLO_ARM64)
    return macho


def test_open_macho_x86_64():
    macho = setup_macho_x86_64()
    assert macho.is_valid()


def test_open_macho_arm64():
    macho = setup_macho_arm64()
    assert macho.is_valid()


def test_open_macho_fat():
    macho = setup_macho_fat()
    assert macho.is_valid()


def test_num_archs_x86_64():
    macho = setup_macho_x86_64()
    assert macho.get_num_archs() == 1


def test_num_archs_arm64():
    macho = setup_macho_arm64()
    assert macho.get_num_archs() == 1


def test_num_archs_fat():
    macho = setup_macho_fat()
    assert macho.get_num_archs() == 2


def test_get_first_arch_name_x86_64():
    macho = setup_macho_x86_64()
    arch = macho.get_architecture(0)
    assert "x86_64" == str(arch)


def test_get_first_arch_name_arm64():
    macho = setup_macho_arm64()
    arch = macho.get_architecture(0)
    assert "arm64" == str(arch)


def test_get_arch_names_fat_01():
    macho = setup_macho_fat()
    arch = macho.get_architecture(0)
    assert "i386" == str(arch)


def test_get_arch_names_fat_02():
    macho = setup_macho_fat()
    arch = macho.get_architecture(1)
    assert "x86_64" == str(arch)


def _compare_arch_at_index(arch_idx, slice_idx, macho):
    arch = macho.get_architecture(arch_idx)
    slice1 = macho.get_architecture_slice(str(arch))
    slice2 = macho.get_architecture_slice_at_index(slice_idx)
    return slice1 == slice2


def test_get_arch_at_index_x86_64():
    macho = setup_macho_x86_64()
    arch_idx = slice_idx = 0
    assert _compare_arch_at_index(arch_idx, slice_idx, macho) is True


def test_get_arch_at_index_arm64():
    macho = setup_macho_arm64()
    arch_idx = slice_idx = 0
    assert _compare_arch_at_index(arch_idx, slice_idx, macho) is True


def test_get_arch_at_index_fat_01():
    macho = setup_macho_fat()
    arch_idx = slice_idx = 0
    assert _compare_arch_at_index(arch_idx, slice_idx, macho) is True


def test_get_arch_at_index_fat_02():
    macho = setup_macho_fat()
    arch_idx = slice_idx = 1
    assert _compare_arch_at_index(arch_idx, slice_idx, macho) is True


def setup_segments_x86_64():
    macho = setup_macho_x86_64()
    mslice = macho.get_architecture_slice_at_index(0)
    segments = mslice.segments
    return segments


def setup_segments_arm64():
    macho = setup_macho_arm64()
    mslice = macho.get_architecture_slice_at_index(0)
    segments = mslice.segments
    return segments


def setup_get_seg_num(filename, arch_idx, segnum):
    macho = setup_macho_generic(filename)
    mslice = macho.get_architecture_slice_at_index(arch_idx)
    seg = mslice.segments[segnum]
    return seg


def test_get_segments_x86_64_01():
    segments = setup_segments_x86_64()
    # previously we were getting a __DATA_CONST, but not now
    # why?
    assert 4 == len(segments)


def test_get_segments_x86_64_02():
    text_segment = setup_get_seg_num(HELLO_X86_64, 0, 1)
    assert b'__TEXT' == text_segment.segname


def test_get_segments_x86_64_03():
    text_segment = setup_get_seg_num(HELLO_X86_64, 0, 1)
    assert 0x68 == text_segment.file_off


def test_get_segments_arm64_01():
    segments = setup_segments_arm64()
    assert 5 == len(segments)


def test_get_segments_arm64_02():
    data_segment = setup_get_seg_num(HELLO_ARM64, 0, 3)
    assert b'__DATA' == data_segment.segname


def test_get_segments_arm64_03():
    data_segment = setup_get_seg_num(HELLO_ARM64, 0, 3)
    assert 0x2d8 == data_segment.file_off


def test_sections_x86_64_01():
    text_segment = setup_get_seg_num(HELLO_X86_64, 0, 1)
    text_sections = text_segment.sections
    assert 5 == len(text_sections)


def test_sections_x86_64_02():
    text_segment = setup_get_seg_num(HELLO_X86_64, 0, 1)
    text_sections = text_segment.sections
    text_text = text_sections[0]
    assert b'__text' == text_text.sectname


def test_sections_x86_64_03():
    text_segment = setup_get_seg_num(HELLO_X86_64, 0, 1)
    text_sections = text_segment.sections
    text_text = text_sections[0]
    assert 0xb0 == text_text.file_offset


def test_sections_arm64_01():
    text_segment = setup_get_seg_num(HELLO_ARM64, 0, 1)
    text_sections = text_segment.sections
    assert 5 == len(text_sections)


def test_sections_arm64_02():
    text_segment = setup_get_seg_num(HELLO_ARM64, 0, 1)
    text_sections = text_segment.sections
    text_text = text_sections[0]
    assert b'__text' == text_text.sectname


def test_sections_arm64_03():
    text_segment = setup_get_seg_num(HELLO_ARM64, 0, 1)
    text_sections = text_segment.sections
    text_text = text_sections[0]
    assert 0xb0 == text_text.file_offset


def test_get_c_string_x86_64():
    #   $ strings -t x -a data/hello-x86_64
    # faa Hello world
    macho = setup_macho_x86_64()
    mslice = macho.get_architecture_slice_at_index(0)
    hello_world_offset = 0xfaa
    mslice.data_seek(hello_world_offset)
    data = mslice.data.get_c_string()
    assert "Hello world\n" == data


def test_get_c_string_arm64():
    #  $ strings -t x -a data/hello-arm64
    # 7fa8 Hello world
    macho = setup_macho_arm64()
    mslice = macho.get_architecture_slice_at_index(0)
    hello_world_offset = 0x7fa8
    mslice.data_seek(hello_world_offset)
    data = mslice.data.get_c_string()
    assert "Hello world\n" == data


def test_get_c_string_fat_01():
    # $ strings -arch i386 -t x ./hello-fat
    # f9e Hello world
    macho = setup_macho_fat()
    mslice = macho.get_architecture_slice_at_index(0)
    hello_world_offset = 0xf9e
    mslice.data_seek(hello_world_offset)
    data = mslice.data.get_c_string()
    assert "Hello world\n" == data


def test_get_c_string_fat_02():
    # $ strings -arch x86_64 -t x ./hello-fat
    # f9e Hello world
    macho = setup_macho_fat()
    mslice = macho.get_architecture_slice_at_index(1)
    hello_world_offset = 0xf9e
    mslice.data_seek(hello_world_offset)
    data = mslice.data.get_c_string()
    assert "Hello world\n" == data
