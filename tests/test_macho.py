from pyobjfile.mach_o import Mach


def setup_macho():
    macho_path = "tests/data/hello"
    macho = Mach(path=macho_path)
    return macho


def test_open_macho():
    macho = setup_macho()
    assert macho.is_valid()


def test_num_archs():
    macho = setup_macho()
    assert macho.get_num_archs() == 1


def test_get_first_arch_name():
    macho = setup_macho()
    arch = macho.get_architecture(0)
    assert "x86_64" == str(arch)


def test_get_arch_at_index():
    macho = setup_macho()
    arch = macho.get_architecture(0)
    slice1 = macho.get_architecture_slice(str(arch))
    slice2 = macho.get_architecture_slice_at_index(0)
    assert slice1 == slice2


def setup_segments():
    macho = setup_macho()
    mslice = macho.get_architecture_slice_at_index(0)
    segments = mslice.segments
    return segments


def test_get_segments():
    segments = setup_segments()
    assert 5 == len(segments)


def test_sections_01():
    segments = setup_segments()
    text_segment = segments[1]
    assert 0x68 == text_segment.file_off


def test_sections_02():
    segments = setup_segments()
    text_segment = segments[1]
    assert b'__TEXT' == text_segment.segname


def test_get_c_string():
    macho = setup_macho()
    mslice = macho.get_architecture_slice_at_index(0)
    hello_world_offset = 0xfaa
    mslice.data.seek(hello_world_offset)
    data = mslice.data.get_c_string()
    assert "Hello world\n" == data
