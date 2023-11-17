tests = {
    'basic elf init': 'basic_init.cc',
    'iterators': 'iter.cc',
    'malformed elf files': 'malformed_input.cc',
    '\'sstrip\'ed file (no symbols or sections)': 'stripped.cc',
}

foreach name, source : tests
    exe = executable(source.substring(0, -3), # remove suffix .cc
                    source, link_with: libzep,
                    cpp_args: ['-DTEST_FILE_DIR="' + meson.project_source_root() + '/tests/files/"',
                                '-std=c++20', '-Wall', '-Wextra'])
    test(name, exe)
endforeach
