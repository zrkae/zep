tests = {
    'basic elf init': 'basic_init.cc',
    'iterators': 'iter.cc',
}

foreach name, source : tests
                   # remove suffix .cc
    exe = executable(source.substring(0, -3), source, link_with: libzep)
    test(name, exe)
endforeach
