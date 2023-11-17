project('zep', 'cpp',
        default_options: ['cpp_std=c++20',
                          'warning_level=3'])

subdir('src')
subdir('tests')

run_target('check',
  command : 'tests/scripts/check.sh')
