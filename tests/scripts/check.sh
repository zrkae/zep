#!/bin/sh

cppcheck --enable=all ${MESON_SOURCE_ROOT}/src --suppress=unusedFunction --suppress=missingIncludeSystem
