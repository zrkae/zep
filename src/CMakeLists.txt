project(zep)

if (NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra -pedantic -std=c++20 -fsanitize=address,undefined")

set(SOURCES
    zep.cc
)

add_library(${PROJECT_NAME} SHARED ${SOURCES})
