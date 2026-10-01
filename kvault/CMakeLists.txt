cmake_minimum_required(VERSION 3.20)
project(kvault
    VERSION 1.0.0
    DESCRIPTION "KernelVault: Production-Grade Linux Kernel-Assisted Secure Storage System"
    LANGUAGES C CXX
)

# Enforce Modern C++20 Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for language servers and static analysis
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Strict Compiler Diagnostics & Architectural Standards
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -Wshadow
        -Wnon-virtual-dtor
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
    )
endif()

# Sanitizer Configuration Option
option(ENABLE_ASAN "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(ENABLE_ASAN)
    message(STATUS "Enabling AddressSanitizer & UndefinedBehaviorSanitizer (-fsanitize=address,undefined)")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# Include directories
include_directories(include)

# Core Static Library
add_library(kvault_core STATIC
    src/UniqueFd.cpp
    src/FileLock.cpp
    src/AtomicFileWriter.cpp
    src/KeyDerivation.cpp
    src/VaultManager.cpp
)

add_library(sec_store_core ALIAS kvault_core)

target_include_directories(kvault_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# CLI Binary Executable
add_executable(kvault
    src/main.cpp
)

target_link_libraries(kvault PRIVATE
    kvault_core
)

# Backwards compatibility executable alias target
add_custom_target(sec-store ALL
    COMMAND ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE:kvault> $<TARGET_FILE_DIR:kvault>/sec-store
    DEPENDS kvault
    COMMENT "Creating legacy symlink sec-store -> kvault"
)

# Out-of-tree Linux Kernel Module Custom Target
find_program(MAKE_EXE make)
if(MAKE_EXE AND UNIX)
    add_custom_target(driver
        COMMAND ${MAKE_EXE} -C ${CMAKE_CURRENT_SOURCE_DIR}/driver all
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/driver
        COMMENT "Compiling Linux Kernel Module kvault against running kernel headers..."
    )

    add_custom_target(driver-clean
        COMMAND ${MAKE_EXE} -C ${CMAKE_CURRENT_SOURCE_DIR}/driver clean
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/driver
        COMMENT "Cleaning Linux Kernel Module build artifacts..."
    )
endif()

# Static Analysis Targets
find_program(CPPCHECK_EXE cppcheck)
if(CPPCHECK_EXE)
    add_custom_target(cppcheck
        COMMAND ${CPPCHECK_EXE}
            --enable=all
            --suppress=missingIncludeSystem
            --inconclusive
            --error-exitcode=1
            --std=c++20
            -I ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        COMMENT "Running cppcheck static analysis on C++ sources..."
    )
endif()

find_program(CLANG_TIDY_EXE clang-tidy)
if(CLANG_TIDY_EXE)
    add_custom_target(clang-tidy
        COMMAND ${CLANG_TIDY_EXE}
            -p ${CMAKE_BINARY_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
        COMMENT "Running clang-tidy checks on C++ sources..."
    )
endif()

# Kernel checkpatch.pl Target
find_file(CHECKPATCH_PL "checkpatch.pl" PATHS "/usr/src/linux/scripts" "/lib/modules/$(uname -r)/source/scripts")
if(CHECKPATCH_PL)
    add_custom_target(checkpatch
        COMMAND ${CHECKPATCH_PL} --no-tree -f ${CMAKE_CURRENT_SOURCE_DIR}/driver/kvault_module.c
        COMMENT "Running Linux Kernel checkpatch.pl on kernel driver..."
    )
endif()

# Installation Targets
install(TARGETS kvault DESTINATION bin)
install(DIRECTORY include/ DESTINATION include/kvault FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")

# Unit and Integration Testing
option(BUILD_TESTING "Build Google Test test suite" ON)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
