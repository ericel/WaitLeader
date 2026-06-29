cmake_minimum_required(VERSION 3.20)
project(WaitLeader C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_program(CLANG_EXE clang REQUIRED)
set(WAITLEADER_MULTIARCH_INCLUDE "/usr/include/${CMAKE_HOST_SYSTEM_PROCESSOR}-linux-gnu")

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/waitleader_xdp.o
    COMMAND ${CLANG_EXE} -O2 -g -target bpf -I${WAITLEADER_MULTIARCH_INCLUDE} -c ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/waitleader_xdp.c -o ${CMAKE_CURRENT_BINARY_DIR}/waitleader_xdp.o
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/waitleader_xdp.c ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/waitleader_maps.h
    COMMENT "Compiling eBPF XDP fast data plane"
    VERBATIM
)

add_custom_target(xdp_bytecode ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/waitleader_xdp.o)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/waitleader_sk_msg.o
    COMMAND ${CLANG_EXE} -O2 -g -target bpf -I${WAITLEADER_MULTIARCH_INCLUDE} -c ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/waitleader_sk_msg.c -o ${CMAKE_CURRENT_BINARY_DIR}/waitleader_sk_msg.o
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/waitleader_sk_msg.c ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/waitleader_maps.h
    COMMENT "Compiling eBPF SK_MSG encrypted data plane"
    VERBATIM
)

add_custom_target(sk_msg_bytecode ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/waitleader_sk_msg.o)

# --- USER SPACE CONTROL PLANE ---
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

add_executable(waitleader_ctrl src/ctrl/WaitLeaderCtrl.cpp)
target_include_directories(waitleader_ctrl PRIVATE ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(waitleader_ctrl PRIVATE ${LIBBPF_LIBRARIES} elf z)

add_executable(dbwaller_xdp_mock src/ctrl/MockDBWallerEngine.cpp)
target_include_directories(dbwaller_xdp_mock PRIVATE ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(dbwaller_xdp_mock PRIVATE ${LIBBPF_LIBRARIES} elf z)

add_executable(waitleader_observe src/ctrl/WaitLeaderObserve.cpp)
target_include_directories(waitleader_observe PRIVATE ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(waitleader_observe PRIVATE ${LIBBPF_LIBRARIES} elf z)

add_executable(waitleader_h2_policy src/ctrl/WaitLeaderH2Policy.cpp)
target_include_directories(waitleader_h2_policy PRIVATE ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(waitleader_h2_policy PRIVATE ${LIBBPF_LIBRARIES} elf z)

enable_testing()

add_executable(test_memory_leak tests/test_memory_leak.cpp)
target_include_directories(test_memory_leak PRIVATE ${LIBBPF_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/src/ctrl)
target_link_libraries(test_memory_leak PRIVATE ${LIBBPF_LIBRARIES} elf z)

add_test(NAME MemoryLeakValidation COMMAND test_memory_leak)
