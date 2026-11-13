cmake_minimum_required(VERSION 3.25)
project(QSAFE VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)
include(CTest)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.17.0
  GIT_SHALLOW TRUE
)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(SQLite3 REQUIRED)
set(QSAFE_LIBOQS_PREFIX "${CMAKE_SOURCE_DIR}/build/liboqs-install" CACHE PATH "liboqs install prefix")
find_package(liboqs CONFIG QUIET PATHS "${QSAFE_LIBOQS_PREFIX}/lib/cmake/liboqs")
find_path(ISA_L_INCLUDE_DIR NAMES erasure_code.h PATH_SUFFIXES isa-l)
find_library(ISA_L_LIBRARY NAMES isal)

if(NOT ISA_L_INCLUDE_DIR OR NOT ISA_L_LIBRARY)
  message(FATAL_ERROR "ISA-L development files are required for Reed-Solomon coding")
endif()

add_library(qsafe_common src/common/encoding.cpp)
target_include_directories(qsafe_common PUBLIC include)

add_library(qsafe_crypto src/crypto/hash.cpp src/crypto/signature.cpp)
target_include_directories(qsafe_crypto PUBLIC include)
target_link_libraries(qsafe_crypto PUBLIC qsafe_common OpenSSL::Crypto OQS::oqs)

add_library(qsafe_merkle src/merkle/merkle_tree.cpp)
target_include_directories(qsafe_merkle PUBLIC include)
target_link_libraries(qsafe_merkle PUBLIC qsafe_crypto)
add_library(qsafe_manifest src/manifest/manifest.cpp)
target_include_directories(qsafe_manifest PUBLIC include)
target_link_libraries(qsafe_manifest PUBLIC qsafe_crypto)
add_library(qsafe_storage src/storage/chunker.cpp src/storage/cloud_store.cpp)
target_include_directories(qsafe_storage PUBLIC include)
target_link_libraries(qsafe_storage PUBLIC qsafe_crypto SQLite::SQLite3)
add_library(qsafe_audit src/audit/audit.cpp src/audit/risk_sampling.cpp)
target_include_directories(qsafe_audit PUBLIC include)
target_link_libraries(qsafe_audit PUBLIC qsafe_manifest qsafe_merkle qsafe_storage)
add_library(qsafe_repair src/repair/reed_solomon_codec.cpp src/repair/commitment_repair.cpp)
target_include_directories(qsafe_repair PUBLIC include PRIVATE ${ISA_L_INCLUDE_DIR})
target_link_libraries(qsafe_repair PUBLIC qsafe_crypto qsafe_audit qsafe_storage ${ISA_L_LIBRARY})
add_library(qsafe_receipts src/receipts/audit_log.cpp)
target_include_directories(qsafe_receipts PUBLIC include)
target_link_libraries(qsafe_receipts PUBLIC qsafe_crypto SQLite::SQLite3)
add_library(qsafe_bench src/bench/faults/fault_injector.cpp)
target_include_directories(qsafe_bench PUBLIC include)
target_link_libraries(qsafe_bench PUBLIC qsafe_storage)
add_library(qsafe_vault_core src/vault/workspace.cpp)
target_include_directories(qsafe_vault_core PUBLIC include)
target_link_libraries(qsafe_vault_core PUBLIC qsafe_repair qsafe_audit qsafe_merkle qsafe_storage)

foreach(target qsafe_common qsafe_crypto qsafe_merkle qsafe_manifest qsafe_storage qsafe_audit
               qsafe_repair qsafe_receipts qsafe_bench qsafe_vault_core)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
endforeach()

if(BUILD_TESTING)
  add_executable(qsafe_scaffold_test tests/scaffold_test.cpp)
  target_link_libraries(qsafe_scaffold_test PRIVATE GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(qsafe_scaffold_test)

  add_executable(qsafe_common_test tests/common/encoding_test.cpp)
  target_link_libraries(qsafe_common_test PRIVATE qsafe_common GTest::gtest_main)
  target_compile_options(qsafe_common_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_common_test)

  add_executable(qsafe_crypto_test tests/crypto/hash_test.cpp)
  target_link_libraries(qsafe_crypto_test PRIVATE qsafe_crypto GTest::gtest_main)
  target_compile_options(qsafe_crypto_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_crypto_test)

  add_executable(qsafe_merkle_test tests/merkle/merkle_test.cpp)
  target_link_libraries(qsafe_merkle_test PRIVATE qsafe_merkle GTest::gtest_main)
  target_compile_options(qsafe_merkle_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_merkle_test)

  add_executable(qsafe_merkle_integration_test tests/merkle/integration_test.cpp)
  target_link_libraries(qsafe_merkle_integration_test PRIVATE qsafe_merkle GTest::gtest_main)
  target_compile_options(qsafe_merkle_integration_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_merkle_integration_test)

  add_executable(qsafe_manifest_test tests/manifest/manifest_test.cpp)
  target_link_libraries(qsafe_manifest_test PRIVATE qsafe_manifest GTest::gtest_main)
  target_compile_options(qsafe_manifest_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_manifest_test)

  add_executable(qsafe_storage_test tests/storage/chunker_test.cpp
                                     tests/storage/cloud_store_test.cpp)
  target_link_libraries(qsafe_storage_test PRIVATE qsafe_storage GTest::gtest_main)
  target_compile_options(qsafe_storage_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_storage_test)

  add_executable(qsafe_audit_test tests/audit/audit_test.cpp
                                   tests/audit/audit_integration_test.cpp
                                   tests/audit/risk_sampling_test.cpp)
  target_link_libraries(qsafe_audit_test PRIVATE qsafe_audit GTest::gtest_main)
  target_compile_options(qsafe_audit_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_audit_test)

  add_executable(qsafe_fault_test tests/bench/fault_injector_test.cpp)
  target_link_libraries(qsafe_fault_test PRIVATE qsafe_bench GTest::gtest_main)
  target_compile_options(qsafe_fault_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_fault_test)

  add_executable(qsafe_repair_codec_test tests/repair/codec_test.cpp)
  target_link_libraries(qsafe_repair_codec_test PRIVATE qsafe_repair GTest::gtest_main)
  target_compile_options(qsafe_repair_codec_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_repair_codec_test)

  add_executable(qsafe_commitment_repair_test tests/repair/repair_test.cpp)
  target_link_libraries(qsafe_commitment_repair_test PRIVATE qsafe_repair GTest::gtest_main)
  target_compile_options(qsafe_commitment_repair_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_commitment_repair_test)

  add_executable(qsafe_receipts_test tests/receipts/receipt_log_test.cpp)
  target_link_libraries(qsafe_receipts_test PRIVATE qsafe_receipts qsafe_audit GTest::gtest_main)
  target_compile_options(qsafe_receipts_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_receipts_test)

  add_executable(qsafe_vault_test tests/vault/workspace_test.cpp)
  target_link_libraries(qsafe_vault_test PRIVATE qsafe_vault_core GTest::gtest_main)
  target_compile_options(qsafe_vault_test PRIVATE -Wall -Wextra -Wpedantic)
  gtest_discover_tests(qsafe_vault_test)

  if(liboqs_FOUND)
    add_executable(qsafe_liboqs_gate tests/liboqs_gate.c)
    target_link_libraries(qsafe_liboqs_gate PRIVATE OQS::oqs)
    add_test(NAME qsafe_liboqs_gate COMMAND qsafe_liboqs_gate)
  endif()
endif()

add_executable(qsafe_signature_bench benchmarks/signature_bench.cpp)
target_link_libraries(qsafe_signature_bench PRIVATE qsafe_crypto)

add_executable(qsafe_demo tools/qsafe_demo.cpp)
target_link_libraries(qsafe_demo PRIVATE qsafe_receipts qsafe_repair qsafe_audit qsafe_merkle
                                          qsafe_storage)

add_executable(qsafe_audit_experiment benchmarks/audit_experiment.cpp)
target_link_libraries(qsafe_audit_experiment PRIVATE qsafe_receipts qsafe_repair qsafe_bench
                                                       qsafe_audit qsafe_merkle qsafe_storage)
target_compile_options(qsafe_audit_experiment PRIVATE -Wall -Wextra -Wpedantic)

add_executable(qsafe_vault tools/qsafe_vault.cpp)
target_link_libraries(qsafe_vault PRIVATE qsafe_vault_core)
target_compile_options(qsafe_vault PRIVATE -Wall -Wextra -Wpedantic)
