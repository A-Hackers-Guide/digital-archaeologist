add_executable(da_detect_test detect_test.cpp)
target_link_libraries(da_detect_test PRIVATE da_core)
add_test(NAME detect COMMAND da_detect_test)

add_executable(da_sha256_test sha256_test.cpp)
target_link_libraries(da_sha256_test PRIVATE da_core)
add_test(NAME sha256 COMMAND da_sha256_test)

add_executable(da_base64_test base64_test.cpp)
target_link_libraries(da_base64_test PRIVATE da_core)
add_test(NAME base64 COMMAND da_base64_test)

add_executable(da_crc32_test crc32_test.cpp)
target_link_libraries(da_crc32_test PRIVATE da_core)
add_test(NAME crc32 COMMAND da_crc32_test)

add_executable(da_strings_test strings_test.cpp)
target_link_libraries(da_strings_test PRIVATE da_core)
add_test(NAME strings COMMAND da_strings_test)

add_executable(da_carve_test carve_test.cpp)
target_link_libraries(da_carve_test PRIVATE da_core)
add_test(NAME carve COMMAND da_carve_test)

add_executable(da_timeline_test timeline_test.cpp)
target_link_libraries(da_timeline_test PRIVATE da_core)
add_test(NAME timeline COMMAND da_timeline_test)

# CLI smoke tests using the built binary
add_test(NAME cli_help COMMAND archaeologist --help)
add_test(NAME cli_version COMMAND archaeologist --version)
add_test(NAME cli_help_unknown COMMAND archaeologist --help unknown)
add_test(NAME cli_help_password COMMAND archaeologist --help password)
