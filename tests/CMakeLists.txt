add_executable(da_detect_test detect_test.cpp)
target_link_libraries(da_detect_test PRIVATE da_core)
add_test(NAME detect COMMAND da_detect_test)

add_executable(da_sha256_test sha256_test.cpp)
target_link_libraries(da_sha256_test PRIVATE da_core)
add_test(NAME sha256 COMMAND da_sha256_test)

add_executable(da_base64_test base64_test.cpp)
target_link_libraries(da_base64_test PRIVATE da_core)
add_test(NAME base64 COMMAND da_base64_test)

# CLI smoke tests using the built binary
add_test(NAME cli_help COMMAND archaeologist --help)
add_test(NAME cli_version COMMAND archaeologist --version)
add_test(NAME cli_help_unknown COMMAND archaeologist --help unknown)
add_test(NAME cli_help_password COMMAND archaeologist --help password)
