add_executable(vault_tests test_vault.cpp)
target_link_libraries(vault_tests PRIVATE aes_cpp::aes_cpp hmac_cpp::hmac_cpp obfy)
add_test(NAME vault_tests COMMAND vault_tests)
