add_executable(vault_tests test_vault.cpp)
target_link_libraries(vault_tests PRIVATE aes_cpp::aes_cpp hmac_cpp::hmac_cpp obfy)
target_compile_options(vault_tests PRIVATE ${PROJECT_COMPILE_OPTIONS})
target_link_options(vault_tests PRIVATE ${PROJECT_LINK_OPTIONS})
add_test(NAME vault_tests COMMAND vault_tests)

add_executable(pepper_tests
    test_pepper.cpp
    ../examples/pepper/pepper_provider.cpp
    ../examples/pepper/os_keychain.cpp
    ../examples/pepper/machine_bound.cpp
    ../examples/pepper/encrypted_file.cpp)
target_include_directories(pepper_tests PRIVATE ../examples/pepper)
target_link_libraries(pepper_tests PRIVATE aes_cpp::aes_cpp hmac_cpp::hmac_cpp obfy)
target_compile_options(pepper_tests PRIVATE ${PROJECT_COMPILE_OPTIONS})
target_link_options(pepper_tests PRIVATE ${PROJECT_LINK_OPTIONS})
if (APPLE)
    target_link_libraries(pepper_tests PRIVATE "-framework Security" "-framework CoreFoundation")
endif()
if (WIN32)
    target_link_libraries(pepper_tests PRIVATE crypt32)
endif()
add_test(NAME pepper_tests COMMAND pepper_tests)
