set(pepper_src
    pepper/pepper_provider.cpp
    pepper/os_keychain.cpp
    pepper/machine_bound.cpp
    pepper/encrypted_file.cpp)

add_executable(example_simple simple.cpp ${pepper_src})
target_link_libraries(example_simple PRIVATE aes_cpp::aes_cpp hmac_cpp::hmac_cpp obfy)

add_executable(example_json json_vault.cpp ${pepper_src})
target_link_libraries(example_json PRIVATE aes_cpp::aes_cpp hmac_cpp::hmac_cpp obfy)

add_executable(example_jwr jwr_vault.cpp ${pepper_src})
target_link_libraries(example_jwr PRIVATE aes_cpp::aes_cpp hmac_cpp::hmac_cpp obfy)
