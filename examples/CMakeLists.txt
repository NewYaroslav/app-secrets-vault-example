add_executable(example_simple simple.cpp)
target_link_libraries(example_simple PRIVATE aes_cpp::aes_cpp hmac_cpp::hmac_cpp obfy)

add_executable(example_json json_vault.cpp)
target_link_libraries(example_json PRIVATE aes_cpp::aes_cpp hmac_cpp::hmac_cpp obfy)

add_executable(example_jwr jwr_vault.cpp)
target_link_libraries(example_jwr PRIVATE aes_cpp::aes_cpp hmac_cpp::hmac_cpp obfy)
