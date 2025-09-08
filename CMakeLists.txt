cmake_minimum_required(VERSION 3.14)
project(app_secrets_vault_example LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Disable tests/examples in third-party libs
set(AES_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(HMACCPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(HMACCPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(OBFY_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(OBFY_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

add_subdirectory(third_party/aes-cpp)
add_subdirectory(third_party/hmac-cpp)
add_subdirectory(third_party/obfy)

# nlohmann json single include
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/json/single_include/nlohmann)

enable_testing()

add_subdirectory(examples)
add_subdirectory(test)
