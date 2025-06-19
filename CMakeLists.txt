cmake_minimum_required(VERSION 3.10)
project(BITSHIELD)

set(CMAKE_CXX_STANDARD 17)
find_package(OpenSSL REQUIRED)

include_directories(include)
add_executable(BITSHIELD
    src/main.cpp
    src/scanner.cpp
    src/utils.cpp
    src/aes.cpp
)




target_include_directories(BITSHIELD PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(BITSHIELD PRIVATE OpenSSL::Crypto)
# Find YARA
find_library(YARA_LIB yara REQUIRED)
find_path(YARA_INCLUDE_DIR yara.h)

# Add include and link directories
target_include_directories(BITSHIELD PRIVATE ${YARA_INCLUDE_DIR})
target_link_libraries(BITSHIELD PRIVATE ${YARA_LIB})

# Copy files to build directory
file(COPY signatures DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
