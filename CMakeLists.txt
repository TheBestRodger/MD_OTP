cmake_minimum_required(VERSION 3.25)
project(MD_OTP)
set(MPROJECT_VERSION 1.0.0)
set(CMAKE_C_STANDARD 99)
#sfind_package(Kerberos REQUIRED)

include(settings.cmake)
include_directories(${INCLUDE_PATH})

# # pkg-config
# find_package(PkgConfig REQUIRED)

# # pkg-config для поиска Kerberos
# pkg_check_modules(KRB5 REQUIRED krb5)
# message(KRB5)
include_directories(/home/myplugin/Plugin/libs/usr/include/mit-krb5)

file(GLOB_RECURSE   SOURCE     ${SOURCE_PATH}/*.c)
file(GLOB_RECURSE   HEADER     ${INCLUDE_PATH}/*.h)
file(GLOB_RECURSE   LIBDIR     /usr/lib/x86_64-linux-gnu/mit-krb5/*.so)

#add_library(OTP SHARED ${HEADER} ${SOURCE})
#set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}/lib)
add_executable(MD_OTP ${HEADER} ${SOURCE})

target_link_libraries(MD_OTP ${LIBDIR})
# target_link_libraries(MD_OTP /lib/x86_64-linux-gnu/mit-krb5/libkrb5.so)
target_link_libraries(MD_OTP /lib/x86_64-linux-gnu/libcom_err.so)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE})