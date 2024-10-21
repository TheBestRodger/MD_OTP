cmake_minimum_required(VERSION 3.25)
project(MyOTP)
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
#include_directories(/home/md_otp/3th/krad)

file(GLOB_RECURSE   SOURCE     ${SOURCE_PATH}/*.c)
file(GLOB_RECURSE   HEADER     ${INCLUDE_PATH}/*.h)
#file(GLOB_RECURSE   LIBDIR     /home/myplugin/Plugin/libs/usr/lib/x86_64-linux-gnu/mit-krb5/*.so)

#add_library(OTP SHARED ${HEADER} ${SOURCE})
#set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}/lib)
add_library(OTP SHARED ${HEADER} ${SOURCE} )

target_link_libraries(OTP /lib/x86_64-linux-gnu/mit-krb5/libkrb5.so)
target_link_libraries(OTP /lib/x86_64-linux-gnu/libcom_err.so)
target_link_libraries(OTP /home/md_otp/test_plugin/lib/libkrad.so)
target_link_libraries(OTP /usr/lib/x86_64-linux-gnu/libattr.a)
#set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE})



set(LIBRARY_OUTPUT_PATH /home/md_otp/test_plugin/lib)#${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE})