cmake_minimum_required(VERSION 3.25)
project(MyOTP)
set(MPROJECT_VERSION 1.0.0)
set(CMAKE_C_STANDARD 99)


include_directories(${KRB5})

include_directories(/home/md_otp/test_plugin/include)
add_executable(OTP source/md_otp.c)

target_link_libraries(OTP
/home/md_otp/test_plugin/lib/libOTP.so
/lib/x86_64-linux-gnu/mit-krb5/libkrb5.so
/lib/x86_64-linux-gnu/libcom_err.so
/home/md_otp/test_plugin/lib/libkrad.so
)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE})