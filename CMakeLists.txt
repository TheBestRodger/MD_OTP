cmake_minimum_required(VERSION 3.25)
project(MyOTP)
set(MPROJECT_VERSION 1.0.0)
set(CMAKE_C_STANDARD 99)
#sfind_package(Kerberos REQUIRED)

include(settings.cmake)
include_directories(${INCLUDE_PATH})

# pkg-config
find_package(PkgConfig REQUIRED)

# pkg-config для поиска Kerberos
pkg_check_modules(KRB5 REQUIRED krb5)
message(KRB5)
include_directories(${KRB5})

file(GLOB_RECURSE   SOURCE     ${SOURCE_PATH}/*.c)
file(GLOB_RECURSE   HEADER     ${INCLUDE_PATH}/*.h)

#add_library(OTP SHARED ${HEADER} ${SOURCE})
#set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}/lib)
add_executable(OTP ${HEADER} ${SOURCE})

# Добавьте директории с заголовочными файлами из pkg-config


# Добавьте параметры компоновки (link) из pkg-config
link_directories(/lib/x86_64-linux-gnu)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
target_link_libraries(OTP
libgssapi_krb5.so
libk5crypto.so
libkadm5clnt_mit.so
libkadm5srv_mit.so
libkrb5.so
libgssrpc.so   
libkadm5clnt.so 
libkadm5srv.so      
libkdb5.so        
libkrb5support.so
libcom_err.a
)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE})