# Путь к заголовочным файлам
message(Settings " CMAKE_SOURCE_DIR")
set(INCLUDE_PATH ${CMAKE_SOURCE_DIR}/include)

# Путь к искодным текстам программ
set(SOURCE_PATH ${CMAKE_SOURCE_DIR}/source)

# Путь к собранным исполняемым модулям
set(BIN_PATH ${CMAKE_SOURCE_DIR}/bin)

# Путь к собранным статическим библиотекам
set(LIB_PATH ${CMAKE_SOURCE_DIR}/libs)

set(KRB5_HEADERS /usr/include/mit-krb5)
set(KRB5_LIBS /usr/lib/x86_64-linux-gnu/mit-krb5)