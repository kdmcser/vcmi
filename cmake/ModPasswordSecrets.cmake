# 由根 CMakeLists.txt include。
#
# mod 密码的密文与掩码来自环境变量，编译期在这里变换后写入构建目录（不进版本库）。
#
# 为什么要变换：VCMI 源码是全开的，任何写死在源码或明文躺在二进制里的材料都等于公开。
# 这里做两层：
#   1. 材料按字符/字节交错切成 4 片，密文片存的是 base64 字母表下标（不是字符本身），
#      掩码片存的是异或过的值 —— 二进制里既没有可打印的密文片段，也没有掩码原文；
#   2. 每片的异或键在本构建目录首次配置时随机生成并固定（secret_keys.cmake），
#      不落在源码里。
# 想拿到原始材料，必须读懂 lib/filesystem/protect/SecretConstants.cpp 的还原逻辑，
# 再把这些键从二进制里找出来。
#
# VM 的 opcode 置换密钥同理："逻辑指令 -> 物理字节"的映射每个构建目录一份随机。

set(MOD_PASSWORD_ENV $ENV{MOD_PASSWORD})
if(NOT MOD_PASSWORD_ENV)
    message(FATAL_ERROR "环境变量 MOD_PASSWORD 未设置，无法编译")
endif()
if(NOT MOD_PASSWORD_ENV MATCHES "^[A-Za-z0-9+/=]+$")
    message(FATAL_ERROR "MOD_PASSWORD 必须是 base64 字符串（只允许 A-Z a-z 0-9 + / =）")
endif()

set(MOD_PASSWORD_MASK_VALUE $ENV{MOD_PASSWORD_MASK})
if(NOT MOD_PASSWORD_MASK_VALUE)
    message(FATAL_ERROR "环境变量 MOD_PASSWORD_MASK 未设置")
endif()

# 必须与 PasswordProgram.cpp 里 base64Decode 用的那张表一致
set(BASE64_ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

set(SHARD_COUNT 4)

set(GENERATED_DIR "${CMAKE_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${GENERATED_DIR}")

# ---- 每构建目录随机的变换键：首次配置时生成，之后固定不变 ----
# 碎片是用这些键变换出来的，键若每次配置都重新随机，旧碎片就对不上了。
set(SECRET_KEYS_FILE "${GENERATED_DIR}/secret_keys.cmake")
if(NOT EXISTS "${SECRET_KEYS_FILE}")
    set(GENERATED_KEY_TEXT "# 由 cmake/ModPasswordSecrets.cmake 首次配置时生成，之后固定不变。\n")
    foreach(shard RANGE 0 3)
        string(RANDOM LENGTH 2 ALPHABET "0123456789abcdef" CIPHER_KEY_BYTE)
        string(APPEND GENERATED_KEY_TEXT "set(SECRET_CIPHER_KEY_${shard} 0x${CIPHER_KEY_BYTE})\n")
    endforeach()
    foreach(shard RANGE 0 3)
        string(RANDOM LENGTH 2 ALPHABET "0123456789abcdef" MASK_KEY_BYTE)
        string(APPEND GENERATED_KEY_TEXT "set(SECRET_MASK_KEY_${shard} 0x${MASK_KEY_BYTE})\n")
    endforeach()
    file(WRITE "${SECRET_KEYS_FILE}" "${GENERATED_KEY_TEXT}")
endif()
include("${SECRET_KEYS_FILE}")

# ---- 密文：按字符交错切片，每片存 base64 字母表下标（填充符 '=' 记为 64） ----
string(LENGTH "${MOD_PASSWORD_ENV}" CIPHER_LENGTH)
math(EXPR CIPHER_MAX_INDEX "${CIPHER_LENGTH} - 1")
set(CIPHER_INDEX 0)
foreach(i RANGE 0 ${CIPHER_MAX_INDEX})
    string(SUBSTRING "${MOD_PASSWORD_ENV}" ${i} 1 CIPHER_CHAR)

    string(FIND "${BASE64_ALPHABET}" "${CIPHER_CHAR}" CIPHER_VALUE)
    if(CIPHER_VALUE EQUAL -1)
        if(NOT CIPHER_CHAR STREQUAL "=")
            message(FATAL_ERROR "MOD_PASSWORD 含非法 base64 字符 '${CIPHER_CHAR}'")
        endif()
        set(CIPHER_VALUE 64)
    endif()

    math(EXPR CIPHER_SHARD_INDEX "${CIPHER_INDEX} % ${SHARD_COUNT}")
    if(CIPHER_SHARD_INDEX EQUAL 0)
        math(EXPR OBFUSCATED_VALUE "${CIPHER_VALUE} ^ ${SECRET_CIPHER_KEY_0}")
    elseif(CIPHER_SHARD_INDEX EQUAL 1)
        math(EXPR OBFUSCATED_VALUE "${CIPHER_VALUE} ^ ${SECRET_CIPHER_KEY_1}")
    elseif(CIPHER_SHARD_INDEX EQUAL 2)
        math(EXPR OBFUSCATED_VALUE "${CIPHER_VALUE} ^ ${SECRET_CIPHER_KEY_2}")
    else()
        math(EXPR OBFUSCATED_VALUE "${CIPHER_VALUE} ^ ${SECRET_CIPHER_KEY_3}")
    endif()

    list(APPEND CIPHER_SHARD_${CIPHER_SHARD_INDEX} "${OBFUSCATED_VALUE}")
    math(EXPR CIPHER_INDEX "${CIPHER_INDEX} + 1")
endforeach()

# ---- 掩码：十六进制字节流，交错分片后每片异或各自的键 ----
string(LENGTH "${MOD_PASSWORD_MASK_VALUE}" MASK_LEN)
if(MASK_LEN LESS 2)
    message(FATAL_ERROR "MOD_PASSWORD_MASK 长度非法：${MASK_LEN}")
endif()

math(EXPR MOD_RESULT "${MASK_LEN} % 2")
if(NOT MOD_RESULT EQUAL 0)
    message(FATAL_ERROR "MOD_PASSWORD_MASK 长度非法：${MASK_LEN}（必须是偶数）")
endif()

math(EXPR MASK_MAX_INDEX "${MASK_LEN} - 2")
set(MASK_BYTE_INDEX 0)
foreach(i RANGE 0 ${MASK_MAX_INDEX} 2)
    string(SUBSTRING "${MOD_PASSWORD_MASK_VALUE}" ${i} 2 HEX_BYTE)
    string(TOUPPER "${HEX_BYTE}" HEX_BYTE)
    if(NOT HEX_BYTE MATCHES "^[0-9A-F][0-9A-F]$")
        message(FATAL_ERROR "MOD_PASSWORD_MASK 含非法十六进制字节 '${HEX_BYTE}'")
    endif()

    math(EXPR MASK_SHARD_INDEX "${MASK_BYTE_INDEX} % ${SHARD_COUNT}")
    if(MASK_SHARD_INDEX EQUAL 0)
        math(EXPR OBFUSCATED_BYTE "0x${HEX_BYTE} ^ ${SECRET_MASK_KEY_0}")
    elseif(MASK_SHARD_INDEX EQUAL 1)
        math(EXPR OBFUSCATED_BYTE "0x${HEX_BYTE} ^ ${SECRET_MASK_KEY_1}")
    elseif(MASK_SHARD_INDEX EQUAL 2)
        math(EXPR OBFUSCATED_BYTE "0x${HEX_BYTE} ^ ${SECRET_MASK_KEY_2}")
    else()
        math(EXPR OBFUSCATED_BYTE "0x${HEX_BYTE} ^ ${SECRET_MASK_KEY_3}")
    endif()

    list(APPEND MASK_SHARD_${MASK_SHARD_INDEX} "${OBFUSCATED_BYTE}")
    math(EXPR MASK_BYTE_INDEX "${MASK_BYTE_INDEX} + 1")
endforeach()

# 空碎片补一个占位值，避免生成零长度数组（实际读取范围由长度常量限制）
foreach(shard RANGE 0 3)
    if(NOT CIPHER_SHARD_${shard})
        list(APPEND CIPHER_SHARD_${shard} "0")
    endif()
    if(NOT MASK_SHARD_${shard})
        list(APPEND MASK_SHARD_${shard} "0")
    endif()
    string(JOIN ", " CIPHER_SHARD_${shard}_STR ${CIPHER_SHARD_${shard}})
    string(JOIN ", " MASK_SHARD_${shard}_STR ${MASK_SHARD_${shard}})
endforeach()

string(JOIN ", " CIPHER_SHARD_KEYS_STR
    ${SECRET_CIPHER_KEY_0} ${SECRET_CIPHER_KEY_1} ${SECRET_CIPHER_KEY_2} ${SECRET_CIPHER_KEY_3})
string(JOIN ", " MASK_SHARD_KEYS_STR
    ${SECRET_MASK_KEY_0} ${SECRET_MASK_KEY_1} ${SECRET_MASK_KEY_2} ${SECRET_MASK_KEY_3})

math(EXPR MASK_BYTE_COUNT "${MASK_LEN} / 2")

configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/secrets.h.in"
    "${GENERATED_DIR}/secrets.h"
    @ONLY
)

# ---- VM 的 opcode 置换密钥：首次配置时随机生成，同一构建目录之后固定不变 ----
set(VM_KEY_HEADER "${GENERATED_DIR}/vm_key.h")
if(NOT EXISTS "${VM_KEY_HEADER}")
    string(RANDOM LENGTH 2 ALPHABET "0123456789abcdef" VM_KEY_0)
    string(RANDOM LENGTH 2 ALPHABET "0123456789abcdef" VM_KEY_1)
    string(RANDOM LENGTH 2 ALPHABET "0123456789abcdef" VM_KEY_X)
    configure_file(
        "${CMAKE_CURRENT_LIST_DIR}/vm_key.h.in"
        "${VM_KEY_HEADER}"
        @ONLY
    )
endif()
