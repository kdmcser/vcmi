# 由根 CMakeLists.txt include。
#
# mod 密码的密文与掩码来自环境变量，编译期在这里拆成碎片，
# 连同 VM 的 opcode 置换密钥一起生成到构建目录（不进版本库）。
#
# 为什么要拆：VCMI 源码是全开的，任何写死在源码里的常量都等于公开。
# 拆成交错碎片、每片再各自异或之后，二进制里搜不到完整的密文或掩码，
# 想拿到就必须读懂 lib/filesystem/protect/SecretConstants.cpp 的还原逻辑。
# VM 的置换密钥则每个构建目录随机生成，"逻辑指令 -> 物理字节"的映射
# 同样不落在源码里。

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

set(SHARD_COUNT 4)

# ---- 密文：按字符交错切片 ----
string(LENGTH "${MOD_PASSWORD_ENV}" CIPHER_LENGTH)
math(EXPR CIPHER_MAX_INDEX "${CIPHER_LENGTH} - 1")
set(CIPHER_INDEX 0)
foreach(i RANGE 0 ${CIPHER_MAX_INDEX})
    string(SUBSTRING "${MOD_PASSWORD_ENV}" ${i} 1 CIPHER_CHAR)
    math(EXPR CIPHER_SHARD_INDEX "${CIPHER_INDEX} % ${SHARD_COUNT}")
    string(APPEND CIPHER_SHARD_${CIPHER_SHARD_INDEX} "${CIPHER_CHAR}")
    math(EXPR CIPHER_INDEX "${CIPHER_INDEX} + 1")
endforeach()

# ---- 掩码：十六进制字节流，交错分片后每片异或各自不同的常量 ----
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
    # 下面这几个常量必须与 SecretConstants.cpp 里的 shardKeys 一一对应
    if(MASK_SHARD_INDEX EQUAL 0)
        math(EXPR OBFUSCATED_BYTE "0x${HEX_BYTE} ^ 0x71")
    elseif(MASK_SHARD_INDEX EQUAL 1)
        math(EXPR OBFUSCATED_BYTE "0x${HEX_BYTE} ^ 0x1E")
    elseif(MASK_SHARD_INDEX EQUAL 2)
        math(EXPR OBFUSCATED_BYTE "0x${HEX_BYTE} ^ 0x9B")
    else()
        math(EXPR OBFUSCATED_BYTE "0x${HEX_BYTE} ^ 0x44")
    endif()

    list(APPEND MASK_SHARD_${MASK_SHARD_INDEX} "${OBFUSCATED_BYTE}")
    math(EXPR MASK_BYTE_INDEX "${MASK_BYTE_INDEX} + 1")
endforeach()

# 空碎片补一个占位值，避免生成零长度数组（密文长度会限制实际读取范围）
foreach(shard RANGE 0 3)
    if(NOT CIPHER_SHARD_${shard})
        set(CIPHER_SHARD_${shard} "A")
    endif()
    if(NOT MASK_SHARD_${shard})
        list(APPEND MASK_SHARD_${shard} "0")
    endif()
    string(JOIN ", " MASK_SHARD_${shard}_STR ${MASK_SHARD_${shard}})
endforeach()

math(EXPR MASK_BYTE_COUNT "${MASK_LEN} / 2")

set(GENERATED_DIR "${CMAKE_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${GENERATED_DIR}")

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
