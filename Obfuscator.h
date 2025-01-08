#pragma once

// 异或密钥
constexpr char key1 = '\x01';
constexpr char key2 = '\x02';

constexpr void XorData(char* src, char* dest, int len) {
    for (int i = 0; i < len; i++) {
        dest[i] = src[i] ^ key1 ^ key2;
    }
}

template <int len>
class Obfuscator {
public:
    char obfString[len];

    // 编译时加密存储密文
    constexpr Obfuscator(char* str) : obfString{} {
        XorData(str, obfString, len);
    }

    // 运行时解密至栈中
    char* Decrypt() {
        XorData(obfString, obfString, len);
        return obfString;
    }
};

#define OBF(str) []{ constexpr Obfuscator<sizeof(str)> obf(str); return obf; }().Decrypt()