#pragma once

#include "StdInc.h"
#include "../lib/filesystem/ResourcePath.h"

class CImageMd5Calculator
{
private:
    // Internal structure for MD5 algorithm
    struct MD5Context {
        uint32_t state[4];      // State (ABCD)
        uint32_t count[2];      // Bit counter, 64-bit, low 32 bits first
        ui8 buffer[64];         // Input buffer
    };

    // Internal MD5 functions
    static void init(MD5Context* context);
    static void update(MD5Context* context, const ui8* input, uint32_t inputLen);
    static void final(ui8 digest[16], MD5Context* context);
    static void transform(uint32_t state[4], const ui8 block[64]);

    // Helper functions
    static void encode(ui8* output, const uint32_t* input, uint32_t len);
    static void decode(uint32_t* output, const ui8* input, uint32_t len);

    // Basic operations (as defined in RFC1321)
    static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) | (~x & z);
    }

    static inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
        return (x & z) | (y & ~z);
    }

    static inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ y ^ z;
    }

    static inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) {
        return y ^ (x | ~z);
    }

    // Rotate left operation
    static inline uint32_t rotateLeft(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    // MD5 step operations
    static inline void FF(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
        uint32_t x, uint32_t s, uint32_t ac) {
        a = rotateLeft(a + F(b, c, d) + x + ac, s) + b;
    }

    static inline void GG(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
        uint32_t x, uint32_t s, uint32_t ac) {
        a = rotateLeft(a + G(b, c, d) + x + ac, s) + b;
    }

    static inline void HH(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
        uint32_t x, uint32_t s, uint32_t ac) {
        a = rotateLeft(a + H(b, c, d) + x + ac, s) + b;
    }

    static inline void II(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
        uint32_t x, uint32_t s, uint32_t ac) {
        a = rotateLeft(a + I(b, c, d) + x + ac, s) + b;
    }

	ImagePath getRealImagePath(const ImagePath& imagePath);
	std::string calculateMd5(ui8* data, si64 size);
	std::vector<std::pair<std::unique_ptr<ui8[]>, si64> > readDefJsonImages(const JsonNode & config);
	std::pair<std::unique_ptr<ui8[]>, si64> readOneImage(const ImagePath & imagePath);

public:
	std::string calculate(const ImagePath &imagePath);
	std::string calculate(const AnimationPath & animationPath);
};
