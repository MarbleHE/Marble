#ifndef UHE_UHE_BITHELPERS_H
#define UHE_UHE_BITHELPERS_H


#include <vector>
#include <cmath>
#include <stdexcept>

namespace Marble {


    /// Check if an integer @p a can be expressed in two's complement with @p n bits
    inline bool overflow(long long a, long long n) {
        auto p = std::exp2(n - 1);
        return (a < -p || p - 1 < a);
    }

    /// Helper function to avoid issues with not-quite-accurate-enough doubles
    /// CREDIT: StackOverflow user dgobbi https://stackoverflow.com/a/15327567
    inline int ceil_log2(unsigned long long x) {
        static const unsigned long long t[6] = {
                0xFFFFFFFF00000000ull,
                0x00000000FFFF0000ull,
                0x000000000000FF00ull,
                0x00000000000000F0ull,
                0x000000000000000Cull,
                0x0000000000000002ull
        };

        int y = (((x & (x - 1)) == 0) ? 0 : 1);
        int j = 32;
        int i;

        for (i = 0; i < 6; i++) {
            int k = (((x & t[i]) == 0) ? 0 : j);
            y += k;
            x >>= k;
            j >>= 1;
        }

        return y;
    }

    /// Helper function to avoid issues with not-quite-accurate-enough doubles
    /// CREDIT: StackOverflow user Desmond Hume https://stackoverflow.com/a/11398748
    inline unsigned int floor_log2(uint64_t value) {
        const unsigned int tab64[64] = {
                63, 0, 58, 1, 59, 47, 53, 2,
                60, 39, 48, 27, 54, 33, 42, 3,
                61, 51, 37, 40, 49, 18, 28, 20,
                55, 30, 34, 11, 43, 14, 22, 4,
                62, 57, 46, 52, 38, 26, 32, 41,
                50, 36, 17, 19, 29, 10, 13, 21,
                56, 45, 25, 31, 35, 16, 9, 12,
                44, 24, 15, 8, 23, 7, 6, 5};

        value |= value >> 1;
        value |= value >> 2;
        value |= value >> 4;
        value |= value >> 8;
        value |= value >> 16;
        value |= value >> 32;

        return tab64[((uint64_t) ((value - (value >> 1)) * 0x07EDD5E59A4E28C2)) >> 58];
    }

    /// Convert an integer to two's complement signed binary representation
    std::vector<bool> signed_bits(long value, unsigned int bit_length = 0);

    /// Convert a vector batched bits into a vector of longs
    std::vector<long> bits_to_long(const std::vector<std::vector<long>> &v);


}
#endif //UHE_UHE_BITHELPERS_H
