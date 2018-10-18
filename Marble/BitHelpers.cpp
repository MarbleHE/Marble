#include <climits>

#include "BitHelpers.h"
#include <stdexcept>
#include <vector>

namespace Marble {
    std::pair<long, int> find_log_scale(double d, unsigned int max_bits) {
        // The exponent has at most 11 bits + some bias, so should fit into int
        if (d != 0) {
            auto log_scale = static_cast<int>(std::floor(std::log2(std::abs(d))));

            // Keep as many significant digits as we can
            d = d / exp2(log_scale); //N.B. log_scale might be negative!
            auto x = static_cast<long long>(d * exp2(max_bits - 1)); //truncate
            log_scale -= (max_bits - 1); //adjust scaling

            // Now we might actually have something like 100100000 with too many zeros, so let's reduce it!
            while (((x >> 1) << 1) == x) {
                x = x >> 1;
                log_scale += 1;
            }
            return std::make_pair(x, log_scale);
        } else { // d == 0
            return std::make_pair(0, 0);
        }

    }


    std::vector<long> bits_to_long(const std::vector<std::vector<long>> &v) {
        std::vector<long> ret;
        if (!v.empty()) {
            ret = std::vector<long>(v[0].size(), 0);
            // non-sign bits
            for (std::vector<long>::size_type i = 0;
                 i < v.size() - 1; ++i) {
                for (std::vector<long>::size_type k = 0; k < v[i].size(); ++k) {
                    // We are now looking at bit i of slot k
                    ret[k] += (v[i][k] != 0) * exp2(i);
                }
            }
            // sign bit
            auto i = v.size() - 1;
            for (std::vector<long>::size_type k = 0; k < v[i].size(); ++k) {
                // We are now looking at the sign bit of slot k
                ret[k] -= (v[i][k] != 0) * exp2(i);
            }
        }
        return ret;
    }

    std::vector<bool> signed_bits(long value, unsigned int bit_length) {
        if (bit_length == 0) {
            if (value < 0) {
                bit_length = static_cast<unsigned int>(ceil_log2(abs(value)) + 1);
            } else if (value == 0) {
                bit_length = 1;
            } else /* value > 0 */ {
                bit_length = static_cast<unsigned int>(ceil_log2(value + 1) + 1);
            }
        }
        if (overflow(value, bit_length)) {
            throw std::domain_error("Not enough bits to represent value");
        } else {
            std::vector<bool> bits(bit_length, 0);
            // sign bit
            if (value < 0) {
                bits[bit_length - 1] = 1;
                value += exp2(bit_length - 1);
            }
            // non-sign bits
            for (std::vector<bool>::size_type i = 0; i < bit_length - 1; ++i) {
                bits[i] = value % 2;
                value /= 2;
            }
            return bits;
        }
    }
}