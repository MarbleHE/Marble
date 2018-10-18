#include "M.h"
#include "timer.h"
#include <algorithm>
#include <NTL/BasicThreadPool.h>

namespace Marble {

    // Initialize static members
    M::Mode M::mode = M::Mode::Analysis;
    std::unique_ptr<HElibGenerator> M::gen = nullptr;
    bool  M::requires_bitslicing = false;
    int M::max_multdepth = 0;
    int M::max_slots = 0;

    // Global helpers
    SelectorType sum = {1};
    SelectorType min = {2};
    SelectorType min_with_index = {3};
    SelectorType batched = {-1};


    M &M::operator+=(const M &rhs) {

        if (mode == Mode::HElibEvaluation) {
            enc_if_needed();
            if (rhs.helib_impl == nullptr) {
                M t = rhs;
                t.enc_if_needed();
                *helib_impl += *(t.helib_impl);
            } else {
                *helib_impl += *(rhs.helib_impl);
            }
        }

        for (int i = 0; i < values.size(); ++i) {
            values[i] += rhs.values[i];
        }

        if (!plaintext || !(rhs.plaintext)) {
            // For non-two's-complement, we have a carry out
            // For two's complement, we sign extend before addition
            bitSize = max(rhs.bitSize, bitSize) + 1;

            // Only when both were plaintext can we continue with plaintext
            plaintext = plaintext && rhs.plaintext;

            // If one of them was two's complement, the result will be, too
            twos_complement = twos_complement || rhs.twos_complement;

            // Only when both were plaintext can we continue with plaintext
            plaintext = plaintext && rhs.plaintext;

            // Multiplicative depth:
            multdepth = max(this->multdepth, rhs.multdepth);
            multdepth += int(ceil(log(bitSize) / log(2.0)));
            max_multdepth = max(multdepth, max_multdepth);
        }

        return *this;
    }

    M &M::operator+=(const vector<long> &rhs) {
        int max_rhs_bitSize = 0;
        bool rhs_negative = false;

        // For non-two's-complement, we have a carry out
        // For two's complement, we sign extend before addition
        bitSize = max(max_rhs_bitSize, bitSize) + 1;

        // If one of them was two's complement, the result will be, too
        twos_complement = twos_complement || rhs_negative;

        // When one is plaintext, we can continue with that
        // plaintext = plaintext;

        // Multiplicative depth:
        multdepth += int(ceil(log(bitSize) / log(2.0)));
        max_multdepth = max(multdepth, max_multdepth);

        if (mode == Mode::HElibEvaluation) {
            enc_if_needed();
            *helib_impl += values;
        }

        for (int i = 0; i < values.size(); ++i) {
            values[i] += rhs[i];
            max_rhs_bitSize = max(max_rhs_bitSize, ceil_log2(rhs[i] + 1));
            if (rhs[i] < 0) {
                rhs_negative = true;
            }
        }

        return *this;
    }

    M &M::operator-=(const M &rhs) {
        if (mode == Mode::HElibEvaluation) {
            enc_if_needed();
            if (rhs.helib_impl == nullptr) {
                M t = rhs;
                t.enc_if_needed();
                *helib_impl -= *(t.helib_impl);
            } else {
                *helib_impl -= *(rhs.helib_impl);
            }
        }

        for (int i = 0; i < values.size(); ++i) {
            values[i] -= rhs.values[i];
        }


        if (!plaintext || !(rhs.plaintext)) {
            // For non-two's-complement, we have a carry out
            // For two's complement, we sign extend before addition
            bitSize = max(rhs.bitSize, bitSize) + 1;

            // Only when both were plaintext can we continue with plaintext
            plaintext = plaintext && rhs.plaintext;

            // If one of them was two's complement, the result will be, too
            twos_complement = twos_complement || rhs.twos_complement;

            // Only when both were plaintext can we continue with plaintext
            plaintext = plaintext && rhs.plaintext;

            // Multiplicative depth:
            multdepth = max(this->multdepth, rhs.multdepth);
            multdepth += 2 * int(ceil(log(bitSize) / log(2.0)));
            max_multdepth = max(multdepth, max_multdepth);
        }

        return *this;
    }

    M &M::operator*=(const M &rhs) {
        if (mode == Mode::HElibEvaluation) {
            enc_if_needed();
            if (rhs.helib_impl == nullptr) {
                M t = rhs;
                t.enc_if_needed();
                *helib_impl *= *(t.helib_impl);
            } else {
                *helib_impl *= *(rhs.helib_impl);
            }
        }

        for (int i = 0; i < values.size(); ++i) {
            values[i] *= rhs.values[i];
        }

        if (!plaintext || !(rhs.plaintext)) {

            // For non-two's-complement, we have a carry out
            // For two's complement, we sign extend before addition
            this->bitSize = rhs.bitSize + this->bitSize;

            // If one of them was two's complement, the result will be, too
            this->twos_complement = this->twos_complement || rhs.twos_complement;

            // Only when both were plaintext can we continue with plaintext
            this->plaintext = this->plaintext && rhs.plaintext;

            // Multiplicative depth:
            this->multdepth = max(this->multdepth, rhs.multdepth);
            this->multdepth += int(ceil(log(bitSize) / log(1.5) + log(this->bitSize) / log(2.0)));
            max_multdepth = max(multdepth, max_multdepth);

        }

        return *this;
    }

    M &M::operator*=(vector<long> &rhs) {
        int max_rhs_bitSize = 0;
        bool rhs_negative = false;


        // For non-two's-complement, we have a carry out
        // For two's complement, we sign extend before addition
        int smallerSize = std::min(max_rhs_bitSize, this->bitSize);
        this->bitSize = max_rhs_bitSize + this->bitSize;

        // If one of them was two's complement, the result will be, too
        twos_complement = twos_complement || rhs_negative;

        // When one is plaintext, we can continue with that
        // plaintext = plaintext;

        // Multiplicative depth:
        this->multdepth += int(ceil(log(smallerSize) / log(1.5) + log(this->bitSize) / log(2.0)));
        max_multdepth = max(multdepth, max_multdepth);

        if (mode == Mode::HElibEvaluation) {
            enc_if_needed();
            *helib_impl *= values;
        }

        for (int i = 0; i < values.size(); ++i) {
            values[i] += rhs[i];
            max_rhs_bitSize = max(max_rhs_bitSize, ceil_log2(rhs[i]) + 1);
            if (rhs[i] < 0) {
                rhs_negative = true;
            }
        }

        return *this;
    }


    M &M::operator!() {
        if (!plaintext) {
            this->multdepth += int(ceil(log(this->bitSize) / log(2.0)));
            max_multdepth = max(multdepth, max_multdepth);
            this->bitSize = 1;
            this->twos_complement = false;
            M::requires_bitslicing = true;
        }

        if (mode == Mode::HElibEvaluation) {
            enc_if_needed();
            !(*helib_impl);

        }

        for (auto &v : values) {
            v = !v;
        }
        return *this;
    }

    M operator==(const M &lhs, const M &rhs) {

        M t = lhs;

        if (M::mode == M::Mode::HElibEvaluation) {
            t.enc_if_needed();

            if (rhs.helib_impl == nullptr) {
                M tr = rhs;
                tr.enc_if_needed();
                *t.helib_impl = *t.helib_impl == *tr.helib_impl;
            } else {
                *t.helib_impl = *t.helib_impl == *rhs.helib_impl;
            }
        }

        for (int i = 0; i < t.values.size(); ++i) {
            t.values[i] = lhs.values[i] == rhs.values[i];
        }

        if (!(lhs.plaintext) || !(rhs.plaintext)) {
            M::requires_bitslicing = true;
            t.multdepth = max(lhs.multdepth, rhs.multdepth);
            t.multdepth += int(ceil(log(t.bitSize) / log(2.0)));
            M::max_multdepth = max(t.multdepth, M::max_multdepth);
            t.bitSize = 1;
            t.twos_complement = false;
            t.plaintext = false;
        }

        return t;
    }

    M operator!=(const M &lhs, const M &rhs) {

        M t = lhs;


        if (M::mode == M::Mode::HElibEvaluation) {
            t.enc_if_needed();

            if (rhs.helib_impl == nullptr) {
                M tr = rhs;
                tr.enc_if_needed();
                *t.helib_impl = *t.helib_impl != *tr.helib_impl;
            } else {
                *t.helib_impl = *t.helib_impl != *rhs.helib_impl;
            }
        }

        for (int i = 0; i < t.values.size(); ++i) {
            t.values[i] = lhs.values[i] != rhs.values[i];
        }

        if (!(lhs.plaintext) || !(rhs.plaintext)) {
            M::requires_bitslicing = true;
            t.multdepth = max(lhs.multdepth, rhs.multdepth);
            t.multdepth += int(ceil(log(t.bitSize) / log(2.0)));
            M::max_multdepth = max(t.multdepth, M::max_multdepth);
            t.bitSize = 1;
            t.twos_complement = false;
            t.plaintext = false;
        }

        return t;
    }

    M operator<=(const M &lhs, const M &rhs) {

        M t = lhs;


        if (M::mode == M::Mode::HElibEvaluation) {
            t.enc_if_needed();

            if (rhs.helib_impl == nullptr) {
                M tr = rhs;
                tr.enc_if_needed();
                *t.helib_impl = *t.helib_impl <= *tr.helib_impl;
            } else {
                *t.helib_impl = *t.helib_impl <= *rhs.helib_impl;
            }
        }

        for (int i = 0; i < t.values.size(); ++i) {
            t.values[i] = lhs.values[i] <= rhs.values[i];
        }

        if (!(lhs.plaintext) || !(rhs.plaintext)) {
            M::requires_bitslicing = true;
            t.multdepth = max(lhs.multdepth, rhs.multdepth);
            t.multdepth += int(ceil(log(t.bitSize) / log(2.0)));
            M::max_multdepth = max(t.multdepth, M::max_multdepth);
            t.bitSize = 1;
            t.twos_complement = false;
            t.plaintext = false;
        }

        return t;
    }

    M operator<(const M &lhs, const M &rhs) {

        M t = lhs;

        if (M::mode == M::Mode::HElibEvaluation) {
            t.enc_if_needed();

            if (rhs.helib_impl == nullptr) {
                M tr = rhs;
                tr.enc_if_needed();
                *t.helib_impl = *t.helib_impl < *tr.helib_impl;
            } else {
                *t.helib_impl = *t.helib_impl < *rhs.helib_impl;
            }
        }

        for (int i = 0; i < t.values.size(); ++i) {
            t.values[i] = lhs.values[i] < rhs.values[i];
        }


        if (!(lhs.plaintext) || !(rhs.plaintext)) {
            M::requires_bitslicing = true;
            t.multdepth = max(lhs.multdepth, rhs.multdepth);
            t.multdepth += int(ceil(log(t.bitSize) / log(2.0)));
            M::max_multdepth = max(t.multdepth, M::max_multdepth);
            t.bitSize = 1;
            t.twos_complement = false;
            t.plaintext = false;
        }

        return t;
    }

    M operator>(const M &lhs, const M &rhs) {

        M t = lhs;


        if (M::mode == M::Mode::HElibEvaluation) {
            t.enc_if_needed();

            if (rhs.helib_impl == nullptr) {
                M tr = rhs;
                tr.enc_if_needed();
                *t.helib_impl = *t.helib_impl > *tr.helib_impl;
            } else {
                *t.helib_impl = *t.helib_impl > *rhs.helib_impl;
            }
        }

        for (int i = 0; i < t.values.size(); ++i) {
            t.values[i] = lhs.values[i] > rhs.values[i];
        }

        if (!(lhs.plaintext) || !(rhs.plaintext)) {
            M::requires_bitslicing = true;
            t.multdepth = max(lhs.multdepth, rhs.multdepth);
            t.multdepth += int(ceil(log(t.bitSize) / log(2.0)));
            M::max_multdepth = max(t.multdepth, M::max_multdepth);
            t.bitSize = 1;
            t.twos_complement = false;
            t.plaintext = false;
        }

        return t;
    }

    M operator>=(const M &lhs, const M &rhs) {

        M t = lhs;


        if (M::mode == M::Mode::HElibEvaluation) {
            t.enc_if_needed();

            if (rhs.helib_impl == nullptr) {
                M tr = rhs;
                tr.enc_if_needed();
                *t.helib_impl = *t.helib_impl >= *tr.helib_impl;
            } else {
                *t.helib_impl = *t.helib_impl >= *rhs.helib_impl;
            }
        }

        for (int i = 0; i < t.values.size(); ++i) {
            t.values[i] = lhs.values[i] >= rhs.values[i];
        }

        if (!(lhs.plaintext) || !(rhs.plaintext)) {
            M::requires_bitslicing = true;
            t.multdepth = max(lhs.multdepth, rhs.multdepth);
            t.multdepth += int(ceil(log(t.bitSize) / log(2.0)));
            M::max_multdepth = max(t.multdepth, M::max_multdepth);
            t.bitSize = 1;
            t.twos_complement = false;
            t.plaintext = false;
        }

        return t;
    }

    M operator+(const M &lhs, const M &rhs) {
        M t = lhs;
        t += rhs;
        return t;
    }

    M operator-(const M &lhs, const M &rhs) {
        M t = lhs;
        t -= rhs;
        return t;
    }

    M operator*(const M &lhs, const M &rhs) {
        M t = lhs;
        t *= rhs;
        return t;
    }

    M &M::operator++() {
        M one = M(1, 1, false, true);
        return (*this) += one;

    }

    M &M::operator--() {
        M one = M(1, 1, false, true);
        return (*this) -= one;
    }


    void M::rotate(long k) {
        if (k > 0) {
            std::rotate(values.rbegin(), values.rbegin() + k, values.rend());
        } else {
            k = -k;
            std::rotate(values.begin(), values.begin() + k, values.end());
        }
        if (M::mode == M::Mode::HElibEvaluation) {
            enc_if_needed();
            if (!plaintext) {
                helib_impl->rotate(k);
            }
        }
    }

    void M::batched_sum(long interval, long in_interval) {
        long sets = values.size() / interval;


        if (M::mode == M::Mode::HElibEvaluation) {
            if (!plaintext) {
                enc_if_needed();
                helib_impl->internal_add(interval, in_interval);
            }
        }

        for (long i = 0; i < sets; ++i) {
            for (long j = 1; j < interval; ++j) {
                values[i * interval] += values[i * interval + j];
                values[i * interval + j] = 0;
            }
        }


        if (!plaintext) {
            bitSize = int(ceil(log(interval * ((1 << bitSize) - 1)) / log(2.0)));
            multdepth +=
                    int(ceil(log(bitSize) / log(2.0))
                        + /*final add operation */
                        ceil(log(interval)

                             / log(2.0)));
            max_multdepth = max(multdepth, max_multdepth);
        }
    }

    void M::batched_min(long interval, long in_interval) {

        long sets = in_interval; //values.size() / interval;

        if (M::mode == M::Mode::HElibEvaluation) {
            if (!plaintext) {
                enc_if_needed();
                M t = *this;
                helib_impl->internal_minimum_with_index(interval, in_interval, values.size()/interval, *t.helib_impl);
            }
        }

        long minv = LONG_MAX;
        for (int i = 0; i < values.size(); ++i) {
            if (i % interval == 0 && values[i] < minv) {
                minv = values[i];
            }
            values[i] = 0;
        }
        values[0] = minv;

        if (!plaintext) {
            int levels_per_recursive_calls = int(
                    ceil(log(bitSize) / log(2.0)) /*compare operation */ + 1 /*non-native rot*/);
            int recursive_calls = int(ceil(log(sets) / log(2.0))) + 1;
            multdepth += levels_per_recursive_calls * recursive_calls;
            requires_bitslicing = true;
            max_multdepth = max(multdepth, max_multdepth);
        }

    }


    void M::batched_min_with_index(long interval, long in_interval, M &indices) {

        long sets = values.size() / interval;

        if (M::mode == M::Mode::HElibEvaluation) {
            if (!plaintext) {
                enc_if_needed();
                indices.enc_if_needed();
                helib_impl->internal_minimum_with_index(interval, in_interval, values.size()/interval , *indices.helib_impl);
            }

        }

        long min = LONG_MAX;
        long index = -1;
        for (int i = 0; i < values.size(); ++i) {
            if (i % interval == 0 && values[i] < min) {
                min = values[i];
                index = i;
            }
            values[i] = 0;
        }
        values[0] = min;
        indices.values[0] = indices.values[index];

        if (!plaintext) {
            requires_bitslicing = true;
            int levels_per_recursive_calls = int(
                    ceil(log(bitSize) / log(2.0)) /*compare operation */ + 1 /*non-native rot*/);
            int recursive_calls = int(ceil(log(sets) / log(2.0))) + 1;
            multdepth += levels_per_recursive_calls * recursive_calls;
            indices.multdepth += log(sets) / log(2.0);

            max_multdepth = max(indices.multdepth, max_multdepth);
            max_multdepth = max(multdepth, max_multdepth);
        }


    }

    M &M::fold(std::function<M(M, M)> f, int interval, int in_interval) {
        if (interval == -1) {
            interval = 1;
        }

        if (in_interval == -1) {
            in_interval = 1;
        }

        // rotate down by half, then apply f to combine values
        while(interval > 1) {
            M t = *this;
            t.rotate(interval / 2);
            *this = f(*this,t);
            interval = interval / 2;
        }

        return *this;

    }

    M &M::fold(SelectorType s, int interval, int in_interval) {
        if (interval == -1) {
            interval = 1;
        }

        if (in_interval == -1) {
            in_interval = 1;
        }

        if (s.x == 1) {
            batched_sum(interval, in_interval);
        } else if (s.x == 2) {
            batched_min(interval, in_interval);
        }

        return *this;
    }

    M &M::fold(SelectorType s, M &indices, int interval, int in_interval) {
        if (interval == -1) {
            interval = 1;
        }

        if (in_interval == -1) {
            in_interval = 1;
        }

        if (indices.size() <= values.size()) {
            // Generate a matching index
            vector<long> ind(values.size(), 0);
            int counter = 0;
            for (int i = 0; i < ind.size(); ++i) {
                if(i % interval < in_interval) {
                    ind[i] = counter++;
                }
            }
            int bS = ceil_log2(ind.size()) + 1;
            indices = encode(batched, ind, bS, false);
        }


        assert(s.x == 3);

        batched_min_with_index(interval, in_interval, indices);

        return *this;
    }


    M encode(SelectorType batched, long value, int bitSize, bool twos_complement) {
        assert(bitSize > 0);
        return M(value, bitSize, twos_complement, true);

    }

    M encrypt(SelectorType batched, long value, int bitSize, bool twos_complement) {
        assert(bitSize > 0);
        return M(value, bitSize, twos_complement, false);
    }

    M encrypt(SelectorType batched, vector<int> values, int bitSize, bool twos_complement) {
        vector<long> v(values.size());
        for (int i = 0; i < values.size(); ++i) {
            v[i] = values[i];
        }
        return encrypt(batched, v, bitSize, twos_complement);
    }

    M encode(SelectorType batched, vector<long> values, int bitSize, bool twos_complement) {
        assert(bitSize > 0);
        return M(values, bitSize, twos_complement, true);
    }

    M encode(SelectorType batched, vector<int> values, int bitSize, bool twos_complement) {
        vector<long> v(values.size());
        for (int i = 0; i < values.size(); ++i) {
            v[i] = values[i];
        }
        return encode(batched, v, bitSize, twos_complement);
    }

    M encrypt(SelectorType batched, vector<long> values, int bitSize, bool twos_complement) {
        assert(bitSize > 0);
        return M(values, bitSize, twos_complement, false);
    }

    M encrypt(SelectorType batched, vector<bool> values, int bitSize, bool twos_complement) {
        vector<long> v(values.size());
        for (int i = 0; i < values.size(); ++i) {
            v[i] = values[i];
        }
        return encrypt(SelectorType(), v, bitSize, twos_complement);
    }

    M encrypt(long value, int bitSize, bool twos_complement) {
        return M(value, bitSize, twos_complement, false);
    }


    vector<M> encrypt(vector<long> values, int bitSize, bool twos_complement) {
        vector<M> vs;
        for (int i = 0; i < values.size(); ++i) {
            M t = M(values[i], bitSize, twos_complement, false);
            vs.emplace_back(t);
        }
        return vs;
    }

    vector<M> encrypt(vector<bool> values, int bitSize, bool twos_complement) {
        vector<long> v(values.size());
        for (int i = 0; i < values.size(); ++i) {
            v[i] = values[i];
        }
        return encrypt(v, bitSize, twos_complement);
    }

    /// Will make sure that this has a valid impl
    /// If plaintext, will use encode, otherwise will use encrypt
    void M::enc_if_needed() {
        if (M::mode == M::Mode::HElibEvaluation) {
            if (helib_impl == nullptr) {
                helib_impl = std::make_unique<M_HElib>((*gen)(values, bitSize));
            }
        }
    }

    M::M(long i) {
        this->values = std::vector<long>(1, i);
        this->bitSize = ceil_log2(i) + 1;
        this->twos_complement = (i < 0);
        this->plaintext = true;
        this->multdepth = 0;
    }

    M::M() {
        this->values = std::vector<long>(1, 0);
        this->bitSize = 1;
        this->twos_complement = false;
        this->plaintext = true;
        this->multdepth = 0;
    }

    M::M(long value, int bitSize, bool twos_complement, bool plaintext) {
        this->values = std::vector<long>(1, value);
        this->bitSize = bitSize;
        this->twos_complement = twos_complement;
        this->plaintext = plaintext;
        this->multdepth = 0;

        if (!plaintext && mode == Mode::HElibEvaluation) {
            helib_impl = std::make_unique<M_HElib>((*gen)(value, bitSize));
        }
    }

    M::M(vector<long> values, int bitSize, bool twos_complement, bool plaintext) {
        this->values = values;
        this->bitSize = bitSize;
        this->twos_complement = twos_complement;
        this->plaintext = plaintext;
        this->multdepth = 0;
        this->max_slots = max(max_slots, (int) values.size());

        if (!plaintext && mode == Mode::HElibEvaluation) {
            helib_impl = std::make_unique<M_HElib>((*gen)(values, bitSize));
        }
    }

    M::M(const M &other) {
        if (other.helib_impl != nullptr) {
            helib_impl = std::make_unique<M_HElib>(*other.helib_impl);
        }
        multdepth = other.multdepth;
        bitSize = other.bitSize;
        plaintext = other.plaintext;
        values = other.values;
        twos_complement = other.twos_complement;
    }

    M::M(M &&other) : helib_impl(std::move(other.helib_impl)) {
        multdepth = other.multdepth;
        bitSize = other.bitSize;
        plaintext = other.plaintext;
        values = other.values;
        twos_complement = other.twos_complement;
    };


    M &M::operator=(const M &other) {
        if (other.helib_impl != nullptr) {
            helib_impl = std::make_unique<M_HElib>(*other.helib_impl);
        }
        multdepth = other.multdepth;
        bitSize = other.bitSize;
        plaintext = other.plaintext;
        values = other.values;
        twos_complement = other.twos_complement;
        return *this;
    }

    M &M::operator=(M &&other) {
        helib_impl = std::move(other.helib_impl);
        multdepth = other.multdepth;
        bitSize = other.bitSize;
        plaintext = other.plaintext;
        values = other.values;
        twos_complement = other.twos_complement;
        return *this;
    }

    M &M::operator=(long i) {
        this->values = std::vector<long>(1, i);
        this->bitSize = ceil_log2(i) + 1;
        this->twos_complement = (i < 0);
        this->plaintext = true;
        this->multdepth = 0;

        return *this;
    }

    M &M::operator=(bool b) {
        *this = encrypt(SelectorType(), b, 1, false);
        return *this;
    }

    M &M::operator=(int i) {
        *this = encrypt(SelectorType(), i, 32, true);
        return *this;
    }

    int M::size() {
        return values.size();
    }

    void M::reset_counts() {
        M::max_multdepth = 0;
        M::max_slots = 0;
    }

    void M::analyse(std::function<void()> f) {
        M::mode = M::Mode::Analysis;
        M::reset_counts();
        f();
        cout << "Function requires multdepth: " << M::max_multdepth;
        cout << " and at least " << M::max_slots << " slots." << endl;
    }

    void M::evaluate(std::function<void()> f) {
        // First run the analysis, but silently
        M::reset_counts();
        M::mode = M::Mode::SilentAnalysis;
        f();

        if (M::requires_bitslicing) {
            if (M::max_multdepth > 60 && M::max_slots > 60) {
                cout << "Error: Computation multiplicative depth is too large for feasible evaluation!" << endl;
                assert(0);
            } else {
                M::gen = std::make_unique<HElibGenerator>(M::max_multdepth, M::max_slots);
            }

            M::mode = M::Mode::HElibEvaluation;
            NTL::SetNumThreads(std::thread::hardware_concurrency());
        }
        M::reset_counts();

        // Benchmarking (single iteration only, because it might be very slow)
        timespec startTime = gettime();
        f();
        cout << "Function executed in: " << time_diff(startTime, gettime()) << "ms." << endl;
    }

    void output(M value, string msg, int slot) {
        if (M::mode == M::Mode::Analysis) {
            cout << "Output " << msg << ":" << endl;
            cout << "Multiplicative depth: " << value.multdepth << endl;
            cout << "Bitsize: " << value.bitSize << endl;
            if (slot >= 0) {
                cout << "(Plaintext) value at " << slot << ": " << value.values[slot] << endl;
            } else {
                cout << "(Plaintext) value: " << value.values << endl;
            }
        } else if (M::mode == M::Mode::HElibEvaluation) {
            value.enc_if_needed();
            vector<long> plaintexts = (*(M::gen))(*value.helib_impl, value.twos_complement);
            if (value.size() > 1) {
                cout << plaintexts << " (" << msg << ")" << endl;
                //cout << value.values << " (" << msg << " plaintexts)" << endl;
            } else {
                cout << plaintexts[0] << " (" << msg << ")" << endl;
            }
        }
    }

}
