
#include <intraSlot.h>
#include "M_HElib.h"
#include "M_HElibImpl.h"
#include "debugging.h"

namespace Marble {
    using std::vector;
    using std::unique_ptr;
    using std::shared_ptr;
    using std::make_unique;
    using std::make_shared;



    //region M_HElib interfaces

    // Constructors / Assignment

    M_HElib HElibGenerator::operator()(std::vector<long> v, int bitSize) const {
        return M_HElib(v, sec_key_fix_, bitSize);
    }


    M_HElib HElibGenerator::operator()(std::vector<long> v) const {
        return M_HElib(v, sec_key_fix_, ceil_log2(v[0]));
    }

    M_HElib::M_HElib(unique_ptr<M_HElibImpl> &&pimpl) : impl(std::move(pimpl)) {};



    M_HElib::M_HElib(long n, const shared_ptr<const HElibPubKeyFix> &pub_key_fix, unsigned int max_bits)
            : impl(
            std::make_unique<M_HElibImpl>(n, pub_key_fix, max_bits)) {};

    M_HElib::M_HElib(long n, const shared_ptr<const HElibSecKeyFix> &sec_key_fix, unsigned int max_bits) {
        impl = std::make_unique<M_HElibImpl>(n, sec_key_fix, max_bits);
    };

    M_HElib::M_HElib(vector<long> v, const shared_ptr<const HElibPubKeyFix> &pub_key_fix,
                             unsigned int max_bits) : impl(
            std::make_unique<M_HElibImpl>(v, pub_key_fix, max_bits)) {};

    M_HElib::M_HElib(vector<long> v, const shared_ptr<const HElibSecKeyFix> &sec_key_fix,
                             unsigned int max_bits) : impl(
            std::make_unique<M_HElibImpl>(v, sec_key_fix, max_bits)) {};

    M_HElib::M_HElib(const M_HElib &x) : impl(std::make_unique<M_HElibImpl>(*x.impl)) {
    };

    M_HElib::~M_HElib() = default;

    M_HElib::M_HElib(M_HElib &&x) noexcept = default;

    M_HElib &M_HElib::operator=(const M_HElib &x) {
        impl = std::make_unique<M_HElibImpl>(*x.impl);
        return *this;
    }

    M_HElib &M_HElib::operator=(M_HElib &&x) noexcept {
        impl = std::move(x.impl);
        return *this;
    };


    // Decryption

    vector<long> M_HElib::decrypt(const FHESecKey &sec_key, bool negative) const {
        return impl->decrypt(sec_key, negative);
    }

    // Arithmetic assignment operators

    M_HElib &M_HElib::operator+=(const M_HElib &rhs) {
        *impl += *rhs.impl;
        return *this;
    };

    M_HElib &M_HElib::operator+=(const vector<long> &rhs) {
        *impl += rhs;
        return *this;
    };

    M_HElib &M_HElib::operator-=(const M_HElib &rhs) {
        *impl -= *rhs.impl;
        return *this;
    }

    M_HElib &M_HElib::operator*=(const M_HElib &rhs) {
        *impl *= *rhs.impl;
        return *this;
    }

    M_HElib &M_HElib::operator*=(const vector<long> &rhs) {
        *impl *= rhs;
        return *this;
    }

    // Increment/Decrement

    M_HElib &M_HElib::operator++() {
        impl->operator++();
        return *this;
    }

    M_HElib &M_HElib::operator--() {
        impl->operator--();
        return *this;
    }

    M_HElib &M_HElib::operator!() {
        impl->operator!();
        return *this;
    }

    const M_HElib operator+(const M_HElib &lhs, const M_HElib &rhs) {
        M_HElib t = lhs;
        t += rhs;
        return t;
    }

    const M_HElib operator-(const M_HElib &lhs, const M_HElib &rhs) {
        M_HElib t = lhs;
        t -= rhs;
        return t;
    }

    const M_HElib operator*(const M_HElib &lhs, const M_HElib &rhs) {
        M_HElib t = lhs;
        t *= rhs;
        return t;
    }

    const M_HElib operator<(const M_HElib &lhs, const M_HElib &rhs) {
        M_HElib t = lhs;
        *t.impl = *lhs.impl < *rhs.impl;
        return t;
    }

    const M_HElib operator==(const M_HElib &lhs, const M_HElib &rhs) {
        M_HElib t = lhs;
        *t.impl = *lhs.impl == *rhs.impl;
        return t;
    };

    const M_HElib operator!=(const M_HElib &lhs, const M_HElib &rhs) {
        M_HElib t = lhs;
        *t.impl = *lhs.impl != *rhs.impl;
        return t;
    }

    const M_HElib operator<=(const M_HElib &lhs, const M_HElib &rhs) {
        M_HElib t = lhs;
        *t.impl = *lhs.impl <= *rhs.impl;
        return t;
    }

    const M_HElib operator>(const M_HElib &lhs, const M_HElib &rhs) {
        M_HElib t = lhs;
        *t.impl = *lhs.impl > *rhs.impl;
        return t;
    }

    const M_HElib operator>=(const M_HElib &lhs, const M_HElib &rhs) {
        M_HElib t = lhs;
        *t.impl = *lhs.impl >= *rhs.impl;
        return t;
    }

    const M_HElib operator&&(const M_HElib &lhs, const M_HElib &rhs) {
        M_HElib t = lhs;
        *t.impl = *lhs.impl && *rhs.impl;
        return t;
    }

    const M_HElib operator||(const M_HElib &lhs, const M_HElib &rhs) {
        M_HElib t = lhs;
        *t.impl = *lhs.impl || *rhs.impl;
        return t;
    }

    M_HElib &M_HElib::rotate(long k) {
        impl->rotate(k);
        return *this;
    }

    M_HElib &M_HElib::internal_add(long interval, long in_interval) {
        impl->internal_add(interval, in_interval);
        return *this;
    }

    M_HElib &M_HElib::internal_minimum_with_index(long interval, long in_interval, long sets, M_HElib &indices) {
        impl->internal_minimum_with_index(interval, in_interval, sets, *indices.impl);
        return *this;
    }

    //endregion

    // region GENERATOR

    /// HElib parameters
    static long mValues[][16] = {
            // { p, phi(m),   m,   d, m1, m2, m3,    g1,   g2,   g3, ord1,ord2,ord3,   B, c, slots}
            {2, 48,    105,   12, 3,    35,  0,   71,    76,    0,     2,   2,   0,   25, 2, 4},    //0: 4 slots      (2x2)
            {2, 600,   1023,  10, 11,   93,  0,   838,   584,   0,     10,  6,   0,   25, 2, 60},   //1: 60 slots     (10x6)
            {2, 2304,  4641,  24, 7,    3,   221, 3979,  3095,  3760,  6,   2,   -8,  25, 3, 96},   //2: 96 slots     (6x2x8)
            {2, 5460,  8193,  26, 8193, 0,   0,   46,    0,     0,     210, 0,   0,   25, 3, 210},  //3: 210 slots    (210)
            {2, 8190,  8191,  13, 8191, 0,   0,   39,    0,     0,     630, 0,   0,   25, 3, 639},  //4: 639 slots    (630)
            {2, 10752, 11441, 48, 17,   673, 0,   4712,  2024,  0,     16,  -14, 0,   25, 3, 224},  //5: 224 slots    (16x14)
            {2, 15004, 15709, 22, 23,   683, 0,   4099,  13663, 0,     22,  31,  0,   25, 3, 682},  //6: 682 slots    (22x31)
            {2, 27000, 32767, 15, 31,   7,   151, 11628, 28087, 25824, 30,  6,   -10, 28, 4, 1800}  //7: 1800 slots   (30x6x10)
    };

    HElibGenerator::HElibGenerator(long levels, long slots, unsigned long plaintext_base,
                                   unsigned long r, long sec, long hw, long digits, long candidate_m) {

        unpackSlotEncoding = std::make_shared<vector<zzX>>();
        if (plaintext_base == 2) {
            int prm = -1;
            for (int i = 0; i < 8; ++i) {
                // check if we have a matching set of params available
                if (mValues[i][15] >= slots) {
                    prm = i;
                    cout << "Choosing prm = " << prm << endl;
                    cout << "With levels: " << levels << endl;
                    break;
                }
            }

            if (prm >= 0) {

                long *vals = mValues[prm];
                long p = vals[0];
                //  long phim = vals[1];
                long m = vals[2];

                NTL::Vec<long> mvec;
                append(mvec, vals[4]);
                if (vals[5] > 1) append(mvec, vals[5]);
                if (vals[6] > 1) append(mvec, vals[6]);

                std::vector<long> gens;
                gens.push_back(vals[7]);
                if (vals[8] > 1) gens.push_back(vals[8]);
                if (vals[9] > 1) gens.push_back(vals[9]);

                std::vector<long> ords;
                ords.push_back(vals[10]);
                if (abs(vals[11]) > 1) ords.push_back(vals[11]);
                if (abs(vals[12]) > 1) ords.push_back(vals[12]);

                long B = vals[13];
                long c = vals[14];


                unique_ptr<FHEcontext> context = std::make_unique<FHEcontext>(m, p, /*r=*/r, gens, ords);
                context->bitsPerLevel = B;
                buildModChain(*context, levels, c,/*extraBits=*/8);

                buildUnpackSlotEncoding(*unpackSlotEncoding, *context->ea);

                shared_ptr<FHESecKey> secKey = std::make_shared<FHESecKey>(*context);
                secKey->GenSecKey(/*Hweight=*/hw);
                addSome1DMatrices(*secKey); // compute key-switching matrices
                addFrbMatrices(*secKey);

                // Now that we're done modifying the key, move it to the const member
                unique_ptr<const FHEcontext> const_context(std::move(context));
                sec_key_fix_ = make_shared<HElibSecKeyFix>(std::move(const_context), secKey);

                cout << "Using param set " << prm << endl;
            }

        } else {

            // Find m:
            auto m = static_cast<unsigned long>(FindM(sec, levels, digits, plaintext_base, r, slots, candidate_m));

            // Construct the context
            unique_ptr<FHEcontext> context = std::make_unique<FHEcontext>(m, plaintext_base, r);

            // Generates the chain of moduli (mostly) as described in the BGV cryptosystem (a chain of moduli is used for key switching, a noise managment technique)
            buildModChain(*context, levels);

            // Generate a secret key
            shared_ptr<FHESecKey> sec_key = std::make_shared<FHESecKey>(*context);
            sec_key->GenSecKey(hw);

            // These "Matrices" are part of the public key and are required to support "rotations" between CRT-batched slots
            // It is possible to add more Matrices to speed up computation, but at an extreme memory cost
            // The addSome1DMatrices(...) function generates all Matrices necessary for the rotation operations.
            addSome1DMatrices(*sec_key);


            buildUnpackSlotEncoding(*unpackSlotEncoding, *context->ea);

            // Now that we're done modifying the key, move it to the const member
            unique_ptr<const FHEcontext> const_context(std::move(context));
            sec_key_fix_ = make_shared<HElibSecKeyFix>(std::move(const_context), sec_key);


        }

#ifdef DEBUG_PRINTOUT
        dbgEa = (EncryptedArray *) sec_key_fix_->context->ea;
        dbgKey = &(*sec_key_fix_->sec_key);
#endif


    }


    //endregion
}

