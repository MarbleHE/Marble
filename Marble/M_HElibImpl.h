
#ifndef UHE_HELIBSCALARIMPL_H
#define UHE_HELIBSCALARIMPL_H

#include "M_HElib.h"
#include "Ctxt.h"
#include <vector>

class Marble::M_HElib::M_HElibImpl {

    /// Type of single bit
    using Bit = Ctxt;

    /// Type of iterator over vector of bits
    using BitIter = vector<Bit>::iterator;

public:

    /// Default destructor
    ~M_HElibImpl() noexcept = default;

    /// Copy constructor
    M_HElibImpl(const M_HElibImpl &x);

    /// Move constructor
    M_HElibImpl(M_HElibImpl &&x) noexcept;

    /// Copy assignment
    M_HElibImpl &operator=(const M_HElibImpl &x);

    /// Move assignment
    M_HElibImpl &operator=(M_HElibImpl &&x) noexcept;

    /// "Real" construtor
    M_HElibImpl(vector<Bit> bits, shared_ptr<const HElibPubKeyFix> pub_key_fix);


    /// Public-key Encryption with same value in all slots
    M_HElibImpl(long n, const shared_ptr<const HElibPubKeyFix> &pub_key_fix, unsigned int bitSize);

    /// Public-key Batched Encryption
    M_HElibImpl(vector<long>, const shared_ptr<const HElibPubKeyFix> &pub_key_fix,
                    unsigned int bitSize);

    /// Secret-key Encryption with same value in all slots
    M_HElibImpl(long n, const shared_ptr<const HElibSecKeyFix> &sec_key_fix, unsigned int bitSize);


    /// Secret-key Batched Encryption
    M_HElibImpl(vector<long>, const shared_ptr<const HElibSecKeyFix> &sec_key_fix,
                    unsigned int bitSize);

    // Decryption
    vector<long> decrypt(const FHESecKey &sec_key, bool negative) const;


    // ARITHMETIC OPERATIONS

    M_HElibImpl &operator+=(const M_HElibImpl &rhs);

    M_HElibImpl &operator+=(const vector<long> &rhs);


    M_HElibImpl &operator-=(const M_HElibImpl &rhs);


    M_HElibImpl &operator*=(const M_HElibImpl &rhs);

    M_HElibImpl &operator*=(const vector<long> &rhs);


    M_HElibImpl &operator++();

    M_HElibImpl &operator--();

    M_HElibImpl operator!() const;

    friend M_HElibImpl operator==(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

    friend M_HElibImpl operator!=(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

    friend M_HElibImpl operator<=(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

    friend M_HElibImpl operator<(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

    friend M_HElibImpl operator>(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

    friend M_HElibImpl operator>=(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

    friend M_HElibImpl operator&&(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

    friend M_HElibImpl operator||(const M_HElibImpl &lhs, const M_HElibImpl &rhs);


    /// SIMD-element manipulation
    M_HElibImpl &rotate(long k);

    /// SIMD vector-internal addition
    M_HElibImpl &internal_add(long interval, long in_interval);

    /// SIMD vector-internal minimum
    M_HElibImpl &internal_minimum_with_index(long interval, long in_interval, long sets, M_HElibImpl &indices);


private:

    /// The public key associated with this number
    shared_ptr<const HElibPubKeyFix> pub_key_fix_;

    /// The underlying "integer" bits (signed, two's complement)
    vector<Bit> bits_;

    /// The log of the scaling, i.e. the value is signed_binary_number(bits_) * pow(2,log_scale_);
    int log_scale_;
};

#endif //UHE_HELIBSCALARIMPL_H
