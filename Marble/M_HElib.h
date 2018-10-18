#ifndef UHE_UHE_HELIB_H
#define UHE_UHE_HELIB_H

#include <vector>
#include <memory>

#include "FHE.h"
#include "BitHelpers.h"

namespace Marble {
    // Forward declarations of helper classes defined below

    class HElibPubKeyFix;

    class HElibSecKeyFix;

    class HElibGenerator;

    /// An HElib-encrypted scalar that behaves like a built-in numerical type as much as possible
    /// The closes analogy would be a float, however there are some subtle differences
    /// It encodes numbers as follows:
    /// There is a (plaintext) scaling factor s
    /// There is a (bit-wise encrypted) integer z, represented in two's complement
    /// The number of bits in z can vary, and the number of bits is public
    /// The value of the HElibScalar is z * 2^s
    /// Since the number of bits in z and the plaintext s are leaked,
    /// some information about the size of the number is revealed
    /// Where this is not acceptable, it is possible to fix the scaling factor
    /// and number of bits used during encryption.
    /// Slightly technical remark:
    /// During computations these numbers might change again
    /// but this change is information leaked by the 'circuit', not the encryption
    /// During computation, no bits are discarded and no rounding occurs
    /// Instead, multiplying e.g. a number where z is 8 bits with one where z is 16 bits
    /// will result in a 24-bit z in the result
    /// This is not the most efficient approach, however it simplifies reasoning about these numbers quite drastically
    /// This class also supports "batching", i.e. it internally contains many different slots that all represent a different number
    /// In this case, all slots have the same number of bits and the same scaling factor
    class M_HElib {
    public:
        /// Destructor
        ~M_HElib() noexcept;

        /// Copy constructor
        M_HElib(const M_HElib &x);

        /// Move constructor
        M_HElib(M_HElib &&x) noexcept;

        /// Copy assignment
        M_HElib &operator=(const M_HElib &x);

        /// Move assignment
        M_HElib &operator=(M_HElib &&x) noexcept;

        /// Addition
        M_HElib &operator+=(const M_HElib &rhs);

        /// Addition with Plaintext
        M_HElib &operator+=(const vector<long> &rhs);

        /// Subtraction
        M_HElib &operator-=(const M_HElib &rhs);

        /// Multiplication
        M_HElib &operator*=(const M_HElib &rhs);

        /// Multiplication
        M_HElib &operator*=(const vector<long> &rhs);


        /// Increment operator
        M_HElib &operator++();

        /// Decrement operator
        M_HElib &operator--();

        /// Increment operator
        M_HElib operator++(int) {
            auto tmp = *this;
            operator++();
            return tmp;
        }

        /// Decrement operator
        M_HElib operator--(int) {
            auto tmp = *this;
            operator--();
            return tmp;
        }


        /// SIMD-element manipulation
        M_HElib &rotate(long k);

        /// SIMD vector-internal addition
        M_HElib &internal_add(long interval, long in_interval);

        /// SIMD vector-internal minimum
        M_HElib &internal_minimum_with_index(long interval, long in_interval, long sets, M_HElib &indices);


        /// Logical negation operator
        M_HElib &operator!();

        friend const M_HElib operator+(const M_HElib &lhs, const M_HElib &rhs);

        friend const M_HElib operator-(const M_HElib &lhs, const M_HElib &rhs);

        friend const M_HElib operator*(const M_HElib &lhs, const M_HElib &rhs);

        friend const M_HElib operator==(const M_HElib &lhs, const M_HElib &rhs);


        friend const M_HElib operator!=(const M_HElib &lhs, const M_HElib &rhs);

        friend const M_HElib operator<(const M_HElib &lhs, const M_HElib &rhs);

        friend const M_HElib operator<=(const M_HElib &lhs, const M_HElib &rhs);

        friend const M_HElib operator>(const M_HElib &lhs, const M_HElib &rhs);

        friend const M_HElib operator>=(const M_HElib &lhs, const M_HElib &rhs);

        friend const M_HElib operator&&(const M_HElib &lhs, const M_HElib &rhs);

        friend const M_HElib operator||(const M_HElib &lhs, const M_HElib &rhs);

    private:
        friend class HElibGenerator;

        // "Real" constructors


        M_HElib(long n, const std::shared_ptr<const HElibPubKeyFix> &pub_key_fix, unsigned int max_bits);

        M_HElib(long n, const std::shared_ptr<const HElibSecKeyFix> &sec_key_fix, unsigned int max_bits);


        M_HElib(std::vector<long> v, const std::shared_ptr<const HElibPubKeyFix> &pub_key_fix,
                    unsigned int max_bits);

        M_HElib(std::vector<long> v, const std::shared_ptr<const HElibSecKeyFix> &sec_key_fix,
                    unsigned int max_bits);

        class M_HElibImpl;

        friend M_HElibImpl operator!=(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

        friend M_HElibImpl operator==(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

        friend M_HElibImpl operator!=(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

        friend M_HElibImpl operator<=(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

        friend M_HElibImpl operator<(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

        friend M_HElibImpl operator>(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

        friend M_HElibImpl operator>=(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

        friend M_HElibImpl operator&&(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

        friend M_HElibImpl operator||(const M_HElibImpl &lhs, const M_HElibImpl &rhs);

        explicit M_HElib(std::unique_ptr<M_HElibImpl> &&pimpl);

        // Decryption
        std::vector<long> decrypt(const FHESecKey &sec_key, bool negative) const;

        // Data members

        std::unique_ptr<M_HElibImpl> impl;

    };

    // Because HElib likes to use references where it shouldn't,
    // we need to bundle all this stuff because freeing one of them
    // can lead to dangling references in the others :(
    class HElibPubKeyFix {
    public:
        /// The FHEcontext, which the FHESecKey has a reference to
        const std::unique_ptr<const FHEcontext> context;

        /// The FHEPubKey which can be used to encrypt
        const std::shared_ptr<const FHEPubKey> pub_key;

        /// Destructor
        virtual ~HElibPubKeyFix() = default;

        /// Simple constructor
        HElibPubKeyFix(std::unique_ptr<const FHEcontext> c, std::shared_ptr<const FHEPubKey> p) :
                context(std::move(c)), pub_key(p) {};
    };

    class HElibSecKeyFix : public HElibPubKeyFix {
    public:
        /// The FHESecKey which is used to encrypt/decrypt
        const std::shared_ptr<const FHESecKey> sec_key;

        /// Simple constructor
        HElibSecKeyFix(unique_ptr<const FHEcontext> c, shared_ptr<const FHESecKey> s) :
                HElibPubKeyFix(std::move(c), static_pointer_cast<const FHEPubKey>(s)), sec_key(s) {};

    };


    class HElibGenerator {
    public:

        /***
        * @brief Setup FHE context and keys.
        *
        *
        * @param	levels			The required supported multiplicative depth. Will usually be matched exactly.
        *
        * @param	slots			Minimum number of SIMD slots (using CRT batching) that the structure should offer.
        *							Note that the actual number of slots will usually be higher, sometimes significantly so!
        *
        * @param	plaintext_base	The base in which plaintexts should be represented. Usually "2" for binary.
        *
        * @param	r				(Advanced) The power of plaintext_base.
        *							The actual plaintext space in HElib is a Finite Field/Galois Field GF(p^r) where
        *							p = @p plaintext_base. Note that a field GF(p^r) does not behave like e.g. Z_(p^r) would,
        *							but instead behaves like a vector with length r where the coefficients are base-p and operations
        *							are coefficient-wise. Setting this to something other than 1 is only recommended
        *							for advanced users that want to e.g. emulate specific cryptographic fields (e.g. for AES)
        *
        * @param	sec				The desired security level in bits. Will usually be higher than requested.
        *							Note that reserach by M. Albrecht [1] has shown that HElib is actually too optimistic,
        *							and a level of 80 bits as reported by HElib could actually be only 62 bits of security.
        *							[1] Albrecht M.R. (2017) "On Dual Lattice Attacks Against Small-Secret LWE and Parameter Choices in HElib and SEAL"
        *							In: Coron JS., Nielsen J. (eds) Advances in Cryptology � EUROCRYPT 2017. EUROCRYPT 2017.
        *							Lecture Notes in Computer Science, vol 10211. Springer, Cham
        *
        * @param	hw				(Advanced) The hamming weight of the secret key.
        *							The number of non-zero elements of the secret key.
        *							Refer to the official HElib design document [2] for further information.
        *							[1] Halevi S. and Shoup V. (2013) "Design and Implementation of a Homomorphic-Encryption Library"
        *							Available from https://github.com/shaih/HElib/raw/master/doc/designDocument/HElibrary.pdf
        */
        explicit HElibGenerator(long levels, long slots,
                                unsigned long plaintext_base = 2,
                                unsigned long r = 1, long sec = 80, long hw = 128, long digits = 3,
                                long candidate_m = 0);
        //long levels = 30, long slots = 128,
        //                                unsigned long plaintext_base = 2,
        //                                unsigned long r = 1, long sec = 128, long hw = 64, long digits = 3,
        //                                long candidate_m = 0)

        /// Encrypt @p n
        inline M_HElib operator()(int n, int bitSize) const {
            return M_HElib(n, sec_key_fix_, bitSize);
        };

        /// Encrypt @p n
        inline M_HElib operator()(int n) const {
            return M_HElib(n, sec_key_fix_, ceil_log2(n));
        };

        /// Encrypt @p n
        inline M_HElib operator()(long n, int bitSize) const {
            return M_HElib(n, sec_key_fix_, bitSize);
        };

        /// Encrypt @p n
        inline M_HElib operator()(long n) const {
            return M_HElib(n, sec_key_fix_, ceil_log2(n));
        };

        /// Encryption of vector
        M_HElib operator()(std::vector<long> v, int bitSize) const;

        /// Encryption of vector
        M_HElib operator()(std::vector<long> v) const;

        /// Decryption
        inline vector<long> operator()(const M_HElib &x, bool negative = true) const {
            return x.decrypt(*(sec_key_fix_->sec_key), negative);
        }

    private:

        /// The HElibFix thing stored in this Structure
        std::shared_ptr<const HElibSecKeyFix> sec_key_fix_;

        std::shared_ptr<std::vector<zzX>> unpackSlotEncoding;

    };
}

#endif //UHE_UHE_HELIB_H
