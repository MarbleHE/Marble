#include "M_HElibImpl.h"
#include "BitHelpers.h"
#include "CtPtrs.h"
#include "EncryptedArray.h"
#include "BitHelpers.h"
#include "binaryArith.h"
#include <climits>
#include <binaryCompare.h>

#ifdef DEBUG_PRINTOUT

#include "debugging.h"

#endif

namespace Marble {

    /// Type of single bit
    using Bit = Ctxt;

    /// Type of iterator over vector of bits
    using BitIter = vector<Bit>::iterator;

    /// Copy-constructor
    Marble::M_HElib::M_HElibImpl::M_HElibImpl(const M_HElib::M_HElibImpl &x) :
            bits_(x.bits_),
            log_scale_(x.log_scale_),
            pub_key_fix_(x.pub_key_fix_) {};

    /// Move constructor
    Marble::M_HElib::M_HElibImpl::M_HElibImpl(M_HElib::M_HElibImpl &&x) noexcept :
            bits_(std::move(x.bits_)),
            log_scale_(std::move(x.log_scale_)),
            pub_key_fix_(std::move(x.pub_key_fix_)) {};

    /// Copy assignment
    Marble::M_HElib::M_HElibImpl &
    Marble::M_HElib::M_HElibImpl::operator=(const M_HElib::M_HElibImpl &x) {
        bits_ = x.bits_;
        log_scale_ = x.log_scale_;
        pub_key_fix_ = x.pub_key_fix_;
        return *this;
    }

    /// Move assignment
    Marble::M_HElib::M_HElibImpl &
    Marble::M_HElib::M_HElibImpl::operator=(M_HElib::M_HElibImpl &&x) noexcept {
        bits_ = std::move(x.bits_);
        log_scale_ = x.log_scale_;
        pub_key_fix_ = std::move(x.pub_key_fix_);
        return *this;
    }

    /// "Real" constructor
    Marble::M_HElib::M_HElibImpl::M_HElibImpl(vector<Bit> bits, shared_ptr<const HElibPubKeyFix> pub_key_fix)
            : bits_(bits),
              pub_key_fix_(pub_key_fix) {
    }

    /// Public-Key Encryption (long)
    Marble::M_HElib::M_HElibImpl::M_HElibImpl(long n, const shared_ptr<const HElibPubKeyFix> &pub_key_fix,
                                              unsigned int bitSize) : pub_key_fix_(pub_key_fix) {

        bits_ = vector<Bit>(bitSize, Ctxt(*pub_key_fix->pub_key));

        for (long i = 0; i < bitSize; i++) {

            // Get the current bit
            long l = n;
            if (l < 0) {
                // Two's complement
                l += (1 << bitSize);
            }
            l = (l >> i) & 1;

            const EncryptedArray &ea = *(pub_key_fix->context->ea);
            vector<long> ll(ea.size(), l);
            ea.encrypt(bits_[i], *pub_key_fix->pub_key, ll);
        }


    }

    /// Public-Key Batched Encryption (vector<long>)
    M_HElib::M_HElibImpl::M_HElibImpl(vector<long> ls,
                                      const shared_ptr<const HElibPubKeyFix> &pub_key_fix,
                                      unsigned int bitSize
    ) :
            pub_key_fix_(pub_key_fix) {

        bits_ = vector<Bit>(bitSize, Ctxt(*pub_key_fix->pub_key));

        for (long i = 0; i < bitSize; i++) {

            const EncryptedArray &ea = *(pub_key_fix->context->ea);
            std::vector<long> t = ls;
            t.resize(ea.size());
            for (long &l : t) {
                if (l < 0) {
                    // Two's complement
                    l += (1 << bitSize);
                }
                l = (l >> i) & 1;
            }
            ea.encrypt(bits_[i], *pub_key_fix->pub_key, t);
        }

    }


    /// Secret-Key Encryption (long) same value in all slots
    Marble::M_HElib::M_HElibImpl::M_HElibImpl(long n, const shared_ptr<const HElibSecKeyFix> &sec_key_fix,
                                              unsigned int bitSize) : pub_key_fix_(sec_key_fix) {
        bits_ = vector<Bit>(bitSize, Ctxt(*sec_key_fix->sec_key));

        for (long i = 0; i < bitSize; i++) {

            // Get the current bit
            long l = n;
            if (l < 0) {
                // Two's complement
                l += (1 << bitSize);
            }
            l = (l >> i) & 1;

            EncryptedArray ea = *(sec_key_fix->context->ea);
            vector<long> ll(ea.size(), l);
            ea.skEncrypt(bits_[i], *sec_key_fix->sec_key, ll);
        }


    }

    /// Secret-Key batched Encryption (vector<long>)
    M_HElib::M_HElibImpl::M_HElibImpl(vector<long> ls,
                                      const shared_ptr<const HElibSecKeyFix> &sec_key_fix,
                                      unsigned int bitSize
    ) :
            pub_key_fix_(sec_key_fix) {
        bits_ = vector<Bit>(bitSize, Ctxt(*sec_key_fix->sec_key));

        for (long i = 0; i < bitSize; i++) {

            const EncryptedArray &ea = *(sec_key_fix->context->ea);
            std::vector<long> t = ls;
            t.resize(ea.size());
            for (long &l : t) {
                if (l < 0) {
                    // Two's complement
                    l += (1 << bitSize);
                }
                l = (l >> i) & 1;
            }
            ea.skEncrypt(bits_[i], *sec_key_fix->sec_key, t);
        }

    }

    vector<long> Marble::M_HElib::M_HElibImpl::decrypt(const FHESecKey &sec_key, bool negative) const {
        vector<long> out;
        auto bits_copy = bits_;
        decryptBinaryNums(out, CtPtrs_vectorCt(bits_copy), sec_key, *sec_key.getContext().ea, negative);
        return out;
    }

    Marble::M_HElib::M_HElibImpl Marble::M_HElib::M_HElibImpl::operator!() const {

        vector<Bit> b = bits_;

        if (b.size() == 1) {
            // invert the bit
            b[0].addConstant(ZZ(1));
        } else {
            // Combine all the bits in the number in a log(bits) deep NOR 'tree'

            // Because we have efficient "dummy" zeros, we can just extend the bit array until it is a power of two :)
            int next_power_of_two = 1;
            while (next_power_of_two < b.size()) {
                next_power_of_two *= 2;
            } //let's hope the compiler optimizes this somewhat..either way, the number of bits should be small
            auto diff = next_power_of_two - b.size();
            while (diff-- > 0) {
                b.emplace_back(ZeroCtxtLike, b[0]); //'dummy' zero, no real crypto
            }

            // Now that bits_.size() is a power of two, things get a lot easier!
            while (b.size() > 1) {
                // NOR = !a & !b
                // so first flip all bits (by adding one)
                for (int i = 0; i < b.size(); ++i) {
                    b[i].addConstant(ZZ(1));
                }
                // then AND bits from the front and back
                for (int i = 0; i < (b.size() / 2); ++i) {
                    b[i].multiplyBy(b[(b.size() - 1) - i]);
                }
                // drop the second half
                b.resize(b.size() / 2,
                         Bit(ZeroCtxtLike, b[0])); //needs a default element because Bit() doesn't exist
            }
        }
        // add a dummy zero sign bit to make sure "1" doesn't become -2
        b.emplace_back(ZeroCtxtLike, b[0]);
        return M_HElib::M_HElibImpl(std::move(b), pub_key_fix_);
    }

    Marble::M_HElib::M_HElibImpl
    operator==(const M_HElib::M_HElibImpl &lhs, const M_HElib::M_HElibImpl &rhs) {

        M_HElib::M_HElibImpl t_lhs = lhs;
        M_HElib::M_HElibImpl t_rhs = rhs;

        // Combine all the bits in the two numbers in a log(bits) deep XOR 'tree'

        // Because we have efficient "dummy" zeros, we can just extend the bit array until it is a power of two :)
        int next_power_of_two = 1;
        while (next_power_of_two < t_lhs.bits_.size()) {
            next_power_of_two *= 2;
        } //let's hope the compiler optimizes this somewhat..either way, the number of bits should be small
        auto diff = next_power_of_two - t_lhs.bits_.size();
        while (diff-- > 0) {
            t_lhs.bits_.emplace_back(ZeroCtxtLike, t_lhs.bits_[0]); //'dummy' zero, no real crypto
            t_rhs.bits_.emplace_back(ZeroCtxtLike, t_rhs.bits_[0]); //'dummy' zero, no real crypto
        }


        // Do the first XOR, an then add one to it to invert
        for (int i = 0; i < t_lhs.bits_.size(); ++i) {
            t_lhs.bits_[i] += t_rhs.bits_[i];
            t_lhs.bits_[i].addConstant(ZZ(1));
        }

        // Now that bits_.size() is a power of two, things get a lot easier!
        // Do an AND of all values
        while (t_lhs.bits_.size() > 1) {

            // AND bits from the front and back
            for (int i = 0; i < (t_lhs.bits_.size() / 2); ++i) {
                t_lhs.bits_[i].multiplyBy(t_lhs.bits_[(t_lhs.bits_.size() - 1) - i]);
            }
            // drop the second half
            t_lhs.bits_.resize(t_lhs.bits_.size() / 2,
                               Bit(ZeroCtxtLike, t_lhs.bits_[0])); //needs a default element because Bit() doesn't exist
        }

        // add a dummy zero sign bit to make sure "1" doesn't become -2
        t_lhs.bits_.emplace_back(ZeroCtxtLike, t_lhs.bits_[0]);
        return t_lhs;
    }

    Marble::M_HElib::M_HElibImpl
    operator!=(const M_HElib::M_HElibImpl &lhs, const M_HElib::M_HElibImpl &rhs) {

        M_HElib::M_HElibImpl t_lhs = lhs;
        M_HElib::M_HElibImpl t_rhs = rhs;

        // Combine all the bits in the two numbers in a log(bits) deep XOR 'tree'

        // Because we have efficient "dummy" zeros, we can just extend the bit array until it is a power of two :)
        int next_power_of_two = 1;
        while (next_power_of_two < t_lhs.bits_.size()) {
            next_power_of_two *= 2;
        } //let's hope the compiler optimizes this somewhat..either way, the number of bits should be small
        auto diff = next_power_of_two - t_lhs.bits_.size();
        while (diff-- > 0) {
            t_lhs.bits_.emplace_back(ZeroCtxtLike, t_lhs.bits_[0]); //'dummy' zero, no real crypto
            t_rhs.bits_.emplace_back(ZeroCtxtLike, t_rhs.bits_[0]); //'dummy' zero, no real crypto
        }


        // Do the first XOR
        for (int i = 0; i < t_lhs.bits_.size(); ++i) {
            t_lhs.bits_[i] += t_rhs.bits_[i];
        }

        // Now that bits_.size() is a power of two, things get a lot easier!
        // Do an OR of all values
        while (t_lhs.bits_.size() > 1) {
            // OR is NOT( NOT A AND NOT B)
            // so first flip all bits (by adding one)
            for (int i = 0; i < t_lhs.bits_.size(); ++i) {
                t_lhs.bits_[i].addConstant(ZZ(1));
            }

            // AND bits from the front and back
            for (int i = 0; i < (t_lhs.bits_.size() / 2); ++i) {
                t_lhs.bits_[i].multiplyBy(t_lhs.bits_[(t_lhs.bits_.size() - 1) - i]);
            }
            // drop the second half
            t_lhs.bits_.resize(t_lhs.bits_.size() / 2,
                               Bit(ZeroCtxtLike, t_lhs.bits_[0])); //needs a default element because Bit() doesn't exist
        }

        // add a dummy zero sign bit to make sure "1" doesn't become -2
        t_lhs.bits_.emplace_back(ZeroCtxtLike, t_lhs.bits_[0]);
        return t_lhs;
    }

    Marble::M_HElib::M_HElibImpl
    operator<(const M_HElib::M_HElibImpl &lhs, const M_HElib::M_HElibImpl &rhs) {
        auto t_lhs = lhs;
        auto t_rhs = rhs;
        const CtPtrs_vectorCt lhsPtrs(t_lhs.bits_);
        const CtPtrs_vectorCt rhsPtrs(t_rhs.bits_);
        std::vector<Ctxt> max, min;
        CtPtrs_vectorCt maxPtrs(max), minPtrs(min);
        Ctxt mu(*lhs.pub_key_fix_->pub_key);
        Ctxt ni(*lhs.pub_key_fix_->pub_key);
        compareTwoNumbers(maxPtrs, minPtrs, mu, ni, lhsPtrs, rhsPtrs);

        //For < we want "ni"
        vector<Ctxt> b;
        b.emplace_back(ni);

        return M_HElib::M_HElibImpl(std::move(b), lhs.pub_key_fix_);

    }

    Marble::M_HElib::M_HElibImpl
    operator>(const M_HElib::M_HElibImpl &lhs, const M_HElib::M_HElibImpl &rhs) {
        auto t_lhs = lhs;
        auto t_rhs = rhs;
        const CtPtrs_vectorCt lhsPtrs(t_lhs.bits_);
        const CtPtrs_vectorCt rhsPtrs(t_rhs.bits_);
        std::vector<Ctxt> max, min;
        CtPtrs_vectorCt maxPtrs(max), minPtrs(min);
        Ctxt mu(*lhs.pub_key_fix_->pub_key);
        Ctxt ni(*lhs.pub_key_fix_->pub_key);
        compareTwoNumbers(maxPtrs, minPtrs, mu, ni, lhsPtrs, rhsPtrs);

        // For > we want "mu"
        vector<Ctxt> b;
        b.emplace_back(mu);

        return M_HElib::M_HElibImpl(std::move(b), lhs.pub_key_fix_);
    }

    Marble::M_HElib::M_HElibImpl
    operator<=(const M_HElib::M_HElibImpl &lhs, const M_HElib::M_HElibImpl &rhs) {
        auto t_lhs = lhs;
        auto t_rhs = rhs;
        const CtPtrs_vectorCt lhsPtrs(t_lhs.bits_);
        const CtPtrs_vectorCt rhsPtrs(t_rhs.bits_);
        std::vector<Ctxt> max, min;
        CtPtrs_vectorCt maxPtrs(max), minPtrs(min);
        Ctxt mu(*lhs.pub_key_fix_->pub_key);
        Ctxt ni(*lhs.pub_key_fix_->pub_key);
        compareTwoNumbers(maxPtrs, minPtrs, mu, ni, lhsPtrs, rhsPtrs);

        //For < we want "ni" and for "==" we just use that function!
        vector<Bit> b;
        b.emplace_back(ni);

        M_HElib::M_HElibImpl nii(std::move(b), lhs.pub_key_fix_);
        return nii || (lhs == rhs);

    }

    Marble::M_HElib::M_HElibImpl
    operator>=(const M_HElib::M_HElibImpl &lhs, const M_HElib::M_HElibImpl &rhs) {
        auto t_lhs = lhs;
        auto t_rhs = rhs;
        const CtPtrs_vectorCt lhsPtrs(t_lhs.bits_);
        const CtPtrs_vectorCt rhsPtrs(t_rhs.bits_);
        std::vector<Ctxt> max, min;
        CtPtrs_vectorCt maxPtrs(max), minPtrs(min);
        Ctxt mu(*lhs.pub_key_fix_->pub_key);
        Ctxt ni(*lhs.pub_key_fix_->pub_key);
        compareTwoNumbers(maxPtrs, minPtrs, mu, ni, lhsPtrs, rhsPtrs);

        //For > we want "mu" and for "==" we just use that function!
        vector<Ctxt> b;
        b.emplace_back(mu);

        M_HElib::M_HElibImpl muu(std::move(b), lhs.pub_key_fix_);
        return muu || (lhs == rhs);
    }

    Marble::M_HElib::M_HElibImpl
    operator&&(const M_HElib::M_HElibImpl &lhs, const M_HElib::M_HElibImpl &rhs) {
        auto t = !!lhs;
        t.bits_[0].multiplyBy((!!rhs).bits_[0]);

        t.bits_.resize(1, t.bits_[0]);
        t.bits_.emplace_back(ZeroCtxtLike, t.bits_[0]);
        return t;

    }

    Marble::M_HElib::M_HElibImpl
    operator||(const M_HElib::M_HElibImpl &lhs, const M_HElib::M_HElibImpl &rhs) {
        auto t = !!lhs;
        t.bits_[0].addCtxt((!!rhs).bits_[0]);

        t.bits_.resize(1, t.bits_[0]);
        t.bits_.emplace_back(ZeroCtxtLike, t.bits_[0]);
        return t;

    }

    M_HElib::M_HElibImpl &M_HElib::M_HElibImpl::operator+=(const M_HElib::M_HElibImpl &rhs) {
        auto rhs_bits_copy = rhs.bits_;

        // Sign extend the numbers to final size (necessary for twoscomplement without overflow)
        int result_size = max(bits_.size(), rhs.bits_.size()) + 1;
        bits_.resize(result_size, bits_[bits_.size() - 1]);
        rhs_bits_copy.resize(result_size, rhs_bits_copy[rhs_bits_copy.size() - 1]);

        // Wrappers
        vector<Bit> res;
        CtPtrs_vectorCt bitsPtrs(bits_);
        CtPtrs_vectorCt rhsbitsPtrs(rhs_bits_copy);
        CtPtrs_vectorCt resPtrs(res);


#ifdef  DEBUG_PRINTOUT
        vector<long> slots;
        decryptBinaryNums(slots,bitsPtrs,*dbgKey,*dbgEa,true);
        cout << "Calling AddTwoNumbers with a: " << slots    << endl;
        decryptBinaryNums(slots,rhsbitsPtrs,*dbgKey,*dbgEa,true);
        cout << "and b: " << slots << endl;
#endif

        // Actual addition
        addTwoNumbers(resPtrs, bitsPtrs, rhsbitsPtrs, result_size);

        // Set result
        for (int i = 0; i < result_size; ++i) {
            bits_[i] = *resPtrs[i];
        }

        return *this;
    }

    M_HElib::M_HElibImpl &M_HElib::M_HElibImpl::operator+=(const vector<long> &rhs) {
        int rhs_bits_size = 0;
        for (auto &l : rhs) {
            rhs_bits_size = max(rhs_bits_size, ceil_log2(l));
        }

        // Sign extend the numbers to final size (necessary for twoscomplement without overflow)
        int result_size = max((int) bits_.size(), rhs_bits_size) + 1;
        bits_.resize(result_size, bits_[bits_.size() - 1]);

        // Wrappers
        vector<Bit> res;
        CtPtrs_vectorCt bitsPtrs(bits_);


        vector<Bit> rhs_bits(rhs_bits_size, Ctxt(ZeroCtxtLike, bits_[0]));
        for (long i = 0; i < rhs_bits.size(); i++) {

            const EncryptedArray &ea = *(pub_key_fix_->context->ea);
            std::vector<long> t = rhs;
            t.resize(ea.size());
            for (long &l : t) {
                if (l < 0) {
                    // Two's complement
                    l += (1 << rhs_bits_size);
                }
                l = (l >> i) & 1;
            }
            ZZX pt;
            ea.encode(pt, t);
            rhs_bits[i].DummyEncrypt(pt);
        }
        CtPtrs_vectorCt rhsbitsPtrs(rhs_bits);
        CtPtrs_vectorCt resPtrs(res);

        // Actual addition
        addTwoNumbers(resPtrs, bitsPtrs, rhsbitsPtrs, result_size);

        // Set result
        bits_ = res;
        return *this;
    }

    M_HElib::M_HElibImpl &M_HElib::M_HElibImpl::operator-=(const M_HElib::M_HElibImpl &rhs) {
        auto rhs_bits_copy = rhs.bits_;

        const EncryptedArray &ea = *pub_key_fix_->context->ea;
        // Compute the two's complement of the right hand number:
        vector<long> ones(ea.size(), 1);
        Ctxt one(ZeroCtxtLike, bits_[0]);
        ea.encrypt(one, *pub_key_fix_->pub_key, ones);

        for (auto &b : rhs_bits_copy) { // invert the bits
            b += one;
        }
        CtPtrs_vectorCt rhsPtrs(rhs_bits_copy);
        vector<Bit> onev;
        onev.push_back(one);
        CtPtrs_vectorCt onePtrs(onev);
        vector<Bit> rhs_inv;
        CtPtrs_vectorCt rhs_inv_ptrs(rhs_inv);
        addTwoNumbers(rhs_inv_ptrs, rhsPtrs, onePtrs, rhs_bits_copy.size());


        // Sign extend the numbers to final size (necessary for twoscomplement without overflow)
        int result_size = max(bits_.size(), rhs.bits_.size()) + 1;
        bits_.resize(result_size, bits_[bits_.size() - 1]);
        rhs_inv.resize(result_size, rhs_inv[rhs_inv.size() - 1]);

        // Wrappers
        vector<Bit> res;
        CtPtrs_vectorCt bitsPtrs(bits_);
        CtPtrs_vectorCt rhsbitsPtrs(rhs_inv);
        CtPtrs_vectorCt resPtrs(res);

        // Actual addition
        addTwoNumbers(resPtrs, bitsPtrs, rhsbitsPtrs, result_size);

        // Set result
        bits_ = res;
        return *this;
    }

    M_HElib::M_HElibImpl &M_HElib::M_HElibImpl::operator*=(const M_HElib::M_HElibImpl &rhs) {
        auto rhs_bits_copy = rhs.bits_;

        // Sign extend the numbers to final size (necessary for twoscomplement without overflow)
        int result_size = bits_.size() + rhs.bits_.size();
        bits_.resize(result_size, bits_[bits_.size() - 1]);
        rhs_bits_copy.resize(result_size, rhs_bits_copy[rhs_bits_copy.size() - 1]);

        // Wrappers
        vector<Bit> res;
        CtPtrs_vectorCt bitsPtrs(bits_);
        CtPtrs_vectorCt rhsbitsPtrs(rhs_bits_copy);
        CtPtrs_vectorCt resPtrs(res);

        // Actual multiplication
        multTwoNumbers(resPtrs, bitsPtrs, rhsbitsPtrs, false, result_size);

        // Set result
        bits_ = res;
        return *this;
    }


    M_HElib::M_HElibImpl &M_HElib::M_HElibImpl::operator*=(const vector<long> &rhs) {
        int rhs_bits_size = 0;
        for (auto &l : rhs) {
            rhs_bits_size = max(rhs_bits_size, ceil_log2(l));
        }


        vector<bool> b_set(rhs_bits_size, false);
        for (long i = 0; i < rhs_bits_size; i++) {
            std::vector<long> t = rhs;
            for (long &l : t) {
                if (l < 0) {
                    // Two's complement
                    l += (1 << rhs_bits_size);
                }
                l = (l >> i) & 1;
                b_set[i] = l;
            }

        }

        // Sign extend the numbers to final size (necessary for twoscomplement without overflow)
        long resSize = bits_.size() + rhs_bits_size;
        bits_.resize(resSize, bits_[bits_.size() - 1]);


        CtPtrs_vectorCt a(bits_);
        vector<Ctxt> res;
        CtPtrs_vectorCt resPtrs(res);

        // Wrappers
        NTL::Vec<NTL::Vec<Ctxt> > numbers(INIT_SIZE, std::min((long) rhs_bits_size, resSize));
        const Ctxt *ct_ptr = a.ptr2nonNull();
        long nNums = lsize(numbers);
        for (long i = 0; i < nNums; i++)
            numbers[i].SetLength(std::min((i + resSize), resSize),
                                 Ctxt(ZeroCtxtLike, *ct_ptr));
        std::vector<std::pair<long, long> > pairs;
        for (long i = 0; i < nNums; i++)
            for (long j = i; j < lsize(numbers[i]); j++) {
                if (a.isSet(j - i) && !(a[j - i]->isEmpty()) && b_set[i])
                    pairs.push_back(std::pair<long, long>(i, j));
            }

        for (long idx = 1; idx < lsize(pairs); idx++) {
            long i, j;
            std::tie(i, j) = pairs[idx];
            numbers[i][j] = *(a[j - i]);
            //numbers[i][j].multiplyBy(*(b[i])); // multiply by the bit of b
            // above is always one in plaintext version
        }

        CtPtrMat_VecCt nums(numbers); // A wrapper aroune numbers
        addManyNumbers(resPtrs, nums, resSize);

        bits_ = res;
        return *this;
    }


    M_HElib::M_HElibImpl &M_HElib::M_HElibImpl::operator++() {
        M_HElib::M_HElibImpl one(1, pub_key_fix_, 1);
        *this += one;
        return *this;
    }

    M_HElib::M_HElibImpl &M_HElib::M_HElibImpl::operator--() {
        M_HElib::M_HElibImpl one(1, pub_key_fix_, 1);
        *this -= one;
        return *this;
    }

    M_HElib::M_HElibImpl &M_HElib::M_HElibImpl::rotate(long k) {
        auto &ea = *pub_key_fix_->context->ea;
        for (auto &b : bits_) {
            ea.rotate(b, k);
        }
        return *this;
    }

    M_HElib::M_HElibImpl &M_HElib::M_HElibImpl::internal_add(long interval, long in_interval) {
        // Wrappers
        vector<Bit> res;
        CtPtrs_vectorCt resPtrs(res);
        CtPtrs_vectorCt bitsPtrs(bits_);

        // Actual operation
        internalAdd(resPtrs, bitsPtrs, interval, in_interval, nullptr);


        // Set result
        bits_ = res;
        return *this;
    }

    M_HElib::M_HElibImpl &M_HElib::M_HElibImpl::internal_minimum_with_index(long interval, long in_interval, long sets,
                                                                            M_HElib::M_HElibImpl &indices) {
        // Wrappers
        CtPtrs_vectorCt bitsPtrs(bits_);
        CtPtrs_vectorCt indPtrs(indices.bits_);

        // Actual operation
        internalMin(bitsPtrs, indPtrs, interval, in_interval, sets);

        return *this;
    }


}