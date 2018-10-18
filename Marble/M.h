#ifndef UHE_LIBRARY_H
#define UHE_LIBRARY_H

#include <vector>
#include <string>
#include <functional>
#include "M_HElib.h"

using namespace std;

namespace Marble {

    class M;

    struct SelectorType {
        int x = -1;
    };

    /// Optimizations/shortcuts for fold functions
    extern struct SelectorType sum;
    extern struct SelectorType min;
    extern struct SelectorType min_with_index;
    extern struct SelectorType batched;

    //SelectorType batched;

    // Convenience functions with meaningful names (instead of just constructors)

    M encrypt(SelectorType batched, long value, int bitSize, bool twos_complement);

    M encrypt(SelectorType batched, vector<long> value, int bitSize = 32, bool twos_complement = true);

    M encrypt(SelectorType batched, vector<bool> value, int bitSize = 1, bool twos_complement = false);

    M encrypt(SelectorType batched, vector<int> value, int bitSize = 32, bool twos_complement = true);

    M encrypt(long value, int bitSize, bool twos_complement);

    vector<M> encrypt(vector<long> value, int bitSize = 32, bool twos_complement = true);

    vector<M> encrypt(vector<bool> value, int bitSize = 1, bool twos_complement = false);

    M encode(SelectorType batched, long value, int bitSize = 32, bool twos_complement = true);

    M encode(SelectorType batched, vector<long> value, int bitSize = 32, bool twos_complement = true);

    M encode(SelectorType batched, vector<int> value, int bitSize = 32, bool twos_complement = true);




    // Output

    void output(M value, string msg = "", int slot = -1);

    class M {
    public:

        static void analyse(std::function<void()> f);


        static void evaluate(std::function<void()> f);

        /// Dummy contructor
        M();

        /// Copy constructor
        M(const M &other);

        /// Move constructor
        M(M &&other);

        /// Plaintext constructor
        M(long i);

        /// Copy assignment
        M &operator=(const M &other);

        /// Move assignment
        M &operator=(M &&other);

        /// Plaintext encode assignment
        M &operator=(long i);

        /// Encrypt bool
        M &operator=(bool b);

        /// Encrypt int
        M &operator=(int i);

        /// Addition
        M &operator+=(const M &rhs);

        /// Addition
        M &operator+=(const vector<long> &rhs);

        /// Subtraction
        M &operator-=(const M &rhs);

        /// Multiplication
        M &operator*=(const M &rhs);

        /// Multiplication
        M &operator*=(vector<long> &rhs);

        /// Increment operator
        M &operator++();

        /// Decrement operator
        M &operator--();

        /// Increment operator
        M operator++(int) {
            auto tmp = *this;
            operator++();
            return tmp;
        }

        /// Decrement operator
        M operator--(int) {
            auto tmp = *this;
            operator--();
            return tmp;
        }

        /// Logical negation operator
        M &operator!();


        /// Generic internal operation
        /// Works on blocks of slots that are interval long
        /// Considers the first in_interval slots in each block "active"
        M & fold(std::function<M(M, M)> f, int interval = -1, int in_interval = -1);

        /// Optimized internal operation
        M & fold(SelectorType s, int interval = -1, int in_interval = -1);

        /// Special overload for minimum-with-index
        M & fold(SelectorType s, M &indices, int interval = -1, int in_interval = -1);

        /// Internal Rotation
        void rotate(long k);

        /// Internal Addition
        void batched_sum(long interval, long in_interval);

        /// Internal Minimum
        void batched_min(long interval, long in_interval);

        /// Internal Minimum with index
        void batched_min_with_index(long interval, long in_interval, M &indices);

        /// Equality
        friend M operator==(const M &lhs, const M &rhs);

        /// Inequality
        friend M operator!=(const M &lhs, const M &rhs);

        /// Greater-than-or-equal
        friend M operator>=(const M &lhs, const M &rhs);

        /// Greater-than
        friend M operator>(const M &lhs, const M &rhs);

        /// Smaller-than-or-equal
        friend M operator<=(const M &lhs, const M &rhs);

        /// Smaller-than
        friend M operator<(const M &lhs, const M &rhs);

        /// Addition
        friend M operator+(const M &lhs, const M &rhs);

        /// Subtraction
        friend M operator-(const M &lhs, const M &rhs);

        /// Multiplication
        friend M operator*(const M &lhs, const M &rhs);

        /// Current number of used slots
        int size();

        // HElibEvaluation internals
        enum class Mode {
            Analysis, SilentAnalysis, HElibEvaluation
        };
        static Mode mode;


    private:
        vector<long> values;
        int bitSize = -1;
        bool twos_complement;
        bool plaintext;
        int multdepth = 0;


        static std::unique_ptr<HElibGenerator> gen;
        static int max_multdepth;
        static int max_slots;
        static bool requires_bitslicing;

        static void reset_counts();

        std::unique_ptr<M_HElib> helib_impl = nullptr;

        /// Single value, replicated across all slots
        M(long value, int bitSize, bool twos_complement, bool plaintext);

        /// Different values in different slots
        M(vector<long> values, int bitSize, bool twos_complement, bool plaintext);


        friend M encrypt(SelectorType batched, long value, int bitSize, bool twos_complement);

        friend M encode(SelectorType batched, long value, int bitSize, bool twos_complement);


        friend M encrypt(SelectorType batched, vector<long> value, int bitSize, bool twos_complement);

        friend M encode(SelectorType batched, vector<long> value, int bitSize, bool twos_complement);

        friend vector<M> encrypt(vector<long> values, int bitSize, bool twos_complement);

        friend vector<M> encrypt(vector<bool> values, int bitSize, bool twos_complement);

        friend M encrypt(long value, int bitSize, bool twos_complement);

        friend void output(M value, string msg, int slot);

        friend void analyse(std::function<void()> f);

        friend void evaluate(std::function<void()> f);

        void enc_if_needed();

    };


};
#endif