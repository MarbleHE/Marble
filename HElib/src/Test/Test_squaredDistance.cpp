/* Copyright (C) 2012-2017 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <NTL/BasicThreadPool.h>
#include <numeric>

NTL_CLIENT

#include "../EncryptedArray.h"
#include "../FHE.h"

#include "../intraSlot.h"
#include "../binaryArith.h"

#ifdef DEBUG_PRINTOUT

#include "../debugging.h"

#endif
// define flags FLAG_PRINT_ZZX, FLAG_PRINT_POLY, FLAG_PRINT_VEC, functions
//        decryptAndPrint(ostream, ctxt, sk, ea, flags)
//        decryptAndCompare(ctxt, sk, ea, pa);

static std::vector<zzX> unpackSlotEncoding; // a global variable
static bool verbose = true;

static long mValues[][15] = {
// { p, phi(m),   m,   d, m1, m2, m3,    g1,   g2,   g3, ord1,ord2,ord3, B,c}
        {2, 48,    105,   12, 3,    35,  0,   71,    76,    0,     2,   2,   0,   25, 2}, //0: 4 slots      (2x2)
        {2, 600,   1023,  10, 11,   93,  0,   838,   584,   0,     10,  6,   0,   25, 2}, //1: 60 slots     (10x6)
        {2, 2304,  4641,  24, 7,    3,   221, 3979,  3095,  3760,  6,   2,   -8,  25, 3}, //2: 96 slots     (6x2x8)
        {2, 5460,  8193,  26, 8193, 0,   0,   46,    0,     0,     210, 0,   0,   25, 3}, //3: 210 slots    (210)
        {2, 8190,  8191,  13, 8191, 0,   0,   39,    0,     0,     630, 0,   0,   25, 3}, //4: 639 slots    (630)
        {2, 10752, 11441, 48, 17,   673, 0,   4712,  2024,  0,     16,  -14, 0,   25, 3}, //5: 224 slots    (16x14)
        {2, 15004, 15709, 22, 23,   683, 0,   4099,  13663, 0,     22,  31,  0,   25, 3}, //6: 682 slots    (22x31)
        {2, 27000, 32767, 15, 31,   7,   151, 11628, 28087, 25824, 30,  6,   -10, 28, 4}  //7: 1800 slots   (30x6x10)
};


template<typename T>
void
encrypt_bits(T &out, vector<long> in, long bitSize, bool bootstrap, const FHESecKey &secKey, const EncryptedArray &ea) {
    resize(out, bitSize, Ctxt(secKey));
    for (long i = 0; i < bitSize; i++) {
        std::vector<long> t = in;
        for (long &l : t) {
            if (l < 0) {
                // Two's complement
                l += (1 << bitSize);
            }
            l = (l >> i) & 1;
        }
        ea.skEncrypt(out[i], secKey, t);
        if (bootstrap) {
            out[i].modDownToLevel(5);
        }
    }
}

int main(int argc, char *argv[]) {
    ArgMapping amap;
    long prm = 1;
    amap.arg("prm", prm, "parameter size (0-tiny,...,7-huge)");
    long bitSize = 8;
    amap.arg("bitSize", bitSize, "bitSize of input integers (<=32)");
    long active_slots = 10;
    amap.arg("active_slots", active_slots, "Number of slots that belong to one set");
    bool bootstrap = false;
    amap.arg("bootstrap", bootstrap, "test multiplication with bootstrapping");
    long seed = 0;
    amap.arg("seed", seed, "PRG seed");
    long nthreads = 4;
    amap.arg("nthreads", nthreads, "number of threads");
    amap.arg("verbose", verbose, "print more information");
    amap.parse(argc, argv);
    if (seed) NTL::SetSeed(ZZ(seed));
    if (nthreads > 1) NTL::SetNumThreads(nthreads);
    if (bitSize <= 0) bitSize = 5;
    else if (bitSize > 32) bitSize = 32;

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

    // Compute the number of levels
    long L;
    if (bootstrap) L = 30; // that should be enough
    else {
        double add2NumsLvls = log(bitSize + 1) / log(2.0);
        double mult2NumLevls = log(bitSize + 1) / log(1.5) + log(2 * (bitSize + 1)) / log(2.0);
        long bitSizeMult = 2 * (bitSize + 1);
        long bitSizeInternalAdd = ceil(log(active_slots * ((1 << bitSizeMult) - 1)) / log(2.0));
        double internalAddLvls = log(bitSizeInternalAdd) / log(2.0) + /*final add operation */
                                 (log(60 / active_slots) / log(2.0)); // previous guess:  1:8

        double internalMinLvls = (log(bitSizeInternalAdd) / log(2.0)) /*compare operation */
                                 * (log(60 / active_slots) / log(2.0)); // previous guess for 1:12
        L = ceil(add2NumsLvls) + ceil(mult2NumLevls) + ceil(internalAddLvls) + ceil(internalMinLvls) ;

    }

    if (verbose) {
        cout << "Using L=" << L << endl;
        cout << "input bitSizes=" << bitSize << ",";
        if (nthreads > 1) cout << " using " << NTL::AvailableThreads() << " threads\n";
        cout << "computing key-independent tables..." << std::flush;
    }
    FHEcontext context(m, p, /*r=*/1, gens, ords);
    context.bitsPerLevel = B;
    buildModChain(context, L, c,/*extraBits=*/8);
    if (bootstrap) {
        context.makeBootstrappable(mvec, /*t=*/0,
                /*flag=*/false, /*cacheType=DCRT*/2);
    }
    buildUnpackSlotEncoding(unpackSlotEncoding, *context.ea);
    if (verbose) {
        cout << " done.\n";
        context.zMStar.printout();
        cout << " L=" << L << ", B=" << B << endl;
        cout << "\ncomputing key-dependent tables..." << std::flush;
    }
    FHESecKey secKey(context);
    secKey.GenSecKey(/*Hweight=*/128);
    addSome1DMatrices(secKey); // compute key-switching matrices
    addFrbMatrices(secKey);
    if (bootstrap) secKey.genRecryptData();
    if (verbose) cout << " done\n";

    activeContext = &context; // make things a little easier sometimes
#ifdef DEBUG_PRINTOUT
    dbgEa = (EncryptedArray *) context.ea;
    dbgKey = &secKey;
#endif

    const EncryptedArray &ea = *(secKey.getContext().ea);
    if (verbose) {
        cout << "Current settings give " << ea.size() << " slots (";
        for (int i = 0; i < ea.dimension() - 1; ++i) {
            cout << ea.sizeOfDimension(i) << "x";
        }
        cout << ea.sizeOfDimension(ea.dimension() - 1) << ")." << endl;
    }
    assert(active_slots <= ea.size());


    ////////////////////////////////// START TEST //////////////////////////



    // Choose a vector of random numbers
    // Fill anything that isn't an active value with ones (for testing, in reality, would be zeros)
    std::vector<long> pa(ea.size(), 1);
    std::vector<long> pb(ea.size(), 1);
    // We have
    long sets = ea.size() / active_slots;
    for (long i = 0; i < sets * active_slots; ++i) {
        // Two's complement!
        pa[i] = RandomBits_long(bitSize);
        if (pa[i] > (1 << (bitSize - 1)) - 1) {
            // Reverse Two's complement
            pa[i] = -(1 << bitSize) + pa[i];
        }
        pb[i] = RandomBits_long(bitSize);
        if (pb[i] > (1 << (bitSize - 1)) - 1) {
            // Reverse Two's complement
            pb[i] = -(1 << bitSize) + pb[i];
        }
    }
    if (verbose) {
        cout << "pa: " << pa << endl;
        cout << "pb: " << pb << endl;
    }
    // Encrypt the individual bits
    NTL::Vec<Ctxt> eSum, enca, encb;
    encrypt_bits(enca, pa, bitSize, bootstrap, secKey, ea);
    encrypt_bits(encb, pb, bitSize, bootstrap, secKey, ea);


    if (verbose) {
        cout << "\n  bits-size " << bitSize << endl;
        CheckCtxt(enca[0], "b4 addition");
        cout << "Minimum level: " << findMinLevel(CtPtrs_VecCt(enca)) << endl;
    }

    /////// SIGN EXTEND PRIOR TO ADDITION
    resize(enca, bitSize + 1, enca[bitSize - 1]);
    resize(encb, bitSize + 1, encb[bitSize - 1]);

    /////////// ADDITION
    vector<long> slots;
    {
        CtPtrs_VecCt eep(eSum);  // A wrapper around the output vector

        // Outsize == input size because only then does two's complement addition work properly!
        addTwoNumbers(eep, CtPtrs_VecCt(enca), CtPtrs_VecCt(encb),
                      enca.length(), &unpackSlotEncoding);
        decryptBinaryNums(slots, eep, secKey, ea, true, true);
    } // get rid of wrapper
    vector<long> pSum(ea.size());
    if (verbose) {
        CheckCtxt(eSum[lsize(eSum) - 1], "after addition");
        cout << "Minimum level: " << findMinLevel(CtPtrs_VecCt(eSum)) << endl;

        bool correct = true;
        for (int i = 0; i < sets * active_slots; ++i) {
            pSum[i] = pa[i] + pb[i];
            if (slots[i] != pSum[i]) {
                correct = false;
                cout << "addTwoNumbers error at " << i << ":";
                cout << pa[i] << " + " << pb[i] << " was " << slots[i] << " should be:" << pSum[i] << endl;
            }
        }
        if (correct) {
            cout << "addTwoNumbers succeeded!" << endl;
        }
    }

    ///////// SQUARING (currently just a sign-extended standard multiplication)

    // Duplicate the output
    NTL::Vec<Ctxt> eSum2 = eSum;
    // Sign-extend the numbers
    int newSize = 2 * eSum.length();
    resize(eSum, newSize, eSum[eSum.length() - 1]);
    resize(eSum2, newSize, eSum2[eSum2.length() - 1]);

    // Now multiply
    NTL::Vec<Ctxt> eProduct;
    {
        CtPtrs_VecCt eep(eProduct);  // A wrappers around the output vector
        multTwoNumbers(eep, CtPtrs_VecCt(eSum), CtPtrs_VecCt(eSum2),/*negative=*/false,
                       newSize, &unpackSlotEncoding);
        decryptBinaryNums(slots, eep, secKey, ea, true, true);
    } // get rid of the wrapper
    vector<long> pProduct(ea.size());
    if (verbose) {
        CheckCtxt(eProduct[lsize(eProduct) - 1], "after multiplication");
        cout << "Minimum level: " << findMinLevel(CtPtrs_VecCt(eProduct)) << endl;
        cout << "eProduct[size-1] level:" << eProduct[lsize(eProduct) - 1].findBaseLevel() << endl;
        bool correct = true;
        for (int i = 0; i < sets * active_slots; ++i) {
            pProduct[i] = pSum[i] * pSum[i];
            if (slots[i] != pProduct[i]) {
                correct = false;
                cout << "multTwoNumbers error at " << i << ":";
                cout << pSum[i] << " * " << pSum[i] << " was " << slots[i] << " should be:" << pProduct[i] << endl;
            }
        }
        if (correct) {
            cout << "multTwoNumbers succeeded!" << endl;
        }
    }

    ////////// INTERNAL ADD
    NTL::Vec<Ctxt> eInternalSum;
    long pIntSum = std::accumulate(slots.begin(), slots.begin() + active_slots, 0l);
    // Test internal addition
    {
        CtPtrs_VecCt eep(eInternalSum);  // A wrapper around the output vector
        internalAdd(eep, CtPtrs_VecCt(eProduct), active_slots,-1, &unpackSlotEncoding);
        decryptBinaryNums(slots, eep, secKey, ea, true, true);
    } // get rid of the wrapper


    vector<long> pInternalSum(sets);
    if (verbose) {
        CheckCtxt(eInternalSum[lsize(eInternalSum) - 1], "after internal addition");

        cout << "Minimum level: " << findMinLevel(CtPtrs_VecCt(eInternalSum)) << endl;
        bool correct = true;
        for (int i = 0; i < sets; ++i) {
            for (int j = 0; j < active_slots; ++j) {
                pInternalSum[i] += pProduct[i * active_slots + j];
            }
            if (slots[i * active_slots] != pInternalSum[i]) {
                correct = false;
                cout << "internalAdd error at " << i * active_slots << ":";
                cout << "sum from " << i * active_slots << " to " << (i + 1) * active_slots - 1 << "(";
                for (int j = 0; j < active_slots; ++j) {
                    cout << i * active_slots + j << ":" << pProduct[i * active_slots + j] << " ";
                }
                cout << ") was " << slots[i * active_slots] << " should be:"
                     << pInternalSum[i] << endl;
            }
        }
        if (correct) {
            cout << "internalAdd succeeded!" << endl;
            cout << "Current bitsize: " << eInternalSum.length() << endl;
        }
    }



    ////////// INTERNAL MIN

    // For the indices, find out how many bits we need:
    long bits = _ntl_g2logs(ea.size() / active_slots + 1);
    // Generate the fitting index at each position
    vector<long> pIndices(ea.size(), 1); //using 1 instead of 0 to make errors easier to spot
    int index = 0;
    for (int i = 0; i < ea.size(); ++i) {
        if (i % active_slots == 0) {
            pIndices[i] = index;
            ++index;
        }
    }

    NTL::Vec<Ctxt> eIndices;
    // Encode them
    resize(eIndices, bits, Ctxt(secKey));
    for (long i = 0; i < bits; i++) {
        std::vector<long> t = pIndices;
        for (long &l                : t) {
            l = (l >> i) & 1;
        }
        ZZX zzx_t;
        ea.encode(zzx_t, t);
        eIndices[i].DummyEncrypt(zzx_t);
        if (bootstrap) {
            // put them at a lower level
            eIndices[i].modDownToLevel(5);
        }
    }

    vector<long> v_slots;
    vector<long> i_slots;
    { // Wrapper
        CtPtrs_VecCt eev(eInternalSum);
        CtPtrs_VecCt eei(eIndices);
       // internalMin(eev, eei, active_slots, ea.size()/active_slots, &unpackSlotEncoding);
        decryptBinaryNums(v_slots, eev, secKey, ea, true, true);
        decryptBinaryNums(i_slots, eei, secKey, ea, false, true);
    }
    if (verbose) {
        CheckCtxt(eInternalSum[lsize(eInternalSum) - 1], "after internal min");
        cout << "Minimum level: " << findMinLevel(CtPtrs_VecCt(eInternalSum)) << endl;

        bool correct = true;

        //find the plaintext minimum, by only looking at multiples of active_slots
        long pMin = LONG_MAX;
        long pMinIndex = -1;
        for (int i = 0; i < sets; ++i) {
            if (pInternalSum[i] < pMin) {
                pMin = pInternalSum[i];
                pMinIndex = pIndices[i*active_slots];
            }
        }

        if (v_slots[0] != pMin || i_slots[0] != pMinIndex) {
            cout << "internalMin error: min value was= " << v_slots[0] << ",  should be:" << pMin;
            cout << " and index was=" << i_slots[0] << " , should be: " << pMinIndex;
        } else {
            cout << "internalMin succeeded!" << endl;
        }
    }

    return 0;
}