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
/**
 * @file polyEval.h
 * @brief Homomorphic Polynomial Evaluation
 */


#include "Ctxt.h"

//! @brief Evaluate a cleartext polynomial on an encrypted input
//! @param[out] res  to hold the return value
//! @param[in]  poly the degree-d polynomial to evaluate
//! @param[in]  x    the point on which to evaluate
//! @param[in]  k    optional optimization parameter, defaults to sqrt(d/2) rounded up or down to a power of two
void polyEval(Ctxt& ret, ZZX poly, const Ctxt& x, long k=0);
     // Note: poly is passed by value, so caller keeps the original

//! @brief Evaluate an encrypted polynomial on an encrypted input
//! @param[out] res  to hold the return value
//! @param[in]  poly the degree-d polynomial to evaluate
//! @param[in]  x    the point on which to evaluate
void polyEval(Ctxt& ret, const Vec<Ctxt>& poly, const Ctxt& x);


// A useful helper class

//! @brief Store powers of X, compute them dynamically as needed.
// This implementation assumes that the size (# of powers) is determined
// at initialization time, it is not hard to grow the vector as needed,
// but not clear if there is any application that needs it.
class DynamicCtxtPowers {
private:
  vector<Ctxt> v;   // A vector storing the powers themselves

public:
  DynamicCtxtPowers(const Ctxt& c, long nPowers)
  {
    assert (!c.isEmpty() && nPowers>0); // Sanity-check

    Ctxt tmp(c.getPubKey(), c.getPtxtSpace());
    v.resize(nPowers, tmp); // Initializes nPowers empty cipehrtexts
    v[0] = c;               // store X itself in v[0]
  }

  //! @brief Returns the e'th power, computing it as needed
  Ctxt& getPower(long e); // must use e >= 1, else throws an exception

  //! dp.at(i) and dp[i] both return the i+1st power
  Ctxt& at(long i) { return getPower(i+1); }
  Ctxt& operator[](long i) { return getPower(i+1); }

  const vector<Ctxt>& getVector() const { return v; }
  long size() const { return v.size(); }
  bool isPowerComputed(long i)
  { return (i>0 && i<=(long)v.size() && !v[i-1].isEmpty()); }
};
