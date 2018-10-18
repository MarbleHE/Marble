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
#include "EvalMap.h"

// needed to get NTL's TraceMap functions...needed for ThinEvalMap
#include <NTL/lzz_pXFactoring.h>
#include <NTL/GF2XFactoring.h>

// Forward declerations
static BlockMatMul1D*
buildStep1Matrix(const EncryptedArray& ea, shared_ptr<CubeSignature> sig,
                 const Vec<long>& reps, long dim, long cofactor, bool invert,
                 bool normal_basis);
static MatMul1D*
buildStep2Matrix(const EncryptedArray& ea, shared_ptr<CubeSignature> sig,
                 const Vec<long>& reps, long dim, long cofactor,
                 bool invert);
static void
init_representatives(Vec<long>& representatives, long dim, 
                     const Vec<long>& mvec, const PAlgebra& zMStar);


// Constructor: initializing tables for the evaluation-map transformations

EvalMap::EvalMap(const EncryptedArray& _ea, 
                 bool minimal,
                 const Vec<long>& mvec, 
                 bool _invert,
                 bool build_cache,
                 bool normal_basis)

  : ea(_ea), invert(_invert)
{
  const FHEcontext& context = ea.getContext();
  const PAlgebra& zMStar = ea.getPAlgebra();
  
  long p = zMStar.getP();
  long d = zMStar.getOrdP();

  // FIXME: we should check that ea was initilized with 
  // G == factors[0], but this is a slight pain to check
  // currently

  // NOTE: this code is derived from a more general setting, and
  // could certainly be greatly simplified

  nfactors = mvec.length();
  assert(nfactors > 0);

  for (long i = 0; i < nfactors; i++)
    for (long j = i+1; j < nfactors; j++)
      assert(GCD(mvec[i], mvec[j]) == 1);

  long m = computeProd(mvec);
  assert(m == long(zMStar.getM()));

  Vec<long> phivec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)  phivec[i] = phi_N(mvec[i]);
  long phim = computeProd(phivec);

  Vec<long> dprodvec(INIT_SIZE, nfactors+1);
  dprodvec[nfactors] = 1;
  
  for (long i = nfactors-1; i >= 0; i--)
    dprodvec[i] = dprodvec[i+1] *
      multOrd(PowerMod(p % mvec[i], dprodvec[i+1], mvec[i]), mvec[i]);

  Vec<long> dvec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    dvec[i] = dprodvec[i] / dprodvec[i+1];

  long nslots = phim/d;
  assert(d == dprodvec[0]);
  assert(nslots == long(zMStar.getNSlots()));

  long inertPrefix = 0;
  for (long i = 0; i < nfactors && dvec[i] == 1; i++) {
    inertPrefix++;
  }

  if (inertPrefix != nfactors-1)
    Error("EvalMap: case not handled: bad inertPrefix");

  Vec< Vec<long> > local_reps(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    init_representatives(local_reps[i], i, mvec, zMStar);

  Vec<long> crtvec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++) 
    crtvec[i] = (m/mvec[i]) * InvMod((m/mvec[i]) % mvec[i], mvec[i]);

  Vec<long> redphivec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    redphivec[i] = phivec[i]/dvec[i];

  CubeSignature redphisig(redphivec);

  Vec< shared_ptr<CubeSignature> > sig_sequence;
  sig_sequence.SetLength(nfactors+1);
  sig_sequence[nfactors] = shared_ptr<CubeSignature>(new CubeSignature(phivec));

  Vec<long> reduced_phivec = phivec;

  for (long dim = nfactors-1; dim >= 0; dim--) {
    reduced_phivec[dim] /= dvec[dim];
    sig_sequence[dim] = 
      shared_ptr<CubeSignature>(new CubeSignature(reduced_phivec));
  }

  long dim = nfactors - 1;
  unique_ptr<BlockMatMul1D> mat1_data;
  mat1_data.reset(buildStep1Matrix(ea, sig_sequence[dim],
       	          local_reps[dim], dim, m/mvec[dim], invert, normal_basis));
  mat1.reset(new BlockMatMul1DExec(*mat1_data, minimal));

  matvec.SetLength(nfactors-1);
  for (dim=nfactors-2; dim>=0; --dim) {
    unique_ptr<MatMul1D> mat_data;

    mat_data.reset(buildStep2Matrix(ea, sig_sequence[dim], local_reps[dim],
				       dim, m/mvec[dim], invert));
    matvec[dim].reset(new MatMul1DExec(*mat_data, minimal));
  }

  if (build_cache) upgrade();
}

void EvalMap::upgrade()
{
  mat1->upgrade();
  for (long i = 0; i < matvec.length(); i++)
    matvec[i]->upgrade();
}

// Applying the evaluation (or its inverse) map to a ciphertext
void EvalMap::apply(Ctxt& ctxt) const
{
  if (!invert) { // forward direction
    mat1->mul(ctxt); 

    for (long i = matvec.length()-1; i >= 0; i--)
      matvec[i]->mul(ctxt);
  }
  else {         // inverse transformation
    for (long i = 0; i < matvec.length(); i++)
      matvec[i]->mul(ctxt);

    mat1->mul(ctxt); 
  }
}


static void
init_representatives(Vec<long>& representatives, long dim, 
                     const Vec<long>& mvec, const PAlgebra& zMStar)
{
  assert(dim >= 0 && dim < mvec.length());

  // special case
  if (dim >= LONG(zMStar.numOfGens())) {
    representatives.SetLength(1);
    representatives[0] = 1;
    return;
  }
  
  long m = mvec[dim];
  long D = zMStar.OrderOf(dim);
  long g = InvMod(zMStar.ZmStarGen(dim) % m, m);

  representatives.SetLength(D);
  for (long i = 0; i < D; i++)
    representatives[i] = PowerMod(g, i, m);
}

// The callback interface for the matrix-multiplication routines.

//! \cond FALSE (make doxygen ignore these classes)
template<class type> class Step2Matrix : public MatMul1D_derived<type> 
{
  PA_INJECT(type)

  const EncryptedArray& base_ea;
  shared_ptr<CubeSignature> sig;
  long dim;
  Mat<RX> A;

public:
  // constructor
  Step2Matrix(const EncryptedArray& _ea,
              shared_ptr<CubeSignature> _sig, const Vec<long>& reps,
              long _dim, long cofactor, bool invert=false)
    : base_ea(_ea), sig(_sig), dim(_dim)
  {
    long sz = sig->getDim(dim);
    assert(sz == reps.length());

    const EncryptedArrayDerived<type>& ea = _ea.getDerived(type());
    RBak bak; bak.save(); _ea.getAlMod().restoreContext();
    const RX& G = ea.getG();

    Vec<RX> points(INIT_SIZE, sz);
    for (long j = 0; j < sz; j++) 
      points[j] = RX(reps[j]*cofactor, 1) % G;

    A.SetDims(sz, sz);
    for (long j = 0; j < sz; j++)
      A[0][j] = 1;

    for (long i = 1; i < sz; i++)
      for (long j = 0; j < sz; j++)
	A[i][j] = (A[i-1][j] * points[j]) % G;

    if (invert) {
      REBak ebak; ebak.save(); ea.restoreContextForG();

      mat_RE A1, A2;
      conv(A1, A);

      long p = _ea.getAlMod().getZMStar().getP();
      long r = _ea.getAlMod().getR();

      ppInvert(A2, A1, p, r);
      conv(A, A2);
    }
  }

  bool get(RX& out, long i, long j, long k) const override {
    out = A[i][j];
    return false;
  }

  const EncryptedArray& getEA() const override { return base_ea; }
  bool multipleTransforms() const override { return false; }
  long getDim() const override { return dim; }
};

static MatMul1D*
buildStep2Matrix(const EncryptedArray& ea, shared_ptr<CubeSignature> sig,
                 const Vec<long>& reps, long dim, long cofactor,
                 bool invert)
{
  switch (ea.getTag()) {
  case PA_GF2_tag: 
    return new Step2Matrix<PA_GF2>(ea, sig, reps, dim, cofactor, invert);

  case PA_zz_p_tag: 
    return new Step2Matrix<PA_zz_p>(ea, sig, reps, dim, cofactor, invert);

  default: return 0;
  }
}

template<class type> class Step1Matrix : public BlockMatMul1D_derived<type> 
{
  PA_INJECT(type)

  const EncryptedArray& base_ea;
  shared_ptr<CubeSignature> sig;
  long dim;
  Mat< mat_R > A;

public:
  // constructor
  Step1Matrix(const EncryptedArray& _ea, shared_ptr<CubeSignature> _sig,
              const Vec<long>& reps, long _dim, long cofactor, bool invert,
              bool normal_basis)
    : base_ea(_ea), sig(_sig), dim(_dim)
  {
    const EncryptedArrayDerived<type>& ea = _ea.getDerived(type());
    RBak bak; bak.save(); _ea.getAlMod().restoreContext();
    const RX& G = ea.getG();
    long d = deg(G);

    long sz = sig->getDim(dim);
    assert(sz == reps.length());
    assert(dim == sig->getNumDims() - 1);
    assert(sig->getSize() == ea.size());

    // so sz == phi(m_last)/d, where d = deg(G) = order of p mod m

    Vec<RX> points(INIT_SIZE, sz);
    for (long j = 0; j < sz; j++) 
      points[j] = RX(reps[j]*cofactor, 1) % G;

    Mat<RX> AA(INIT_SIZE, sz*d, sz);
    for (long j = 0; j < sz; j++)
      AA[0][j] = 1;

    for (long i = 1; i < sz*d; i++)
      for (long j = 0; j < sz; j++)
	AA[i][j] = (AA[i-1][j] * points[j]) % G;

    A.SetDims(sz, sz);
    for (long i = 0; i < sz; i++)
      for (long j = 0; j < sz; j++) {
	A[i][j].SetDims(d, d);
	for (long k = 0; k < d; k++)
	  VectorCopy(A[i][j][k], AA[i*d + k][j], d);
      }

    if (invert) {
      mat_R A1, A2;
      A1.SetDims(sz*d, sz*d);
      for (long i = 0; i < sz*d; i++)
	for (long j = 0; j < sz*d; j++)
	  A1[i][j] = A[i/d][j/d][i%d][j%d];

      long p = _ea.getAlMod().getZMStar().getP();
      long r = _ea.getAlMod().getR();

      ppInvert(A2, A1, p, r);

      for (long i = 0; i < sz*d; i++)
	for (long j = 0; j < sz*d; j++)
	  A[i/d][j/d][i%d][j%d] = A2[i][j];
    
      if (normal_basis) {
	const Mat<R>& CB = ea.getNormalBasisMatrix();

	// multiply each entry of A on the right by CB
	for (long i = 0; i < sz; i++)
	  for (long j = 0; j < sz; j++)
	    A[i][j] =  A[i][j] * CB;
      } // if (normal_basis)
    } // if (invert)
  } // constructor

  bool get(mat_R& out, long i, long j, long k) const override {
    out = A[i][j];
    return false;
  }

  const EncryptedArray& getEA() const override { return base_ea; }
  bool multipleTransforms() const override { return false; }
  long getDim() const override { return dim; }
};

static BlockMatMul1D*
buildStep1Matrix(const EncryptedArray& ea, shared_ptr<CubeSignature> sig,
                 const Vec<long>& reps, long dim, long cofactor, bool invert,
                 bool normal_basis)
{
  switch (ea.getTag()) {
  case PA_GF2_tag: 
    return new Step1Matrix<PA_GF2>(ea, sig, reps, dim, cofactor, invert, normal_basis);

  case PA_zz_p_tag: 
    return new Step1Matrix<PA_zz_p>(ea, sig, reps, dim, cofactor, invert, normal_basis);

  default: return 0;
  }
}
//! \endcond


//=============== ThinEvalMap stuff

// needed to make generic programming work

void
RelaxedInv(Mat<zz_p>& x, const Mat<zz_p>& a)
{
   relaxed_inv(x, a);
}

void
RelaxedInv(Mat<GF2>& x, const Mat<GF2>& a)
{
   inv(x, a);
}


void TraceMap(GF2X& w, const GF2X& a, long d, const GF2XModulus& F, 
              const GF2X& b)

{
   if (d < 0) LogicError("TraceMap: bad args");

   GF2X y, z, t;

   z = b;
   y = a;
   clear(w);

   while (d) {
      if (d == 1) {
         if (IsZero(w)) 
            w = y;
         else {
            CompMod(w, w, z, F);
            add(w, w, y);
         }
      }
      else if ((d & 1) == 0) {
         Comp2Mod(z, t, z, y, z, F);
         add(y, t, y);
      }
      else if (IsZero(w)) {
         w = y;
         Comp2Mod(z, t, z, y, z, F);
         add(y, t, y);
      }
      else {
         Comp3Mod(z, t, w, z, y, w, z, F);
         add(w, w, y);
         add(y, t, y);
      }

      d = d >> 1;
   }
}



// Forward declerations
static MatMul1D*
buildThinStep1Matrix(const EncryptedArray& ea, shared_ptr<CubeSignature> sig,
                 const Vec<long>& reps, long dim, long cofactor);
static MatMul1D*
buildThinStep2Matrix(const EncryptedArray& ea, shared_ptr<CubeSignature> sig,
                 const Vec<long>& reps, long dim, long cofactor,
                 bool invert, bool inflate=false);
static void
init_representatives(Vec<long>& representatives, long dim, 
                     const Vec<long>& mvec, const PAlgebra& zMStar);


// Constructor: initializing tables for the evaluation-map transformations

ThinEvalMap::ThinEvalMap(const EncryptedArray& _ea, 
                 bool minimal,
                 const Vec<long>& mvec, 
                 bool _invert,
                 bool build_cache)

  : ea(_ea), invert(_invert)
{
  const FHEcontext& context = ea.getContext();
  const PAlgebra& zMStar = ea.getPAlgebra();
  
  long p = zMStar.getP();
  long d = zMStar.getOrdP();

  // FIXME: we should check that ea was initilized with 
  // G == factors[0], but this is a slight pain to check
  // currently

  // NOTE: this code is derived from a more general setting, and
  // could certainly be greatly simplified

  nfactors = mvec.length();
  assert(nfactors > 0);

  for (long i = 0; i < nfactors; i++)
    for (long j = i+1; j < nfactors; j++)
      assert(GCD(mvec[i], mvec[j]) == 1);

  long m = computeProd(mvec);
  assert(m == long(zMStar.getM()));

  Vec<long> phivec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)  phivec[i] = phi_N(mvec[i]);
  long phim = computeProd(phivec);

  Vec<long> dprodvec(INIT_SIZE, nfactors+1);
  dprodvec[nfactors] = 1;
  
  for (long i = nfactors-1; i >= 0; i--)
    dprodvec[i] = dprodvec[i+1] *
      multOrd(PowerMod(p % mvec[i], dprodvec[i+1], mvec[i]), mvec[i]);

  Vec<long> dvec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    dvec[i] = dprodvec[i] / dprodvec[i+1];

  long nslots = phim/d;
  assert(d == dprodvec[0]);
  assert(nslots == long(zMStar.getNSlots()));

  long inertPrefix = 0;
  for (long i = 0; i < nfactors && dvec[i] == 1; i++) {
    inertPrefix++;
  }

  if (inertPrefix != nfactors-1)
    Error("ThinEvalMap: case not handled: bad inertPrefix");

  Vec< Vec<long> > local_reps(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    init_representatives(local_reps[i], i, mvec, zMStar);

  Vec<long> crtvec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++) 
    crtvec[i] = (m/mvec[i]) * InvMod((m/mvec[i]) % mvec[i], mvec[i]);

  Vec<long> redphivec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    redphivec[i] = phivec[i]/dvec[i];

  CubeSignature redphisig(redphivec);

  Vec< shared_ptr<CubeSignature> > sig_sequence;
  sig_sequence.SetLength(nfactors+1);
  sig_sequence[nfactors] = shared_ptr<CubeSignature>(new CubeSignature(phivec));

  Vec<long> reduced_phivec = phivec;

  for (long dim = nfactors-1; dim >= 0; dim--) {
    reduced_phivec[dim] /= dvec[dim];
    sig_sequence[dim] = 
      shared_ptr<CubeSignature>(new CubeSignature(reduced_phivec));
  }

  matvec.SetLength(nfactors);

  if (invert) {
     long dim = nfactors - 1;
     unique_ptr<MatMul1D> mat1_data;
     mat1_data.reset(buildThinStep1Matrix(ea, sig_sequence[dim],
		     local_reps[dim], dim, m/mvec[dim]));
     matvec[dim].reset(new MatMul1DExec(*mat1_data, minimal));
  }
  else {
     long dim = nfactors - 1;
     unique_ptr<MatMul1D> mat1_data;
     mat1_data.reset(buildThinStep2Matrix(ea, sig_sequence[dim],
		     local_reps[dim], dim, m/mvec[dim], invert, /*inflate=*/true));
     matvec[dim].reset(new MatMul1DExec(*mat1_data, minimal));
  }

  for (long dim=nfactors-2; dim>=0; --dim) {
    unique_ptr<MatMul1D> mat_data;

    mat_data.reset(buildThinStep2Matrix(ea, sig_sequence[dim], local_reps[dim],
				       dim, m/mvec[dim], invert));
    matvec[dim].reset(new MatMul1DExec(*mat_data, minimal));
  }

  if (build_cache) upgrade();
}

void ThinEvalMap::upgrade()
{
  for (long i = 0; i < matvec.length(); i++)
    matvec[i]->upgrade();
}

// Applying the evaluation (or its inverse) map to a ciphertext
void ThinEvalMap::apply(Ctxt& ctxt) const
{
  if (!invert) { // forward direction
    for (long i = matvec.length()-1; i >= 0; i--)
      matvec[i]->mul(ctxt);
  }
  else {         // inverse transformation
    for (long i = 0; i < matvec.length(); i++)
      matvec[i]->mul(ctxt);
    traceMap(ctxt);
  }
}


// The callback interface for the matrix-multiplication routines.

//! \cond FALSE (make doxygen ignore these classes)
template<class type> class ThinStep2Matrix : public MatMul1D_derived<type> 
{
  PA_INJECT(type)

  const EncryptedArray& base_ea;
  shared_ptr<CubeSignature> sig;
  long dim;
  Mat<RX> A;

public:
  // constructor
  ThinStep2Matrix(const EncryptedArray& _ea,
              shared_ptr<CubeSignature> _sig, const Vec<long>& reps,
              long _dim, long cofactor, bool invert, bool inflate)
    : base_ea(_ea), sig(_sig), dim(_dim)
  {
    long sz = sig->getDim(dim);
    assert(sz == reps.length());

    const EncryptedArrayDerived<type>& ea = _ea.getDerived(type());
    RBak bak; bak.save(); _ea.getAlMod().restoreContext();
    const RX& G = ea.getG();
    long d = deg(G);

    Vec<RX> points(INIT_SIZE, sz);
    for (long j = 0; j < sz; j++) {
      points[j] = RX(reps[j]*cofactor, 1) % G;
      if (inflate) points[j] = PowerMod(points[j], d, G);
    }

    A.SetDims(sz, sz);
    for (long j = 0; j < sz; j++)
      A[0][j] = 1;

    for (long i = 1; i < sz; i++)
      for (long j = 0; j < sz; j++)
	A[i][j] = (A[i-1][j] * points[j]) % G;

    if (invert) {
      REBak ebak; ebak.save(); ea.restoreContextForG();

      mat_RE A1, A2;
      conv(A1, A);

      long p = _ea.getAlMod().getZMStar().getP();
      long r = _ea.getAlMod().getR();

      ppInvert(A2, A1, p, r);
      conv(A, A2);
    }
  }

  bool get(RX& out, long i, long j, long k) const override {
    out = A[i][j];
    return false;
  }

  const EncryptedArray& getEA() const override { return base_ea; }
  bool multipleTransforms() const override { return false; }
  long getDim() const override { return dim; }
};

static MatMul1D*
buildThinStep2Matrix(const EncryptedArray& ea, shared_ptr<CubeSignature> sig,
                 const Vec<long>& reps, long dim, long cofactor,
                 bool invert, bool inflate)
{
  switch (ea.getTag()) {
  case PA_GF2_tag: 
    return new ThinStep2Matrix<PA_GF2>(ea, sig, reps, dim, cofactor, invert, inflate);

  case PA_zz_p_tag: 
    return new ThinStep2Matrix<PA_zz_p>(ea, sig, reps, dim, cofactor, invert, inflate);

  default: return 0;
  }
}

template<class type> class ThinStep1Matrix : public MatMul1D_derived<type> 
{
  PA_INJECT(type)

  const EncryptedArray& base_ea;
  shared_ptr<CubeSignature> sig;
  long dim;
  Mat<RX> A_deflated;

public:
  // constructor
  ThinStep1Matrix(const EncryptedArray& _ea, shared_ptr<CubeSignature> _sig,
              const Vec<long>& reps, long _dim, long cofactor)
    : base_ea(_ea), sig(_sig), dim(_dim)
  {
    const EncryptedArrayDerived<type>& ea = _ea.getDerived(type());
    RBak bak; bak.save(); _ea.getAlMod().restoreContext();
    const RXModulus G(ea.getG());
    long d = deg(G);

    long p = _ea.getAlMod().getZMStar().getP();
    long r = _ea.getAlMod().getR();

    long sz = sig->getDim(dim);
    assert(sz == reps.length());
    assert(dim == sig->getNumDims() - 1);
    assert(sig->getSize() == ea.size());

    // so sz == phi(m_last)/d, where d = deg(G) = order of p mod m

    Vec<RX> points(INIT_SIZE, sz);
    for (long j = 0; j < sz; j++) 
      points[j] = RX(reps[j]*cofactor, 1) % G;

    Mat<RX> AA(INIT_SIZE, sz*d, sz);
    for (long j = 0; j < sz; j++)
      AA[0][j] = 1;

    for (long i = 1; i < sz*d; i++)
      for (long j = 0; j < sz; j++)
	AA[i][j] = (AA[i-1][j] * points[j]) % G;

    Mat<mat_R> A;
    A.SetDims(sz, sz);
    for (long i = 0; i < sz; i++)
      for (long j = 0; j < sz; j++) {
	A[i][j].SetDims(d, d);
	for (long k = 0; k < d; k++)
	  VectorCopy(A[i][j][k], AA[i*d + k][j], d);
      }

    // if (invert) {
    // NOTE: this version is only used for the inverse matrix
    mat_R A1, A2;
    A1.SetDims(sz*d, sz*d);
    for (long i = 0; i < sz*d; i++)
      for (long j = 0; j < sz*d; j++)
	A1[i][j] = A[i/d][j/d][i%d][j%d];

    ppInvert(A2, A1, p, r);

    for (long i = 0; i < sz*d; i++)
      for (long j = 0; j < sz*d; j++)
	A[i/d][j/d][i%d][j%d] = A2[i][j];
    // }

    A_deflated.SetDims(sz, sz);
    vec_R v, w;
    v.SetLength(d);
    w.SetLength(d);

    RX h;  // set h = X^p mod G
    PowerXMod(h, p, G);

    Vec<R> trace_vec;
    trace_vec.SetLength(2*d-1);
    // set trace_vec[i] = trace(X^i mod G) 
    for (long i = 0; i < 2*d-1; i++) {
      RX trace_val;
      TraceMap(trace_val, (RX(i, 1) % G), d, G, h);
      assert(deg(trace_val) <= 0);
      trace_vec[i] = ConstTerm(trace_val);
    }

    Mat<R> trace_mat; 
    trace_mat.SetDims(d, d);
    // set trace_mat[i][j] = trace(X^{i+j} mod G)
    for (long i = 0; i < d; i++)
      for (long j = 0; j < d; j++)
         trace_mat[i][j] = trace_vec[i+j];

    Mat<R> trace_mat_inv;
    RelaxedInv(trace_mat_inv, trace_mat);

    for (long i = 0 ; i < sz; i++)
      for (long j = 0; j < sz; j++) {
         for (long i1 = 0; i1 < d; i1++)
            v[i1] = A[i][j][i1][0];
         mul(w, v, trace_mat_inv);
         conv(A_deflated[i][j], w);
      }
  } // constructor

  bool get(RX& out, long i, long j, long k) const override {
    out = A_deflated[i][j];
    return false;
  }

  const EncryptedArray& getEA() const override { return base_ea; }
  bool multipleTransforms() const override { return false; }
  long getDim() const override { return dim; }
};

static MatMul1D*
buildThinStep1Matrix(const EncryptedArray& ea, shared_ptr<CubeSignature> sig,
                 const Vec<long>& reps, long dim, long cofactor)
{
  switch (ea.getTag()) {
  case PA_GF2_tag: 
    return new ThinStep1Matrix<PA_GF2>(ea, sig, reps, dim, cofactor);

  case PA_zz_p_tag: 
    return new ThinStep1Matrix<PA_zz_p>(ea, sig, reps, dim, cofactor);

  default: return 0;
  }
}
//! \endcond



