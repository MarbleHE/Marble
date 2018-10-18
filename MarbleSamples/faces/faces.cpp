#include <vector>
#include <functional>
#include "M.h"

using namespace std;
using namespace Marble;

void faces(M in, M db, int dim, int n) {
    output(in,"in");
    output(db,"db");
    M diff = in - db;
    output(diff,"diff");
    M sq = diff * diff;
    output(sq,"sq");

    // SIMD-summation over all dimensions of each face
    M res = sq.fold(sum, dim);
    output(res,"res");
    // SIMD-minimum-index
    M index;
    M min = res.fold(min_with_index, index, dim, 1);
    output(min, "min");
    output(index, "index");
}


int main() {
    // Database of faces templates
    vector<int> face1 = {20, 78, 15 /*...*/};
    vector<int> face2 = {67, 53, 49 /*...*/};
    vector<int> face3 = {76, 112, 40 /*...*/};
    vector<vector<int>> db /*= {face1,face2, ...}*/;
    db.push_back(face1); db.push_back(face2); db.push_back(face3);
    int n = db.size();
    int dim = db[0].size();

    // Input face representation
    vector<int> in = {76, 112, 40 /*...*/};

    // Batched Encryption
    vector<int> db_batched, in_batched;
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < db[i].size(); ++j) {
            db_batched.push_back(db[i][j]);
            in_batched.push_back(in[j]);
        }
    }

    M db_enc = encrypt(batched, db_batched, /*bitSize=*/8);
    M in_enc = encrypt(batched, in_batched, /*bitSize=*/8);

    M::evaluate(bind(faces, in_enc, db_enc, dim, n));

    return 0;
}