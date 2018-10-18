
#include <vector>
#include <functional>
#include "M.h"

using namespace std;
using namespace Marble;

void ads(M x_u, M y_u, M r_inv, M x, M y) {
    M d1 = x_u - x;
    M d2 = y_u - y;
    M ctr = r_inv * (d1 * d1 + d2 * d2);
    M index;
    M min = ctr.fold(min_with_index, index);
    output(index);
}

int main() {
    // Coordinates and relevance of advertised places
    vector<int> x = {114, 254, 35, 12 /*...*/};
    vector<int> y = {76, 112, 40, 111 /*...*/};
    vector<int> r_inv = {4, 2, 2, 5 /*...*/};

    // User coordinates
    vector<int> x_u = {17, 17, 17 , 17/*...*/};
    vector<int> y_u = {158, 158, 158, 158 /*...*/};

    M x_enc = encode(batched, x, /*bitSize=*/8);
    M y_enc = encode(batched, y, /*bitSize=*/8);
    M r_inv_enc = encode(batched, r_inv, /*bitSize=*/8);
    M x_u_enc = encrypt(batched, x_u,/*bitSize=*/8);
    M y_u_enc = encrypt(batched, y_u,/*bitSize=*/8);

    M::evaluate(bind(ads, x_u_enc, y_u_enc, r_inv_enc, x_enc, y_enc));

    return 0;
}