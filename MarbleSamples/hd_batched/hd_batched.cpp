#include <vector>
#include <functional>
#include "M.h"

using namespace std;
using namespace Marble;


void hd_batched(M v, M u) {
    M diff = (v != u);
    diff.fold(sum);
    output(diff);
}

int main() {
    vector<bool> v = {0, 1, 1, 0, 0/*...*/};
    vector<bool> u = {1, 0, 1, 0, 1/*...*/};

    M v_enc = encrypt(batched, v);
    M u_enc = encrypt(batched, u);

    // Simulates the execution and
    // reports e.g. multiplicative depth
    M::analyse(bind(hd_batched, v_enc, u_enc));

    // Benchmarks the application,
    // using the most appropriate settings
    M::evaluate(bind(hd_batched, v_enc, u_enc));

    return 0;
}