#include <vector>
#include <functional>
#include "M.h"

using namespace std;
using namespace Marble;

void hd_enc(vector<M> v, vector<M> u) {
    M sum = 0;
    for (int i = 0; i < v.size(); ++i) {
        sum += (v[i] != u[i]);
    }
    output(sum);
}

int main() {
    vector<bool> v = {0, 1, 1, 0, 0/*...*/};
    vector<bool> u = {1, 0, 1, 0, 1/*...*/};

    vector<M> v_enc = encrypt(v);
    vector<M> u_enc = encrypt(u);

    // Simulates the execution and
    // reports e.g. multiplicative depth
    M::analyse(bind(hd_enc, v_enc, u_enc));

    // Benchmarks the application,
    // using the most appropriate settings
    M::evaluate(bind(hd_enc, v_enc, u_enc));

    return 0;
}