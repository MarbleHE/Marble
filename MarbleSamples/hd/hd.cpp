#include <vector>
using namespace std;

int hd_plaintext(vector<bool> v, vector<bool> u) {
    int sum = 0;
    for (int i = 0; i < v.size(); ++i) {
        sum += (v[i] != u[i]);
    }
    return sum;
}

int main() {

    vector<bool> v = {0, 1, 1, 0, 0/*...*/};
    vector<bool> u = {1, 0, 1, 0, 1/*...*/};
    hd_plaintext(v,u);
}