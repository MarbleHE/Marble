# Marble

This is the Marble FHE framework, a C++ middleware library that translates between user programs written close-to-plaintext-style and FHE computations based on underlying FHE crpto libraries (HElib, SEAL,<your library here?>...).
You can see an example of a [plaintext function](MarbleSamples/hd/hd.cpp) and the corresponding [Marble version](MarbleSamples/hd_enc/hd_enc.cpp) to get an idea of how the framework works.
See the corresponding [paper](https://dl.acm.org/citation.cfm?id=3267978) for more information.

In order to build Marble, run the following
```
git clone https://github.com/MarbleHE/Marble.git
cd Marble
mkdir build
cd build
cmake ..
make all
```
You can then run the examples using e.g. `./MarbleSamples/ads/MarbleSamples_Ads` for the ads example.


This repository currently holds v0.1 which is an out-of-date proof of concept version with support for HElib only. 
The current in-development version as presented at [WAHC18](http://homomorphicencryption.org/workshops/wahc18/) will be released as v1.0 (or at least v0.9 ;) soon (TM) once we are done updating from SEAL 2.3.1 to SEAL 3.0
