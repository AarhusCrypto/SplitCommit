# SplitCommit

A portable C++14 implementation of the recent UC-secure additively homomorphic commitment scheme of [1]. The codebase builds heavily on the [libOTe](https://github.com/osu-crypto/libOTe) library for efficient oblivious transfer extension.

The library is written with efficiency in mind, while being flexible enough for various applications. Currently two message-sizes are supported, bit commitments and 128-bit commitments. More might be added in the future, but if you want/need to add this functionality let me know! 

### Performance

On a single Intel Xeon server (`2 36-cores Intel Xeon CPU E5-2699 v3 @ 2.30GHz and 256GB of RAM`), utilizing a *single thread* per party, the implementation can perform n=2<sup>24</sup> commitment in `11 seconds` (0.65 microseconds/per), decommit in `5.4 seconds` (0.32 microseconds/per), and batch-decommit in `4.6 seconds` (0.27 microseconds/per).

## Installation
The code has been tested to work on MacOS (10.12.1), Windows 10, and Ubuntu 16.04.

### Requirements
* C++ compiler with C++14 support. The code has been successfully built with GCC 5.3.1, GCC 6.1 and CLANG 3.8 and Microsoft Visual Studio. The project is self-contained, meaning no external libraries are required.

#### Linux/macOS
To clone, build and test the code:
* git clone --recursive https://github.com/AarhusCrypto/SplitCommit
* cd SplitCommit
* ./cmake-release.sh
* ./build/release/RunAllTests

If all tests succeed you are good to go.

#### Windows
In `powershell`, clone, build and test the code:
* git clone --recursive https://github.com/AarhusCrypto/SplitCommit
* cd SplitCommit/libs/libOTe
* ./buildAll.ps1
* cd ../..
* splitcommit.sln

Note: 
* gtest located at `./libs/googletest/gtest` must be manually built. That is, open `./libs/googletest/gtest/msvc/gtest.vcproj`, upgrade it if needed, and then build it with Visual Studio.
* If you have issue with `buildAll.ps1` which builds boost, miracl and libOTe, then follow the more manual instructions at [libOTe](https://github.com/osu-crypto/libOTe) which is what `buildAll.ps1` automates.

Run the `test-split-commit` project to perform the unit tests. 

## Running the main files
Two main files are produced during compilation, build/release/SplitCommitSender and build/release/SplitCommitReceiver. An example run of the two clients on different machines could be
* [Machine A] ./build/release/SplitCommitSender -n 10000 -e 8 -ip [A's IP] -p [port_num]
* [Machine B] ./build/release/SplitCommitReceiver -n 10000 -e 8 -ip [A's IP] -p [port_num]

The above code prints the time it takes to respectively perform OTs, commit, decommit and batch decommit for 10,000 random values. The -e parameters specifies how many parallel executions to run. No matter the number of parallel executions, the code only runs num_cpus executions concurrently.

## Acknowledgements
* A huge thanks goes out to [Peter Rindal](https://github.com/ladnir) for helping with the integration with libOTe and optimizing performance of the library.
* The author also heartedly thanks [Ignacio Cascudo Pueyo](http://vbn.aau.dk/en/persons/ignacio-cascudo-pueyo(2f2ded74-b364-4a8d-ada1-189dad083eea).html) and [Diego Ruano](http://vbn.aau.dk/en/persons/diego-ruano(d83d0116-0ba0-448c-aa87-b70afefd1fda).html) of Aalborg University for their invaluable help in creating the generator matrix for the [262,128,40] error correcting code used by the library.

## References
* [1] T. K. Frederiksen, T. P. Jakobsen, J. B. Nielsen, R. Trifiletti, “On the Complexity of Additively Homomorphic UC commitments,” in TCC 2016-A, Part I, ser. LNCS, E. Kushilevitz and T. Malkin, Eds., vol. 9562. Springer, Jan. 2016, pp. 542–565. Availible: http://ia.cr/2015/694.
