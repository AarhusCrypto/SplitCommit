#SplitCommit

A portable C++14 implementation of the recent UC-secure additively homomorphic commitment scheme of [1]. The codebase builds heavily on the [libOTe](https://github.com/osu-crypto/libOTe) library for efficient oblivious transfer extension.

The library is written with efficiency in mind, while being flexible enough for various applications. Currently two message-sizes are supported, bit commitments and 128-bit commitments. More might be added in the future, but if you want/need to add this functionality let me know! 

##Installation
The code has been tested to work on MacOS (10.12.1), Windows 10, and Ubuntu 16.04.

###Requirements
* C++ compiler with C++14 support. The code has been successfully built with GCC 5.3.1, GCC 6.1 and CLANG 3.8 and Microsoft Visual Studio. The project is self-contained, meaning no external libraries are required.

To clone, build and test the code:
* git clone --recursive https://github.com/AarhusCrypto/SplitCommit
* cd splitcommit
* ./cmake-release
* ./build/release/TestSplitCommit

If all tests succeed you are good to go.

##Running the main files
Two main files are produced during compilation, build/release/SplitCommitSender and build/release/SplitCommitReceiver. An example run of the two clients on different machines could be
* [Machine A] ./build/release/SplitCommitSender -n 10000 -e 8 -ip [A's IP] -p [port_num]
* [Machine B] ./build/release/SplitCommitReceiver -n 10000 -e 8 -ip [A's IP] -p [port_num]

The above code prints the time it takes to respectively perform OTs, commit, decommit and batch decommit for 10,000 random values. The -e parameters specifies how many parallel executions to run. No matter the number of parallel executions, the code only runs num_cpus executions concurrently.

##Acknowledgements
* A huge thanks goes out to [Peter Rindal](https://github.com/ladnir) for helping with the integration with libOTe and optimizing performance of the library.
* The author also heartedly thanks [Ignacio Cascudo Pueyo](http://vbn.aau.dk/en/persons/ignacio-cascudo-pueyo(2f2ded74-b364-4a8d-ada1-189dad083eea).html) and [Diego Ruano](http://vbn.aau.dk/en/persons/diego-ruano(d83d0116-0ba0-448c-aa87-b70afefd1fda).html) of Aalborg University for their invaluable help in creating the generator matrix for the [262,128,40] error correcting code used by the library.

##References
* [1] T. K. Frederiksen, T. P. Jakobsen, J. B. Nielsen, R. Trifiletti, “On the Complexity of Additively Homomorphic UC commitments,” in TCC 2016-A, Part I, ser. LNCS, E. Kushilevitz and T. Malkin, Eds., vol. 9562. Springer, Jan. 2016, pp. 542–565.
