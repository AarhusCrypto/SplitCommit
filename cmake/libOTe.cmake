set(libOTe_DIR "${CMAKE_SOURCE_DIR}/libs/libOTe")
add_definitions(-DSOLUTION_DIR=\"${libOTe_DIR}\")

set(Miracl_DIR "${libOTe_DIR}/thirdparty/linux/miracl")
if(NOT EXISTS ${Miracl_DIR})
   execute_process(COMMAND bash "all.get" WORKING_DIRECTORY "${libOTe_DIR}/thirdparty/linux/")
endif(NOT EXISTS ${Miracl_DIR})

include_directories(${Miracl_DIR}) 
link_directories("${Miracl_DIR}/miracl/source/")

set(BOOST_ROOT "${libOTe_DIR}/thirdparty/linux/boost/")
# if($ENV{nasm} MATCHES "")
  # message(WARNING "\nnasm environment variable NOT defined!!!! This means the fast SHA1 function will not be used.")

  # define this so that the asm is disabled.
  add_definitions(-DNO_INTEL_ASM_SHA1=1)
  # set(shaNasmOutput )
  # add_custom_target(sha_asm)
  
# else()
#     set(shaNasm "${libOTe_DIR}/cryptoTools/Crypto/asm/sha_lnx.S")
#         set(shaNasmOutput "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/cryptoTools.dir/Crypto/sha_lnx.S.o")
      
#         add_custom_command(
#                 OUTPUT ${shaNasmOutput}
#                 DEPENDS ${shaNasm} 
#                 COMMENT "nasm -f elf64 ${shaNasm} -o ${shaNasmOutput}"
#                 COMMAND "nasm" "-f elf64" "${shaNasm}" "-o ${shaNasmOutput}"
#                 VERBATIM)


#   # mark this asm output input to everything.
#   add_custom_target(sha_asm DEPENDS ${shaNasmOutput})
# endif()


file(GLOB_RECURSE cryptoTools_SRCS ${libOTe_DIR}/cryptoTools/*.cpp)

include_directories(${libOTe_DIR})
add_library(cryptoTools ${cryptoTools_SRCS} ${shaNasmOutput})
# add_dependencies(cryptoTools sha_asm)



###########################################################################  
###########################################################################  
#                        Link external libraries                          #
#                        -----------------------                          #
#                                                                         #
#  Define the expected location for miracl and boost.                     #
#  Boost will be found using the findBoost  module in CMake               #
#  It should look in the location specified and then look elsewhere       # 
#                                                                         #
###########################################################################  
  
find_library(
  MIRACL_LIB 
  NAMES miracl  
  HINTS "${Miracl_DIR}/miracl/source/")
  
# if we cant fint it, throw an error
if(NOT MIRACL_LIB)
  Message(${MIRACL_LIB})
  message(FATAL_ERROR "Failed to find miracl at " "${Miracl_DIR}/miracl/source/")
endif()


set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

find_package(Boost COMPONENTS system thread)

if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIR}) 
  #message( "Found Boost at ${Boost_LIBRARIES}")
else()
   message(FATAL_ERROR "Failed to find boost at " ${Boost_Lib_Dirs} " Need system thread")
endif()

# target_link_libraries(cryptoTools sha_asm)
target_link_libraries(cryptoTools ${MIRACL_LIB})
target_link_libraries(cryptoTools ${Boost_LIBRARIES})


file(GLOB_RECURSE libOTe_SRCS ${libOTe_DIR}/libOTe/*.cpp)
include_directories(${libOTe_DIR}/libOTe)
add_library(libOTe ${libOTe_SRCS})
target_link_libraries(libOTe cryptoTools)

file(GLOB_RECURSE libOTe_Tests_SRCS ${libOTe_DIR}/libOTe_Tests/*.cpp)
include_directories(${libOTe_DIR}/libOTe_Tests/)
add_library(libOTe_Tests ${libOTe_Tests_SRCS})
target_link_libraries(libOTe_Tests libOTe)