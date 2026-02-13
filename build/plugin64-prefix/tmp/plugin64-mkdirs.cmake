# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "C:/Users/wurte/Desktop/x64dbgmcp"
  "C:/Users/wurte/Desktop/x64dbgmcp/build/build64"
  "C:/Users/wurte/Desktop/x64dbgmcp/build/plugin64-prefix"
  "C:/Users/wurte/Desktop/x64dbgmcp/build/plugin64-prefix/tmp"
  "C:/Users/wurte/Desktop/x64dbgmcp/build/plugin64-prefix/src/plugin64-stamp"
  "C:/Users/wurte/Desktop/x64dbgmcp/build/plugin64-prefix/src"
  "C:/Users/wurte/Desktop/x64dbgmcp/build/plugin64-prefix/src/plugin64-stamp"
)

set(configSubDirs Debug;Release;MinSizeRel;RelWithDebInfo)
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "C:/Users/wurte/Desktop/x64dbgmcp/build/plugin64-prefix/src/plugin64-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "C:/Users/wurte/Desktop/x64dbgmcp/build/plugin64-prefix/src/plugin64-stamp${cfgdir}") # cfgdir has leading slash
endif()
