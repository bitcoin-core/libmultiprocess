# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Uninstall.cmake -- script run by "make uninstall" to remove installed files.
#
# Install steps record the files they install in the build directory:
# "make install" writes install_manifest.txt, and "make install-bin" and
# "make install-lib" write install_manifest_<component>.txt files because they
# install single components. Remove every file listed in any of these
# manifests. Directories are left in place because they may be shared with
# other packages.
#
# Manifests list paths without the DESTDIR prefix, so DESTDIR is prepended here
# the same way cmake_install.cmake prepends it, and "make uninstall
# DESTDIR=<dir>" removes files installed by "make install DESTDIR=<dir>".

if(NOT DEFINED MP_INSTALL_MANIFEST_DIR)
  message(FATAL_ERROR "MP_INSTALL_MANIFEST_DIR must be set to the build directory.")
endif()

file(GLOB manifests "${MP_INSTALL_MANIFEST_DIR}/install_manifest*.txt")
if(NOT manifests)
  message(FATAL_ERROR
    "No install_manifest*.txt files found in ${MP_INSTALL_MANIFEST_DIR}.\n"
    "Nothing has been installed from this build directory.")
endif()

set(installed_files "")
foreach(manifest IN LISTS manifests)
  file(STRINGS "${manifest}" files)
  list(APPEND installed_files ${files})
endforeach()
if(installed_files)
  list(REMOVE_DUPLICATES installed_files)
endif()

foreach(file IN LISTS installed_files)
  set(file "$ENV{DESTDIR}${file}")
  if(EXISTS "${file}" OR IS_SYMLINK "${file}")
    message(STATUS "Uninstalling: ${file}")
    file(REMOVE "${file}")
    if(EXISTS "${file}" OR IS_SYMLINK "${file}")
      message(FATAL_ERROR "Failed to remove ${file}. Check that you have permission to modify the install prefix.")
    endif()
  else()
    message(STATUS "Not found, skipping: ${file}")
  endif()
endforeach()
