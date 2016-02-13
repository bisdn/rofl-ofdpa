#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([rofl-ofdpa], m4_esyscmd_s([./version.sh]), [rofl-devel@roflibs.org])

AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(config)

AM_INIT_AUTOMAKE([foreign -Wall -Werror])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CXX
AC_PROG_SED
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
PKG_PROG_PKG_CONFIG

LT_INIT

# todo: add http://www.gnu.org/software/autoconf-archive/ax_cxx_compile_stdcxx_11.html
CXXFLAGS="$CXXFLAGS -std=c++11"

AC_ARG_WITH([pkgconfigdir], AS_HELP_STRING([--with-pkgconfigdir=PATH],
        [Path to the pkgconfig directory [[LIBDIR/pkgconfig]]]),
        [pkgconfigdir="$withval"], [pkgconfigdir='${libdir}/pkgconfig'])
AC_SUBST([pkgconfigdir])

# Checks for libraries.
PKG_CHECK_MODULES([ROFL], rofl_common >= 0.10.0, [],
  [ AC_MSG_ERROR([minimum version of rofl_common is 0.10.0]) ])

# Checks for header files.
AC_CHECK_HEADER([inttypes.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.

AC_CONFIG_FILES([Makefile
                 rofl_ofdpa.pc
                 include/Makefile
                 lib/Makefile
		 pkg/rhel/rofl-ofdpa.spec])
AC_OUTPUT
