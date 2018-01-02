# Check for rofl-common
#
#AC_CONFIG_SUBDIRS([libs/rofl-common])

AC_MSG_CHECKING(for rofl-common via directly specified paths)
rofl_common_found="yes"
AC_ARG_WITH(
    [rofl-common-headers],
    [AS_HELP_STRING([--with-rofl-common-headers],
    [location of the librofl-common headers])],
    [ROFL_INCLUDES+=" -I$withval"],
    [rofl_common_found="no"]
)
AC_ARG_WITH(
    [rofl-common-libs],
    [AS_HELP_STRING([--with-rofl-common-libs],
    [location of the librofl-common library files])],
    [ROFL_LDFLAGS+=" -L$withval"],
    [rofl_common_found="no"]
)
CPPFLAGS="$ROFL_INCLUDES $CPPFLAGS "
LDFLAGS="$ROFL_LDFLAGS $LDFLAGS "

if test "$rolf_common_found" = "yes"; then
    AC_MSG_RESULT(done)
else
    AC_MSG_RESULT([not found, checking via pkg-config])
    PKG_CHECK_MODULES([ROFL], rofl_common >= 0.11.0, [],
      [ AC_MSG_ERROR([minimum version of rofl_common is 0.11.0]) ])
fi


