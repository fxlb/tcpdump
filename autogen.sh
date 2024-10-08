#!/bin/sh -e

: "${AUTORECONF:=autoreconf}"

AUTORECONFVERSION=`$AUTORECONF --version 2>&1 | grep "^autoreconf" | sed 's/.*) *//'`

maj=`echo "$AUTORECONFVERSION" | cut -d. -f1`
min=`echo "$AUTORECONFVERSION" | cut -d. -f2`
# The minimum required version of autoconf is currently 2.69.
if [ "$maj" = "" ] || [ "$min" = "" ] || \
   [ "$maj" -lt 2 ] || { [ "$maj" -eq 2 ] && [ "$min" -lt 69 ]; }; then
	cat >&2 <<-EOF
	Please install the 'autoconf' package version 2.69 or later.
	If version 2.69 or later is already installed and there is no
	autoconf default, it may be necessary to set the AUTORECONF
	environment variable to enable the one to use, like:
	AUTORECONF=autoreconf-2.69 ./autogen.sh
	or
	AUTORECONF=autoreconf-2.71 ./autogen.sh
	EOF
	exit 1
fi

echo "$AUTORECONF identification: $AUTORECONFVERSION"

# configure.ac is an Autoconf 2.69 file, but it works as expected even with
# Autoconf 2.72.  However, in Autoconf versions 2.70 and later obsolete
# construct warnings are enabled by default, which adds varying (depending on
# the branch) amount of noise to the build matrix output, so provide a means
# to silence that.
env ${AUTOCONF_WARNINGS:+WARNINGS="$AUTOCONF_WARNINGS"} "$AUTORECONF" -f

# Autoconf 2.71 adds a blank line after the final "exit 0" on Linux, but not
# on OpenBSD.  Remove this difference to make it easier to compare the result
# of "make releasetar" across different platforms.  From sed one-liners:
# "delete all trailing blank lines at end of file (works on all seds)".  Don't
# use mktemp(1) because AIX does not have it.
CONFIGURE_NEW="configure.new$$"
sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' <configure >"$CONFIGURE_NEW"
cmp -s configure "$CONFIGURE_NEW" || cat "$CONFIGURE_NEW" >configure
rm -f "$CONFIGURE_NEW"
