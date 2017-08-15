ACLOCAL_AMFLAGS = -I config

SUBDIRS = include lib

MAINTAINERCLEANFILES = \
	$(top_srcdir)/aclocal.m4 \
	$(top_srcdir)/configure \
	$(top_srcdir)/Makefile.in \
	$(top_srcdir)/config/libtool.m4 \
	$(top_srcdir)/config/lt~obsolete.m4 \
	$(top_srcdir)/config/ltoptions.m4 \
	$(top_srcdir)/config/ltsugar.m4 \
	$(top_srcdir)/config/ltversion.m4

pkgconfig_DATA = \
	rofl_ofdpa.pc

EXTRA_DIST = \
	autogen.sh \
	VERSION

format:
	find $(top_srcdir) -regex '.*\.\(hh?\|cc?\|hpp\|cpp\)$$' | xargs clang-format -i -style=file

maintainer-clean-local:
	rm -rf $(top_srcdir)/build-aux
