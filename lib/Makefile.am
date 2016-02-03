MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

lib_LTLIBRARIES = librofl_ofdpa.la

librofl_ofdpa_la_SOURCES = \
	rofl_ofdpa_fm_driver.cpp \
	ofdpa_datatypes.h

librofl_ofdpa_la_CPPFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	${ROFL_CFLAGS}	
	
librofl_ofdpa_la_LIBADD = \
	${ROFL_LIBS}
