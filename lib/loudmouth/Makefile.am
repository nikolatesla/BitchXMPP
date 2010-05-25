include $(top_srcdir)/build/Makefile.am.lm

SUBDIRS = loudmouth docs examples tests

EXTRA_DIST +=			\
	loudmouth-1.0.pc.in     \
	CONTRIBUTORS            \
	README.WIN32

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = loudmouth-1.0.pc

DISTCHECK_CONFIGURE_FLAGS =     \
	--enable-gtk-doc

