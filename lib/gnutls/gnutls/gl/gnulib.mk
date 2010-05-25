## DO NOT EDIT! GENERATED AUTOMATICALLY!
## Process this file with automake to produce Makefile.in.
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2010 Free
# Software Foundation, Inc.
#
# This file is free software, distributed under the terms of the GNU
# General Public License.  As a special exception to the GNU General
# Public License, this file may be distributed as part of a program
# that contains a configuration script generated by Autoconf, under
# the same distribution terms as the rest of that program.
#
# Generated by gnulib-tool.
# Reproduce by: gnulib-tool --import --dir=. --local-dir=gl/override --lib=libgnu --source-base=gl --m4-base=gl/m4 --doc-base=doc --tests-base=gl/tests --aux-dir=build-aux --with-tests --avoid=errno --avoid=fseeko --avoid=gettext-h --avoid=malloc-posix --avoid=realloc-posix --avoid=snprintf --avoid=stdbool --avoid=stdio --avoid=string --avoid=sys_socket --avoid=unistd --avoid=vasnprintf --makefile-name=gnulib.mk --libtool --macro-prefix=gl --no-vc-files arpa_inet autobuild error fdl gendocs getaddrinfo getline getpass-gnu gnupload gpl-3.0 inet_ntop inet_pton lgpl-2.1 maintainer-makefile progname readline version-etc-fsf


MOSTLYCLEANFILES += core *.stackdump

noinst_LTLIBRARIES += libgnu.la

libgnu_la_SOURCES =
libgnu_la_LIBADD = $(gl_LTLIBOBJS)
libgnu_la_DEPENDENCIES = $(gl_LTLIBOBJS)
EXTRA_libgnu_la_SOURCES =
libgnu_la_LDFLAGS = $(AM_LDFLAGS)

## begin gnulib module arpa_inet

BUILT_SOURCES += $(ARPA_INET_H)

# We need the following in order to create <arpa/inet.h> when the system
# doesn't have one.
arpa/inet.h:
	@MKDIR_P@ arpa
	rm -f $@-t $@
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
	  sed -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''NEXT_ARPA_INET_H''@|$(NEXT_ARPA_INET_H)|g' \
	      -e 's|@''HAVE_ARPA_INET_H''@|$(HAVE_ARPA_INET_H)|g' \
	      -e 's|@''GNULIB_INET_NTOP''@|$(GNULIB_INET_NTOP)|g' \
	      -e 's|@''GNULIB_INET_PTON''@|$(GNULIB_INET_PTON)|g' \
	      -e 's|@''HAVE_DECL_INET_NTOP''@|$(HAVE_DECL_INET_NTOP)|g' \
	      -e 's|@''HAVE_DECL_INET_PTON''@|$(HAVE_DECL_INET_PTON)|g' \
	      -e '/definition of GL_LINK_WARNING/r $(LINK_WARNING_H)' \
	      < $(srcdir)/arpa_inet.in.h; \
	} > $@-t
	mv $@-t $@
MOSTLYCLEANFILES += arpa/inet.h arpa/inet.h-t
MOSTLYCLEANDIRS += arpa

EXTRA_DIST += arpa_inet.in.h

## end   gnulib module arpa_inet

## begin gnulib module c-ctype

libgnu_la_SOURCES += c-ctype.h c-ctype.c

## end   gnulib module c-ctype

## begin gnulib module error


EXTRA_DIST += error.c error.h

EXTRA_libgnu_la_SOURCES += error.c

## end   gnulib module error

## begin gnulib module gendocs


EXTRA_DIST += $(top_srcdir)/build-aux/gendocs.sh

## end   gnulib module gendocs

## begin gnulib module getaddrinfo


EXTRA_DIST += gai_strerror.c getaddrinfo.c

EXTRA_libgnu_la_SOURCES += gai_strerror.c getaddrinfo.c

## end   gnulib module getaddrinfo

## begin gnulib module getdelim


EXTRA_DIST += getdelim.c

EXTRA_libgnu_la_SOURCES += getdelim.c

## end   gnulib module getdelim

## begin gnulib module getline


EXTRA_DIST += getline.c

EXTRA_libgnu_la_SOURCES += getline.c

## end   gnulib module getline

## begin gnulib module getpass-gnu


EXTRA_DIST += getpass.c getpass.h

EXTRA_libgnu_la_SOURCES += getpass.c

## end   gnulib module getpass-gnu

## begin gnulib module gnumakefile

distclean-local: clean-GNUmakefile
clean-GNUmakefile:
	test x'$(VPATH)' != x && rm -f $(top_builddir)/GNUmakefile || :

EXTRA_DIST += $(top_srcdir)/GNUmakefile

## end   gnulib module gnumakefile

## begin gnulib module gnupload


EXTRA_DIST += $(top_srcdir)/build-aux/gnupload

## end   gnulib module gnupload

## begin gnulib module havelib


EXTRA_DIST += $(top_srcdir)/build-aux/config.rpath

## end   gnulib module havelib

## begin gnulib module inet_ntop


EXTRA_DIST += inet_ntop.c

EXTRA_libgnu_la_SOURCES += inet_ntop.c

## end   gnulib module inet_ntop

## begin gnulib module inet_pton


EXTRA_DIST += inet_pton.c

EXTRA_libgnu_la_SOURCES += inet_pton.c

## end   gnulib module inet_pton

## begin gnulib module intprops


EXTRA_DIST += intprops.h

## end   gnulib module intprops

## begin gnulib module link-warning

LINK_WARNING_H=$(top_srcdir)/build-aux/link-warning.h

EXTRA_DIST += $(top_srcdir)/build-aux/link-warning.h

## end   gnulib module link-warning

## begin gnulib module maintainer-makefile

EXTRA_DIST += $(top_srcdir)/maint.mk

## end   gnulib module maintainer-makefile

## begin gnulib module netdb

BUILT_SOURCES += $(NETDB_H)

# We need the following in order to create <netdb.h> when the system
# doesn't have one that works with the given compiler.
netdb.h: netdb.in.h
	rm -f $@-t $@
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
	  sed -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''NEXT_NETDB_H''@|$(NEXT_NETDB_H)|g' \
	      -e 's|@''HAVE_NETDB_H''@|$(HAVE_NETDB_H)|g' \
	      -e 's|@''GNULIB_GETADDRINFO''@|$(GNULIB_GETADDRINFO)|g' \
	      < $(srcdir)/netdb.in.h; \
	} > $@-t
	mv $@-t $@
MOSTLYCLEANFILES += netdb.h netdb.h-t

EXTRA_DIST += netdb.in.h

## end   gnulib module netdb

## begin gnulib module netinet_in

BUILT_SOURCES += $(NETINET_IN_H)

# We need the following in order to create <netinet/in.h> when the system
# doesn't have one.
netinet/in.h: netinet_in.in.h
	@MKDIR_P@ netinet
	rm -f $@-t $@
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
	  sed -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''NEXT_NETINET_IN_H''@|$(NEXT_NETINET_IN_H)|g' \
	      -e 's|@''HAVE_NETINET_IN_H''@|$(HAVE_NETINET_IN_H)|g' \
	      < $(srcdir)/netinet_in.in.h; \
	} > $@-t
	mv $@-t $@
MOSTLYCLEANFILES += netinet/in.h netinet/in.h-t
MOSTLYCLEANDIRS += netinet

EXTRA_DIST += netinet_in.in.h

## end   gnulib module netinet_in

## begin gnulib module progname

libgnu_la_SOURCES += progname.h progname.c

## end   gnulib module progname

## begin gnulib module readline


EXTRA_DIST += readline.c readline.h

EXTRA_libgnu_la_SOURCES += readline.c

## end   gnulib module readline

## begin gnulib module stdarg

BUILT_SOURCES += $(STDARG_H)

# We need the following in order to create <stdarg.h> when the system
# doesn't have one that works with the given compiler.
stdarg.h: stdarg.in.h
	rm -f $@-t $@
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */' && \
	  sed -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''NEXT_STDARG_H''@|$(NEXT_STDARG_H)|g' \
	      < $(srcdir)/stdarg.in.h; \
	} > $@-t
	mv $@-t $@
MOSTLYCLEANFILES += stdarg.h stdarg.h-t

EXTRA_DIST += stdarg.in.h

## end   gnulib module stdarg

## begin gnulib module strerror


EXTRA_DIST += strerror.c

EXTRA_libgnu_la_SOURCES += strerror.c

## end   gnulib module strerror

## begin gnulib module version-etc

libgnu_la_SOURCES += version-etc.h version-etc.c

## end   gnulib module version-etc

## begin gnulib module version-etc-fsf

libgnu_la_SOURCES += version-etc-fsf.c

## end   gnulib module version-etc-fsf


mostlyclean-local: mostlyclean-generic
	@for dir in '' $(MOSTLYCLEANDIRS); do \
	  if test -n "$$dir" && test -d $$dir; then \
	    echo "rmdir $$dir"; rmdir $$dir; \
	  fi; \
	done; \
	:
