include $(top_srcdir)/build/Makefile.am.lm

SUBDIRS = parser-tests

noinst_PROGRAMS = $(TEST_PROGS)
TEST_PROGS = 

TEST_PROGS += test-parser                       \
			  test-data-objects

test_parser_SOURCES =                           \
	test-parser.c
	
test_data_objects_SOURCES =                     \
	test-data-objects.c                         \
	$(top_srcdir)/loudmouth/lm-data-objects.c

AM_CPPFLAGS =                                   \
	-I.                                         \
	-I$(top_srcdir)                             \
	-DLM_COMPILATION                            \
	-DRUNTIME_ENDIAN                            \
	$(LOUDMOUTH_CFLAGS)                         \
	-DPARSER_TEST_DIR="\"$(top_srcdir)/tests/parser-tests\""

LIBS =                                          \
	$(LOUDMOUTH_LIBS)                           \
	$(top_builddir)/loudmouth/libloudmouth-1.la

