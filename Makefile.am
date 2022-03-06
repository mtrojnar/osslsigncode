AUTOMAKE_OPTIONS = foreign 1.10
MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/ylwrap \
	$(srcdir)/config.guess $(srcdir)/config.sub
EXTRA_DIST = .gitignore INSTALL.W32.md  NEWS.md  README.md  README.unauthblob.md  TODO.md

AM_CFLAGS = $(OPENSSL_CFLAGS) $(OPTIONAL_LIBCURL_CFLAGS)

bin_PROGRAMS = osslsigncode

osslsigncode_SOURCES = osslsigncode.c msi.c msi.h
osslsigncode_LDADD = $(OPENSSL_LIBS) $(OPTIONAL_LIBCURL_LIBS)

# bash completion script
AM_DISTCHECK_CONFIGURE_FLAGS = --with-bashcompdir='$$(datarootdir)/bash-completion/completions'
bashcompdir = @bashcompdir@
dist_bashcomp_DATA = osslsigncode.bash
