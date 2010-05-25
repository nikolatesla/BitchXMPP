dnl GLIB_GSETTINGS
dnl Defines GSETTINGS_SCHEMAS_INSTALL which controls whether
dnl the schema should be compiled
dnl

AC_DEFUN([GLIB_GSETTINGS],
[
  m4_pattern_allow([AM_V_GEN])
  AC_ARG_ENABLE(schemas-compile,
                AC_HELP_STRING([--disable-schemas-compile],
                               [Disable regeneration of gschemas.compiled on install]),
                [case ${enableval} in
                  yes) GSETTINGS_DISABLE_SCHEMAS_COMPILE=""  ;;
                  no)  GSETTINGS_DISABLE_SCHEMAS_COMPILE="1" ;;
                  *) AC_MSG_ERROR([bad value ${enableval} for --enable-schemas-compile]) ;;
                 esac])
  AC_SUBST([GSETTINGS_DISABLE_SCHEMAS_COMPILE])
  PKG_PROG_PKG_CONFIG([0.16])
  AC_SUBST(gsettingsschemadir, [${datadir}/glib-2.0/schemas])
  AC_SUBST(GLIB_COMPILE_SCHEMAS, `$PKG_CONFIG --variable glib_compile_schemas gio-2.0`)
  if test "x$GLIB_COMPILE_SCHEMAS" = "x"; then
    AC_MSG_ERROR([glib-compile-schemas not found.])
  fi

  GSETTINGS_RULES='
.PHONY : uninstall-gsettings-schemas install-gsettings-schemas clean-gsettings-schemas

mostlyclean-am: clean-gsettings-schemas

%.gschema.valid: %.gschema.xml
	$(AM_V_GEN) $(GLIB_COMPILE_SCHEMAS) --dry-run --schema-file=$^ && touch [$]@

all-am: $(gsettings_SCHEMAS:.xml=.valid)
uninstall-am: uninstall-gsettings-schemas
install-data-am: install-gsettings-schemas

.SECONDARY: $(gsettings_SCHEMAS)

gsettings__base_list = \
  sed "$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;s/\n/ /g" | \
  sed "$$!N;$$!N;$$!N;$$!N;s/\n/ /g"

install-gsettings-schemas: $(gsettings_SCHEMAS:.xml=.valid)
	@$(NORMAL_INSTALL)
	test -z "$(gsettingsschemadir)" || $(MKDIR_P) "$(DESTDIR)$(gsettingsschemadir)"
	@list='\''$(gsettings_SCHEMAS)'\''; test -n "$(gsettingsschemadir)" || list=; \
	for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  echo "$$d$$p"; \
	done | $(gsettings__base_list) | \
	while read files; do \
	  echo " $(INSTALL_DATA) $$files '\''$(DESTDIR)$(gsettingsschemadir)'\''"; \
	  $(INSTALL_DATA) $$files "$(DESTDIR)$(gsettingsschemadir)" || exit $$?; \
	done
	test -n "$(GSETTINGS_DISABLE_SCHEMAS_COMPILE)$(DESTDIR)" || $(GLIB_COMPILE_SCHEMAS) $(gsettingsschemadir)

uninstall-gsettings-schemas:
	@$(NORMAL_UNINSTALL)
	@list='\''$(gsettings_SCHEMAS)'\''; test -n "$(gsettingsschemadir)" || list=; \
	files=`for p in $$list; do echo $$p; done | sed -e '\''s|^.*/||'\''`; \
	test -n "$$files" || exit 0; \
	echo " ( cd '\''$(DESTDIR)$(gsettingsschemadir)'\'' && rm -f" $$files ")"; \
	cd "$(DESTDIR)$(gsettingsschemadir)" && rm -f $$files
	test -n "$(GSETTINGS_DISABLE_SCHEMAS_COMPILE)$(DESTDIR)" || $(GLIB_COMPILE_SCHEMAS) --uninstall $(gsettingsschemadir)

clean-gsettings-schemas:
	rm -f $(gsettings_SCHEMAS:.xml=.valid)

'
  _GSETTINGS_SUBST(GSETTINGS_RULES)
])

dnl _GSETTINGS_SUBST(VARIABLE)
dnl Abstract macro to do either _AM_SUBST_NOTMAKE or AC_SUBST
AC_DEFUN([_GSETTINGS_SUBST],
[
AC_SUBST([$1])
m4_ifdef([_AM_SUBST_NOTMAKE], [_AM_SUBST_NOTMAKE([$1])])
]
)
