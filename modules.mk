mod_antiloris.la: mod_antiloris.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_antiloris.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_antiloris.la
