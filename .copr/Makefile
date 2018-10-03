srpm:
	INSTALL="" ;\
	which git || INSTALL="$$INSTALL git" ;\
	which envsubst || INSTALL="$$INSTALL gettext" ;\
	test -n "$$INSTALL" && dnf install $$INSTALL ; :

	make -C $(dir $(spec)) outdir="$(outdir)" spec="$(spec)"
