EXTRA_DIST = nuauth.fc nuauth.if nuauth.te nufw.fc nufw.if nufw.te README.selinux

SEMAKEFILE = /usr/share/doc/selinux-policy-dev/examples/Makefile
SEMAKE = $(MAKE) -f $(SEMAKEFILE)

nufw.pp: nufw.fc nufw.if nufw.te $(SEMAKEFILE)
	$(SEMAKE) $@

nuauth.pp: nuauth.fc nuauth.if nuauth.te $(SEMAKEFILE)
	$(SEMAKE) $@

policy: nufw.pp nuauth.pp

load: policy
	sudo $(SEMAKE) load

clean-local:
	[ ! -f $(SEMAKEFILE) ] || $(SEMAKE) clean
