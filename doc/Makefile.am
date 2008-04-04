man_MANS = nuaclgen.8 nuauth.8 nufw.8 nutcpc.1 nutop.8 libnuclient.3

README_FILES = README.auth_mysql README.iface README.ldap README.log_mysql README.mark README.pam_nufw
DOC_FILES = acls cache_system debug
MAN_SOURCE_FILES = libnuclient.3.sgml nuaclgen.8.sgml nuauth.8.sgml nufw.8.sgml nutcpc.1.sgml nutop.8.sgml

EXTRA_DIST = $(man_MANS) $(README_FILES) $(MAN_SOURCE_FILES) $(DOC_FILES)

STYLESHEET=/usr/share/xml/docbook/stylesheet/nwalsh/html/docbook.xsl 
STYLEPDF=/usr/share/xml/docbook/stylesheet/nwalsh/pdf/docbook.xsl 

PARAMS=--stringparam html.stylesheet ck-style.css --stringparam section.autolabel 1 

references: references.xml
	xsltproc ${PARAMS} --output references.html ${STYLESHEET} references.xml

howto: howto.xml
	xsltproc ${PARAMS} --output howto.html ${STYLESHEET} howto.xml

pdf: howto.pdf references.pdf

%.pdf: %.xml
	${DOCBOOK2PDF} $<

%.8: %.8.sgml
	${DOCBOOK2MAN} $<

%.1: %.1.sgml
	${DOCBOOK2MAN} $<

%.3: %.3.sgml
	${DOCBOOK2MAN} $<
