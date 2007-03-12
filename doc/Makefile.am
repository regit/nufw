man_MANS = nuaclgen.8 nuauth.8 nufw.8 nufw_dbm.8 nutcpc.1 nutop.8 libnuclient.3

EXTRA_DIST = $(man_MANS)

STYLESHEET=/usr/share/xml/docbook/stylesheet/nwalsh/html/docbook.xsl 
STYLEPDF=/usr/share/xml/docbook/stylesheet/nwalsh/pdf/docbook.xsl 

PARAMS=--stringparam html.stylesheet ck-style.css --stringparam section.autolabel 1 

references: references.xml
	xsltproc ${PARAMS} --output references.html ${STYLESHEET} references.xml

howto: howto.xml
	xsltproc ${PARAMS} --output howto.html ${STYLESHEET} howto.xml

pdf: howto.xml references.xml
	docbook2pdf howto.xml
	docbook2pdf references.xml

