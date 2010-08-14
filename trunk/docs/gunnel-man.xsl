<?xml version="1.0" ?>

<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:fo="http://www.w3.org/1999/XSL/Format" >

	<!-- Stylesheet location for Debian GNU/Linux. -->
	<xsl:import href="file:///usr/share/xml/docbook/stylesheet/nwalsh/manpages/docbook.xsl" />

	<xsl:param name="man.output.in.separate.dir">1</xsl:param>
	<xsl:param name="man.output.base.dir">docs/</xsl:param>
	<xsl:param name="man.output.subdirs.enabled">0</xsl:param>

</xsl:stylesheet>
