<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

   <xsl:output indent="no" encoding="utf-8" method="html"/>

   <xsl:strip-space elements="*"/>

   <xsl:param select="'../xml'" name="XML"/>

   <xsl:variable select="/module/@id" name="ID"/>

   <xsl:include href="directive.xslt"/>

   <xsl:include href="content.xslt"/>

   <xsl:template match="/module">

      <html>
         <head>

            <title>
               <xsl:value-of select="@name"/>
            </title>

         </head>

         <body>

            <center>
               <h3>
                  <xsl:value-of select="@name"/>
               </h3>
            </center>

            <xsl:apply-templates/>

         </body>

      </html>
   </xsl:template>

</xsl:stylesheet>
