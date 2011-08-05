<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

   
   <xsl:template match="section[@name and @title]">
    
      <a name="{@name}"/> 
      <center>
         <h4>
            <xsl:value-of select="@title"/> 
         </h4>
      </center>
      <xsl:apply-templates/>
   </xsl:template>
   
   <xsl:template match="section[not(@name) and @title]">
    
      <center>
         <h4>
            <xsl:value-of select="@title"/> 
         </h4>
      </center>
      <xsl:apply-templates/>
   </xsl:template>
   
   <xsl:template match="section[not(@name) and not(@title)]">
      <xsl:apply-templates/>
   </xsl:template>

   
   <xsl:template match="para"> 
      <p>
         <xsl:apply-templates/> 
      </p>
   </xsl:template>

   
   <xsl:template match="value"> 
      <i>
         <xsl:apply-templates/> 
      </i>
   </xsl:template>
</xsl:stylesheet>