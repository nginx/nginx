<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

   
   <xsl:template match="directive">
    
      <a name="{@name}"/> 
      <center>
         <h4>
            <xsl:value-of select="@name"/> 
         </h4>
      </center>
      <xsl:apply-templates select="syntax"/>
      <xsl:apply-templates select="default"/>
      <xsl:apply-templates select="context"/>
      <xsl:apply-templates select="para"/>
   </xsl:template>
   
   <xsl:template match="syntax">
      <xsl:text>syntax: </xsl:text>
      <xsl:apply-templates/> 
      <br/>
   </xsl:template>
   
   <xsl:template match="default">
      <xsl:text>default: </xsl:text>
      <xsl:apply-templates/> 
      <br/>
   </xsl:template>
   
   <xsl:template match="context">
      <xsl:text>context: </xsl:text>
      <xsl:apply-templates/> 
      <br/>
   </xsl:template>
</xsl:stylesheet>