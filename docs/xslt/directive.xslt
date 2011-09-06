<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

   <xsl:template match="directive">

      <hr/>

      <a name="{@name}"/>
        <!-- <center><h4><xsl:value-of select="@name"/> </h4></center> -->

      <xsl:apply-templates select="syntax"/>

      <xsl:apply-templates select="default"/>

      <xsl:apply-templates select="context"/>

      <xsl:if test="(@appeared-in)">

         <strong>appeared in version</strong>:
         <xsl:value-of select="@appeared-in"/>
      </xsl:if>

      <xsl:apply-templates select="para"/>
   </xsl:template>

   <xsl:template match="syntax">
      <xsl:choose>

         <xsl:when test="position() = 1">

            <strong>syntax</strong>:
         </xsl:when>

         <xsl:otherwise>

            <code>       </code>
         </xsl:otherwise>
      </xsl:choose>

      <code>

         <xsl:apply-templates/> 
      </code>
      <br/>
   </xsl:template>

   <xsl:template match="default">

      <strong>default</strong>:
      <xsl:choose>

         <xsl:when test="count(text()) = 0">

            <strong>none</strong>
         </xsl:when>

         <xsl:otherwise>

            <code>
               <xsl:apply-templates/>
            </code>
         </xsl:otherwise>
      </xsl:choose>

      <br/>
   </xsl:template>

   <xsl:template match="context">

      <xsl:if test="position() = 1">

         <strong>context</strong>:
      </xsl:if>
      <xsl:choose>

         <xsl:when test="count(text()) = 0">

            <strong>any</strong>
         </xsl:when>

         <xsl:otherwise>

            <code>
               <xsl:apply-templates/>
            </code>
         </xsl:otherwise>
      </xsl:choose>
      <xsl:choose>

         <xsl:when test="position() != last()">

            <xsl:text>, </xsl:text>
         </xsl:when>

         <xsl:otherwise>

            <br/>
         </xsl:otherwise>
      </xsl:choose>
   </xsl:template>

</xsl:stylesheet>
