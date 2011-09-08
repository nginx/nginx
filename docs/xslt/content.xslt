<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

   <xsl:template match="section[@id and @name]">

      <a name="{@id}"/> 
      <center>
         <h4>
            <xsl:value-of select="@name"/>
         </h4>
      </center>

      <xsl:apply-templates/>
   </xsl:template>

   <xsl:template match="section[not(@id) and @name]">

      <center>
         <h4>
            <xsl:value-of select="@name"/>
         </h4>
      </center>

      <xsl:apply-templates/>
   </xsl:template>

   <xsl:template match="section[not(@id) and not(@name)]">
      <xsl:apply-templates/>
   </xsl:template>

   <xsl:template match="para"> 
      <p>
         <xsl:apply-templates/>
      </p>
   </xsl:template>

   <xsl:template match="c-def"> 
      <code>
         <xsl:apply-templates/>
      </code>
   </xsl:template>

   <xsl:template match="c-func"> 
      <code>
         <xsl:apply-templates/>
         <xsl:text>()</xsl:text>
      </code>
   </xsl:template>

   <xsl:template match="code"> 
      <code>
         <xsl:apply-templates/>
      </code>
   </xsl:template>

   <xsl:template match="command"> 
      <code>
         <xsl:apply-templates/>
      </code>
   </xsl:template>

   <xsl:template match="dq">

      <xsl:text disable-output-escaping="yes">&amp;ldquo;</xsl:text>

      <xsl:apply-templates/>

      <xsl:text disable-output-escaping="yes">&amp;rdquo;</xsl:text>
   </xsl:template>

   <xsl:template match="example"> 
      <blockquote>
         <pre>
            <xsl:apply-templates/>
         </pre>
      </blockquote>
   </xsl:template>

   <xsl:template match="emphasis"> 
      <strong>
         <xsl:apply-templates/>
      </strong>
   </xsl:template>

   <xsl:template match="header"> 
      <code>
         <xsl:apply-templates/>
      </code>
   </xsl:template>

   <xsl:template match="http-error">

      <i>
         <xsl:text>"</xsl:text>
         <xsl:value-of select="@text"/>
         <xsl:text>"</xsl:text>
      </i>

      <xsl:text> (</xsl:text>
      <xsl:value-of select="@code"/>
      <xsl:text>)</xsl:text>
   </xsl:template>

   <xsl:template match="link[@url]"> 
      <a href="{@url}">
         <xsl:apply-templates/>
      </a>
   </xsl:template>

   <xsl:template match="link[@id and not(@doc)]"> 
      <a href="#{@id}">
         <xsl:apply-templates/>
      </a>
   </xsl:template>

   <xsl:template match="link[@doc and not(@id)]">

      <a href="{substring-before(@doc, '.xml')}.html">
         <xsl:apply-templates/>
      </a>
   </xsl:template>

   <xsl:template match="link[@id and @doc]">

      <a href="{substring-before(@doc, '.xml')}.html#{@id}">
         <xsl:apply-templates/>
      </a>
   </xsl:template>

   <xsl:template match="link"> 
      <u>
         <xsl:apply-templates/>
      </u>
   </xsl:template>

   <xsl:template match="list[@type='bullet']"> 
      <ul>
         <xsl:apply-templates/>
      </ul>
   </xsl:template>

   <xsl:template match="list[@type='enum']"> 
      <ol>
         <xsl:apply-templates/>
      </ol>
   </xsl:template>

   <xsl:template match="listitem"> 
      <li>
         <xsl:apply-templates/>
      </li>
   </xsl:template>

   <xsl:template match="list[@type='tag']"> 
      <dl compact="">
         <xsl:apply-templates/>
      </dl>
   </xsl:template>

   <xsl:template match="tag-name"> 
      <dt>
         <xsl:apply-templates/>
      </dt>
   </xsl:template>

   <xsl:template match="tag-desc"> 
      <dd>
         <xsl:apply-templates/>
      </dd>
   </xsl:template>

   <xsl:template match="pathname"> 
      <code>
         <xsl:apply-templates/>
      </code>
   </xsl:template>

   <xsl:template match="argument"> 
      <code>
         <i>
            <xsl:apply-templates/>
         </i>
      </code>
   </xsl:template>

   <xsl:template match="parameter"> 
      <code>
         <xsl:apply-templates/>
      </code>
   </xsl:template>

   <xsl:template match="value"> 
      <code>
         <xsl:apply-templates/>
      </code>
   </xsl:template>

   <xsl:template match="var"> 
      <code>
         <xsl:apply-templates/>
      </code>
   </xsl:template>

</xsl:stylesheet>
