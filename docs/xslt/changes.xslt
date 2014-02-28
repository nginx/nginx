<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:output method="text"/>

<xsl:param select="'en'" name="lang"/>
<xsl:param select="'../xml/change_log_conf.xml'" name="configuration"/>

<xsl:variable select="document($configuration)/configuration" name="conf"/>
<xsl:variable select="$conf/start" name="start"/>
<xsl:variable select="$conf/indent" name="indent"/>
<xsl:variable select="$conf/length" name="max"/>
<xsl:variable name="br">&lt;br&gt;</xsl:variable>


<xsl:template match="/"> <xsl:apply-templates select="change_log"/> </xsl:template>
<xsl:template match="change_log"> <xsl:apply-templates select="changes"/> </xsl:template>


<xsl:template match="changes">
    <xsl:text>&#10;</xsl:text>

    <xsl:value-of select="substring(concat($conf/changes[@lang=$lang]/title,
                       //change_log/@title,
                       ' ', @ver,
                       '                                                    '),
                1, $conf/changes[@lang=$lang]/length)"/>

    <xsl:if test="$lang='ru'"> <xsl:value-of select="@date"/> </xsl:if>

    <xsl:if test="$lang='en'">
        <xsl:value-of select="substring(@date, 1, 2)"/>
        <xsl:value-of select="$conf/changes[@lang=$lang]/month[number(substring(current()/@date,
                                                            4, 2))]"/>
        <xsl:value-of select="substring(@date, 7, 4)"/>
    </xsl:if>

    <xsl:text>&#10;</xsl:text>

    <xsl:apply-templates select="change"/>

    <xsl:text>&#10;</xsl:text>
</xsl:template>


<xsl:template match="change">
    <xsl:variable select="$conf/changes[@lang=$lang]/*[local-name(.)=current()/@type]" name="prefix"/>

    <xsl:variable name="postfix"> <xsl:if test="$prefix"> <xsl:text>: </xsl:text> </xsl:if> </xsl:variable>

    <xsl:apply-templates select="para[@lang=$lang]"><xsl:with-param select="concat($start, $prefix, $postfix)" name="prefix"/></xsl:apply-templates>
</xsl:template>


<xsl:template name="para" match="para"><xsl:param name="prefix"/>
    <xsl:variable name="text"> <xsl:apply-templates/> </xsl:variable>

    <xsl:text>&#10;</xsl:text>

    <xsl:call-template name="wrap"><xsl:with-param select="normalize-space($text)" name="text"/><xsl:with-param name="prefix"> <xsl:choose><xsl:when test="position() = 1"> <xsl:value-of select="$prefix"/> </xsl:when><xsl:otherwise> <xsl:value-of select="$indent"/> </xsl:otherwise></xsl:choose> </xsl:with-param></xsl:call-template></xsl:template>


<xsl:template name="wrap"><xsl:param name="text"/><xsl:param name="prefix"/>
    <xsl:if test="$text">
        <xsl:variable name="offset">
            <xsl:choose>
                <xsl:when test="starts-with($text, concat($br, ' '))">
                    <xsl:value-of select="string-length($br) + 2"/>
                </xsl:when>
                <xsl:when test="starts-with($text, $br)">
                    <xsl:value-of select="string-length($br) + 1"/>
                </xsl:when>
                <xsl:otherwise>
                    1
                </xsl:otherwise>
            </xsl:choose>
        </xsl:variable>

        <xsl:variable name="length">
            <xsl:call-template name="length"><xsl:with-param select="substring($text, $offset)" name="text"/><xsl:with-param select="string-length($prefix)" name="prefix"/><xsl:with-param select="$max" name="length"/></xsl:call-template></xsl:variable>

        <xsl:value-of select="$prefix"/>

        <xsl:value-of select="normalize-space(translate(substring($text, $offset, $length),
                                    '&#xA0;', ' '))"/>

        <xsl:text>&#10;</xsl:text>

        <xsl:call-template name="wrap"><xsl:with-param select="substring($text, $length + $offset)" name="text"/><xsl:with-param select="$indent" name="prefix"/></xsl:call-template></xsl:if>
</xsl:template>


<xsl:template name="length"><xsl:param name="text"/><xsl:param name="prefix"/><xsl:param name="length"/>
    <xsl:variable select="substring-before(substring($text, 1,
                                    $length - $prefix + string-length($br)),
                                    $br)" name="break"/>

    <xsl:choose>
        <xsl:when test="$break"> <xsl:value-of select="string-length($break)"/> </xsl:when>

        <xsl:when test="$length = 0"> <xsl:value-of select="$max - $prefix"/> </xsl:when>

        <xsl:when test="string-length($text) + $prefix &lt;= $length">
            <xsl:value-of select="$length - $prefix"/>
        </xsl:when>

        <xsl:when test="substring($text, $length - $prefix + 1, 1) = ' '">
            <xsl:value-of select="$length - $prefix + 1"/>
        </xsl:when>

        <xsl:otherwise>
            <xsl:call-template name="length"><xsl:with-param select="$text" name="text"/><xsl:with-param select="$prefix" name="prefix"/><xsl:with-param select="$length - 1" name="length"/></xsl:call-template></xsl:otherwise>
    </xsl:choose>
</xsl:template>


<xsl:template match="at">@</xsl:template>
<xsl:template match="br"> <xsl:value-of select="$br"/> </xsl:template>
<xsl:template match="nobr"> <xsl:value-of select="translate(., ' ', '&#xA0;')"/> </xsl:template>


</xsl:stylesheet>
