#!/bin/sh

# Reads MIME type CSVs referenced by
# https://www.iana.org/assignments/media-types/media-types.xhtml
# and stores them in conf/mime/<type>.types

MIME_DIR=conf/mime

IANA_MIME=https://www.iana.org/assignments/media-types

IANA_TYPES="application \
            audio \
            font \
            haptics \
            image \
            message \
            model \
            multipart \
            text \
            video"

mkdir -p $MIME_DIR

for type in $IANA_TYPES
do
    echo $type

    MIME_FILE=$MIME_DIR/$type.type

    OLD_IFS=$IFS
    IFS=","

    echo "# Auto-generated from $IANA_MIME/$type.csv" > $MIME_FILE

    echo "types {" >> $MIME_FILE

    curl -s $IANA_MIME/$type.csv | tail -n +2 \
                                 | grep -v DEPRECATED | grep -v OBSOLETE \
                                 | while read name template rest
    do
        echo "    $template $name;" >> $MIME_FILE
    done

    echo "}" >> $MIME_FILE

    IFS=$OLD_IFS
done
