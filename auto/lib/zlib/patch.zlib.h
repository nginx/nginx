--- zlib.h	Thu Jul  9 20:06:56 1998
+++ zlib-1.1.3/zlib.h	Tue Mar 22 13:41:04 2005
@@ -709,7 +709,6 @@
    (0 in case of error).
 */
 
-ZEXTERN int ZEXPORTVA   gzprintf OF((gzFile file, const char *format, ...));
 /*
      Converts, formats, and writes the args to the compressed file under
    control of the format string, as in fprintf. gzprintf returns the number of
