--- pcre.c	Thu Aug 21 14:43:07 2003
+++ pcre.c	Tue Mar 22 12:56:59 2005
@@ -246,8 +246,8 @@
 extern "C" void  (*pcre_free)(void *) = free;
 extern "C" int   (*pcre_callout)(pcre_callout_block *) = NULL;
 #else
-void *(*pcre_malloc)(size_t) = malloc;
-void  (*pcre_free)(void *) = free;
+void *(__cdecl *pcre_malloc)(size_t) = malloc;
+void  (__cdecl *pcre_free)(void *) = free;
 int   (*pcre_callout)(pcre_callout_block *) = NULL;
 #endif
 #endif
