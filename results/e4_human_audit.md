# Human audit of rejected-but-touching patches (blind)

For each case, read the CVE, the official fix and the candidate patch, and label the candidate in results/e4_human_audit_labels.csv with exactly one of: equivalent (same fix, written differently), plausible (different but sound fix that keeps valid-input behaviour), over_restrictive (removes the flaw but breaks legitimate use), incorrect (does not or only partly removes the flaw, or breaks the function). If unsure whether it removes the vulnerability, choose incorrect. The arm and repeat are hidden.

## H01. CVE-2018-18586

CVE: chmextract.c in the chmextract sample program, as distributed with libmspack before 0.8alpha, does not protect against absolute/relative pathnames in CHM files, leading to Directory Traversal. NOTE: the vendor disputes that this is a libmspack vulnerability, because chmextract.c was only intended as a source-code example, not a supported application

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,96 +1,18 @@
 static char *create_output_name(unsigned char *fname, unsigned char *dir,
-			 int lower, int isunix, int utf8)
-{
-  unsigned char *p, *name, c, *fe, sep, slash;
-  unsigned int x;
-  sep   = (isunix) ? '/'  : '\\'; /* the path-seperator */
-  slash = (isunix) ? '\\' : '/';  /* the other slash */
-  /* length of filename */
-  x = strlen((char *) fname);
-  /* UTF8 worst case scenario: tolower() expands all chars from 1 to 3 bytes */
-  if (utf8) x *= 3;
-  /* length of output directory */
-  if (dir) x += strlen((char *) dir);
-  if (!(name = (unsigned char *) malloc(x + 2))) {
-    fprintf(stderr, "out of memory!\n");
-    return NULL;
-  }
-  /* start with blank name */
-  *name = '\0';
-  /* add output directory if needed */
-  if (dir) {
-    strcpy((char *) name, (char *) dir);
-    strcat((char *) name, "/");
-  }
-  /* remove leading slashes */
-  while (*fname == sep) fname++;
-  /* copy from fi->filename to new name, converting MS-DOS slashes to UNIX
-   * slashes as we go. Also lowercases characters if needed.
-   */
-  p = &name[strlen((char *)name)];
-  fe = &fname[strlen((char *)fname)];
-  if (utf8) {
-    /* UTF8 translates two-byte unicode characters into 1, 2 or 3 bytes.
-     * %000000000xxxxxxx -> %0xxxxxxx
-     * %00000xxxxxyyyyyy -> %110xxxxx %10yyyyyy
-     * %xxxxyyyyyyzzzzzz -> %1110xxxx %10yyyyyy %10zzzzzz
-     *
-     * Therefore, the inverse is as follows:
-     * First char:
-     *  0x00 - 0x7F = one byte char
-     *  0x80 - 0xBF = invalid
-     *  0xC0 - 0xDF = 2 byte char (next char only 0x80-0xBF is valid)
-     *  0xE0 - 0xEF = 3 byte char (next 2 chars only 0x80-0xBF is valid)
-     *  0xF0 - 0xFF = invalid
-     */
-    do {
-      if (fname >= fe) {
-	free(name);
-	return NULL;
-      }
-      /* get next UTF8 char */
-      if ((c = *fname++) < 0x80) x = c;
-      else {
-	if ((c >= 0xC0) && (c < 0xE0)) {
-	  x = (c & 0x1F) << 6;
-	  x |= *fname++ & 0x3F;
-	}
-	else if ((c >= 0xE0) && (c < 0xF0)) {
-	  x = (c & 0xF) << 12;
-	  x |= (*fname++ & 0x3F) << 6;
-	  x |= *fname++ & 0x3F;
-	}
-	else x = '?';
-      }
-      /* whatever is the path seperator -> '/'
-       * whatever is the other slash    -> '\\'
-       * otherwise, if lower is set, the lowercase version */
-      if      (x == sep)   x = '/';
-      else if (x == slash) x = '\\';
-      else if (lower)      x = (unsigned int) tolower((int) x);
-      /* integer back to UTF8 */
-      if (x < 0x80) {
-	*p++ = (unsigned char) x;
-      }
-      else if (x < 0x800) {
-	*p++ = 0xC0 | (x >> 6);   
-	*p++ = 0x80 | (x & 0x3F);
-      }
-      else {
-	*p++ = 0xE0 | (x >> 12);
-	*p++ = 0x80 | ((x >> 6) & 0x3F);
-	*p++ = 0x80 | (x & 0x3F);
-      }
-    } while (x);
-  }
-  else {
-    /* regular non-utf8 version */
-    do {
-      c = *fname++;
-      if      (c == sep)   c = '/';
-      else if (c == slash) c = '\\';
-      else if (lower)      c = (unsigned char) tolower((int) c);
-    } while ((*p++ = c));
-  }
-  return (char *) name;
+char *create_output_name(char *fname) {
+    char *out, *p;
+    if ((out = malloc(strlen(fname) + 1))) {
+        /* remove leading slashes */
+        while (*fname == '/' || *fname == '\\') fname++;
+        /* if that removes all characters, just call it "x" */
+        strcpy(out, (*fname) ? fname : "x");
+
+        /* change "../" to "xx/" */
+        for (p = out; *p; p++) {
+            if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\\')) {
+               p[0] = p[1] = 'x';
+            }
+        }
+    }
+    return out;
  }
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -25,4 +25,9 @@
   /* remove leading slashes */
   while (*fname == sep) fname++;
+  /* remove leading .. sequences */
+  while (fname[0] == '.' && fname[1] == '.' && (fname[2] == sep || fname[2] == slash || fname[2] == '\0')) {
+    fname += 2;
+    if (*fname == sep || *fname == slash) fname++;
+  }
   /* copy from fi->filename to new name, converting MS-DOS slashes to UNIX
    * slashes as we go. Also lowercases characters if needed.
@@ -94,3 +99,3 @@
   }
   return (char *) name;
- }
+}
```

## H02. CVE-2016-1583

CVE: The ecryptfs_privileged_open function in fs/ecryptfs/kthread.c in the Linux kernel before 4.6.3 allows local users to gain privileges or cause a denial of service (stack memory consumption) via vectors involving crafted mmap calls for /proc pathnames, leading to recursive pagefault handling.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -23,4 +23,11 @@
  		return ERR_CAST(sb);
  
+	/*
+	 * procfs isn't actually a stacking filesystem; however, there is
+	 * too much magic going on inside it to permit stacking things on
+	 * top of it
+	 */
+	sb->s_stack_depth = FILESYSTEM_MAX_STACK_DEPTH;
+
  	if (!proc_parse_options(options, ns)) {
  		deactivate_locked_super(sb);
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -19,12 +19,10 @@
 	}
 
+	if (!proc_parse_options(options, ns))
+		return ERR_PTR(-EINVAL);
+
 	sb = sget(fs_type, proc_test_super, proc_set_super, flags, ns);
  	if (IS_ERR(sb))
  		return ERR_CAST(sb);
- 
- 	if (!proc_parse_options(options, ns)) {
- 		deactivate_locked_super(sb);
- 		return ERR_PTR(-EINVAL);
-	}
 
 	if (!sb->s_root) {
```

## H03. CVE-2015-3331

CVE: The __driver_rfc4106_decrypt function in arch/x86/crypto/aesni-intel_glue.c in the Linux kernel before 3.19.3 does not properly determine the memory locations used for encrypted data, which allows context-dependent attackers to cause a denial of service (buffer overflow and system crash) or possibly execute arbitrary code by triggering a crypto API call, as demonstrated by use of a libkcapi test p

### Official fix
```diff
--- vulnerable
+++ patched
@@ -58,5 +58,5 @@
  		if (!src)
  			return -ENOMEM;
-		assoc = (src + req->cryptlen + auth_tag_len);
+		assoc = (src + req->cryptlen);
  		scatterwalk_map_and_copy(src, req->src, 0, req->cryptlen, 0);
  		scatterwalk_map_and_copy(assoc, req->assoc, 0,
@@ -83,5 +83,5 @@
  		scatterwalk_done(&assoc_sg_walk, 0, 0);
  	} else {
-		scatterwalk_map_and_copy(dst, req->dst, 0, req->cryptlen, 1);
+		scatterwalk_map_and_copy(dst, req->dst, 0, tempCipherLen, 1);
  		kfree(src);
  	}
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -58,5 +58,5 @@
  		if (!src)
  			return -ENOMEM;
-		assoc = (src + req->cryptlen + auth_tag_len);
+		assoc = (src + req->cryptlen);
  		scatterwalk_map_and_copy(src, req->src, 0, req->cryptlen, 0);
  		scatterwalk_map_and_copy(assoc, req->assoc, 0,
```

## H04. CVE-2014-4502

CVE: Multiple heap-based buffer overflows in the parse_notify function in sgminer before 4.2.2, cgminer before 4.3.5, and BFGMiner before 4.1.0 allow remote pool servers to have unspecified impact via a (1) large or (2) negative value in the Extranonc2_size parameter in a mining.subscribe response and a crafted mining.notify request.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -33,5 +33,5 @@
  		port = pool->stratum_port;
  
-	sprintf(address, "%s:%s", url, port);
+	snprintf(address, 254, "%s:%s", url, port);
  
  	if (!extract_sockaddr(address, &sockaddr_url, &stratum_port))
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -33,5 +33,6 @@
  		port = pool->stratum_port;
  
-	sprintf(address, "%s:%s", url, port);
+	if (snprintf(address, sizeof(address), "%s:%s", url, port) >= (int)sizeof(address))
+		return false;
  
  	if (!extract_sockaddr(address, &sockaddr_url, &stratum_port))
```

## H05. CVE-2016-10270

CVE: LibTIFF 4.0.7 allows remote attackers to cause a denial of service (heap-based buffer over-read) or possibly have unspecified other impact via a crafted TIFF image, related to "READ of size 8" and libtiff/tif_read.c:523:22.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -4,12 +4,4 @@
  	uint32 nstrips;
  
-    /* If the value was already computed and store in td_nstrips, then return it,
-       since ChopUpSingleUncompressedStrip might have altered and resized the
-       since the td_stripbytecount and td_stripoffset arrays to the new value
-       after the initial affectation of td_nstrips = TIFFNumberOfStrips() in
-       tif_dirread.c ~line 3612.
-       See http://bugzilla.maptools.org/show_bug.cgi?id=2587 */
-    if( td->td_nstrips )
-        return td->td_nstrips;
  	nstrips = (td->td_rowsperstrip == (uint32) -1 ? 1 :
  	     TIFFhowmany_32(td->td_imagelength, td->td_rowsperstrip));
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,18 +1,22 @@
 TIFFNumberOfStrips(TIFF* tif)
 {
- 	TIFFDirectory *td = &tif->tif_dir;
- 	uint32 nstrips;
- 
-    /* If the value was already computed and store in td_nstrips, then return it,
-       since ChopUpSingleUncompressedStrip might have altered and resized the
-       since the td_stripbytecount and td_stripoffset arrays to the new value
-       after the initial affectation of td_nstrips = TIFFNumberOfStrips() in
-       tif_dirread.c ~line 3612.
-       See http://bugzilla.maptools.org/show_bug.cgi?id=2587 */
-    if( td->td_nstrips )
-        return td->td_nstrips;
- 	nstrips = (td->td_rowsperstrip == (uint32) -1 ? 1 :
- 	     TIFFhowmany_32(td->td_imagelength, td->td_rowsperstrip));
- 	if (td->td_planarconfig == PLANARCONFIG_SEPARATE)
+	TIFFDirectory *td = &tif->tif_dir;
+	uint32 nstrips;
+
+	/* If the value was already computed and store in td_nstrips, then return it,
+	   since ChopUpSingleUncompressedStrip might have altered and resized the
+	   since the td_stripbytecount and td_stripoffset arrays to the new value
+	   after the initial affectation of td_nstrips = TIFFNumberOfStrips() in
+	   tif_dirread.c ~line 3612.
+	   See http://bugzilla.maptools.org/show_bug.cgi?id=2587 */
+	if( td->td_nstrips )
+		return td->td_nstrips;
+	
+	if (td->td_rowsperstrip == 0)
+		return 0;
+	
+	nstrips = (td->td_rowsperstrip == (uint32) -1 ? 1 :
+	     TIFFhowmany_32(td->td_imagelength, td->td_rowsperstrip));
+	if (td->td_planarconfig == PLANARCONFIG_SEPARATE)
 		nstrips = _TIFFMultiply32(tif, nstrips, (uint32)td->td_samplesperpixel,
 		    "TIFFNumberOfStrips");
```

## H06. CVE-2013-0925

CVE: Google Chrome before 26.0.1410.43 does not ensure that an extension has the tabs (aka APIPermission::kTab) permission before providing a URL to this extension, which has unspecified impact and remote attack vectors.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -4,8 +4,6 @@
      int tab_index,
      const Extension* extension) {
-  bool has_permission = extension && extension->HasAPIPermissionForTab(
-      GetTabId(contents), APIPermission::kTab);
-  return CreateTabValue(contents, tab_strip, tab_index,
-                        has_permission ? INCLUDE_PRIVACY_SENSITIVE_FIELDS :
-                            OMIT_PRIVACY_SENSITIVE_FIELDS);
+  DictionaryValue *result = CreateTabValue(contents, tab_strip, tab_index);
+  ScrubTabValueForExtension(contents, extension, result);
+  return result;
  }
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -6,4 +6,7 @@
   bool has_permission = extension && extension->HasAPIPermissionForTab(
       GetTabId(contents), APIPermission::kTab);
+  if (!contents || !tab_strip) {
+    return new DictionaryValue();
+  }
   return CreateTabValue(contents, tab_strip, tab_index,
                         has_permission ? INCLUDE_PRIVACY_SENSITIVE_FIELDS :
```

## H07. CVE-2017-15924

CVE: In manager.c in ss-manager in shadowsocks-libev 3.1.0, improper parsing allows command injection via shell metacharacters in a JSON configuration request received via 127.0.0.1 UDP traffic, related to the add_server, build_config, and construct_command_line functions.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,3 +1,4 @@
 build_config(char *prefix, struct server *server)
+build_config(char *prefix, struct manager_ctx *manager, struct server *server)
  {
      char *path    = NULL;
@@ -17,9 +18,16 @@
      fprintf(f, "\"server_port\":%d,\n", atoi(server->port));
      fprintf(f, "\"password\":\"%s\"", server->password);
-    if (server->fast_open[0]) fprintf(f, ",\n\"fast_open\": %s", server->fast_open);
-    if (server->mode)   fprintf(f, ",\n\"mode\":\"%s\"", server->mode);
-    if (server->method) fprintf(f, ",\n\"method\":\"%s\"", server->method);
-    if (server->plugin) fprintf(f, ",\n\"plugin\":\"%s\"", server->plugin);
-    if (server->plugin_opts) fprintf(f, ",\n\"plugin_opts\":\"%s\"", server->plugin_opts);
+    if (server->method)
+        fprintf(f, ",\n\"method\":\"%s\"", server->method);
+    else if (manager->method)
+        fprintf(f, ",\n\"method\":\"%s\"", manager->method);
+    if (server->fast_open[0])
+        fprintf(f, ",\n\"fast_open\": %s", server->fast_open);
+    if (server->mode)
+        fprintf(f, ",\n\"mode\":\"%s\"", server->mode);
+    if (server->plugin)
+        fprintf(f, ",\n\"plugin\":\"%s\"", server->plugin);
+    if (server->plugin_opts)
+        fprintf(f, ",\n\"plugin_opts\":\"%s\"", server->plugin_opts);
      fprintf(f, "\n}\n");
      fclose(f);
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,6 +1,19 @@
+void
 build_config(char *prefix, struct server *server)
- {
-     char *path    = NULL;
-     int path_size = strlen(prefix) + strlen(server->port) + 20;
+{
+    char *path    = NULL;
+    int path_size = strlen(prefix) + strlen(server->port) + 20;
+
+    // Validate port contains only digits to prevent path traversal
+    if (server->port) {
+        for (const char *p = server->port; *p; p++) {
+            if (*p < '0' || *p > '9') {
+                if (verbose) {
+                    LOGE("invalid port number");
+                }
+                return;
+            }
+        }
+    }
 
     path = ss_malloc(path_size);
@@ -14,14 +27,74 @@
         return;
     }
-     fprintf(f, "{\n");
-     fprintf(f, "\"server_port\":%d,\n", atoi(server->port));
-     fprintf(f, "\"password\":\"%s\"", server->password);
-    if (server->fast_open[0]) fprintf(f, ",\n\"fast_open\": %s", server->fast_open);
-    if (server->mode)   fprintf(f, ",\n\"mode\":\"%s\"", server->mode);
-    if (server->method) fprintf(f, ",\n\"method\":\"%s\"", server->method);
-    if (server->plugin) fprintf(f, ",\n\"plugin\":\"%s\"", server->plugin);
-    if (server->plugin_opts) fprintf(f, ",\n\"plugin_opts\":\"%s\"", server->plugin_opts);
-     fprintf(f, "\n}\n");
-     fclose(f);
-     ss_free(path);
+    fprintf(f, "{\n");
+    fprintf(f, "\"server_port\":%d,\n", atoi(server->port));
+    fprintf(f, "\"password\":\"");
+    if (server->password) {
+        const char *p = server->password;
+        while (*p) {
+            if (*p == '"') fprintf(f, "\\\"");
+            else if (*p == '\\') fprintf(f, "\\\\");
+            else fputc(*p, f);
+            p++;
+        }
+    }
+    fprintf(f, "\"");
+    if (server->fast_open[0]) {
+        fprintf(f, ",\n\"fast_open\":\"");
+        const char *p = server->fast_open;
+        while (*p) {
+            if (*p == '"') fprintf(f, "\\\"");
+            else if (*p == '\\') fprintf(f, "\\\\");
+            else fputc(*p, f);
+            p++;
+        }
+        fprintf(f, "\"");
+    }
+    if (server->mode) {
+        fprintf(f, ",\n\"mode\":\"");
+        const char *p = server->mode;
+        while (*p) {
+            if (*p == '"') fprintf(f, "\\\"");
+            else if (*p == '\\') fprintf(f, "\\\\");
+            else fputc(*p, f);
+            p++;
+        }
+        fprintf(f, "\"");
+    }
+    if (server->method) {
+        fprintf(f, ",\n\"method\":\"");
+        const char *p = server->method;
+        while (*p) {
+            if (*p == '"') fprintf(f, "\\\"");
+            else if (*p == '\\') fprintf(f, "\\\\");
+            else fputc(*p, f);
+            p++;
+        }
+        fprintf(f, "\"");
+    }
+    if (server->plugin) {
+        fprintf(f, ",\n\"plugin\":\"");
+        const char *p = server->plugin;
+        while (*p) {
+            if (*p == '"') fprintf(f, "\\\"");
+            else if (*p == '\\') fprintf(f, "\\\\");
+            else fputc(*p, f);
+            p++;
+        }
+        fprintf(f, "\"");
+    }
+    if (server->plugin_opts) {
+        fprintf(f, ",\n\"plugin_opts\":\"");
+        const char *p = server->plugin_opts;
+        while (*p) {
+            if (*p == '"') fprintf(f, "\\\"");
+            else if (*p == '\\') fprintf(f, "\\\\");
+            else fputc(*p, f);
+            p++;
+        }
+        fprintf(f, "\"");
+    }
+    fprintf(f, "\n}\n");
+    fclose(f);
+    ss_free(path);
 }
```

## H08. CVE-2013-4149

CVE: Buffer overflow in virtio_net_load function in net/virtio-net.c in QEMU 1.3.0 through 1.7.x before 1.7.2 might allow remote attackers to execute arbitrary code via a large MAC table.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -37,8 +37,15 @@
              qemu_get_buffer(f, n->mac_table.macs,
                              n->mac_table.in_use * ETH_ALEN);
-        } else if (n->mac_table.in_use) {
-            uint8_t *buf = g_malloc0(n->mac_table.in_use);
-            qemu_get_buffer(f, buf, n->mac_table.in_use * ETH_ALEN);
-            g_free(buf);
+        } else {
+            int64_t i;
+
+            /* Overflow detected - can happen if source has a larger MAC table.
+             * We simply set overflow flag so there's no need to maintain the
+             * table of addresses, discard them all.
+             * Note: 64 bit math to avoid integer overflow.
+             */
+            for (i = 0; i < (int64_t)n->mac_table.in_use * ETH_ALEN; ++i) {
+                qemu_get_byte(f);
+            }
              n->mac_table.multi_overflow = n->mac_table.uni_overflow = 1;
              n->mac_table.in_use = 0;
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -34,16 +34,16 @@
         n->mac_table.in_use = qemu_get_be32(f);
         /* MAC_TABLE_ENTRIES may be different from the saved image */
-         if (n->mac_table.in_use <= MAC_TABLE_ENTRIES) {
-             qemu_get_buffer(f, n->mac_table.macs,
-                             n->mac_table.in_use * ETH_ALEN);
+        if (n->mac_table.in_use <= MAC_TABLE_ENTRIES) {
+            qemu_get_buffer(f, n->mac_table.macs,
+                            n->mac_table.in_use * ETH_ALEN);
         } else if (n->mac_table.in_use) {
-            uint8_t *buf = g_malloc0(n->mac_table.in_use);
+            uint8_t *buf = g_malloc0(n->mac_table.in_use * ETH_ALEN);
             qemu_get_buffer(f, buf, n->mac_table.in_use * ETH_ALEN);
             g_free(buf);
-             n->mac_table.multi_overflow = n->mac_table.uni_overflow = 1;
-             n->mac_table.in_use = 0;
-         }
-            error_report("virtio-net: saved image requires vnet_hdr=on");
-            return -1;
+            n->mac_table.multi_overflow = n->mac_table.uni_overflow = 1;
+            n->mac_table.in_use = 0;
         }
     }
+
+    return 0;
+}
```

## H09. CVE-2018-11380

CVE: The parse_import_ptr() function in radare2 2.5.0 allows remote attackers to cause a denial of service (heap-based out-of-bounds read and application crash) via a crafted Mach-O file.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -27,9 +27,14 @@
  	for (i = 0; i < bin->nsects; i++) {
  		if ((bin->sects[i].flags & SECTION_TYPE) == stype) {
-			for (j=0, sym=-1; bin->sects[i].reserved1+j < bin->nindirectsyms; j++)
-				if (idx == bin->indirectsyms[bin->sects[i].reserved1 + j]) {
+			for (j = 0, sym = -1; bin->sects[i].reserved1 + j < bin->nindirectsyms; j++) {
+				int indidx = bin->sects[i].reserved1 + j;
+				if (indidx < 0 || indidx >= bin->nindirectsyms) {
+					break;
+				}
+				if (idx == bin->indirectsyms[indidx]) {
  					sym = j;
  					break;
  				}
+			}
  			reloc->offset = sym == -1 ? 0 : bin->sects[i].offset + sym * wordsize;
  			reloc->addr = sym == -1 ? 0 : bin->sects[i].addr + sym * wordsize;
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -27,9 +27,13 @@
  	for (i = 0; i < bin->nsects; i++) {
  		if ((bin->sects[i].flags & SECTION_TYPE) == stype) {
-			for (j=0, sym=-1; bin->sects[i].reserved1+j < bin->nindirectsyms; j++)
+			if (bin->sects[i].reserved1 >= bin->nindirectsyms) {
+				continue;
+			}
+			for (j=0, sym=-1; bin->sects[i].reserved1+j < bin->nindirectsyms; j++) {
 				if (idx == bin->indirectsyms[bin->sects[i].reserved1 + j]) {
  					sym = j;
  					break;
  				}
+			}
  			reloc->offset = sym == -1 ? 0 : bin->sects[i].offset + sym * wordsize;
  			reloc->addr = sym == -1 ? 0 : bin->sects[i].addr + sym * wordsize;
```

## H10. CVE-2016-7126

CVE: The imagetruecolortopalette function in ext/gd/gd.c in PHP before 5.6.25 and 7.x before 7.0.10 does not properly validate the number of colors, which allows remote attackers to cause a denial of service (select_colors allocation error and out-of-bounds write) or possibly have unspecified other impact via a large value in the third argument.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -12,9 +12,9 @@
  	ZEND_FETCH_RESOURCE(im, gdImagePtr, &IM, -1, "Image", le_gd);
  
-	if (ncolors <= 0) {
-		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Number of colors has to be greater than zero");
+	if (ncolors <= 0 || ncolors > INT_MAX) {
+		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Number of colors has to be greater than zero and no more than %d", INT_MAX);
  		RETURN_FALSE;
  	}
-	gdImageTrueColorToPalette(im, dither, ncolors);
+	gdImageTrueColorToPalette(im, dither, (int)ncolors);
  
  	RETURN_TRUE;
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -12,6 +12,6 @@
  	ZEND_FETCH_RESOURCE(im, gdImagePtr, &IM, -1, "Image", le_gd);
  
-	if (ncolors <= 0) {
-		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Number of colors has to be greater than zero");
+	if (ncolors <= 0 || ncolors > 256) {
+		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Number of colors must be between 1 and 256");
  		RETURN_FALSE;
  	}
```

## H11. CVE-2018-10887

CVE: A flaw was found in libgit2 before version 0.27.3. It has been discovered that an unexpected sign extension in git_delta_apply function in delta.c file may lead to an integer overflow which in turn leads to an out of bound read, allowing to read before the base object. An attacker may use this flaw to leak memory addresses or cause a Denial of Service.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -14,8 +14,9 @@
  	*out_len = 0;
  
-	/* Check that the base size matches the data we were given;
-	* if not we would underflow while accessing data from the
-	* base object, resulting in data corruption or segfault.
-	*/
+	/*
+	 * Check that the base size matches the data we were given;
+	 * if not we would underflow while accessing data from the
+	 * base object, resulting in data corruption or segfault.
+	 */
  	if ((hdr_sz(&base_sz, &delta, delta_end) < 0) || (base_sz != base_len)) {
  		giterr_set(GITERR_INVALID, "failed to apply delta: base size does not match given data");
@@ -39,6 +40,5 @@
  		unsigned char cmd = *delta++;
  		if (cmd & 0x80) {
-			/* cmd is a copy instruction; copy from the base.
-			*/
+			/* cmd is a copy instruction; copy from the base. */
  			size_t off = 0, len = 0;
  
@@ -46,10 +46,10 @@
  			if (cmd & 0x02) off |= *delta++ << 8UL;
  			if (cmd & 0x04) off |= *delta++ << 16UL;
-			if (cmd & 0x08) off |= *delta++ << 24UL;
+			if (cmd & 0x08) off |= ((unsigned) *delta++ << 24UL);
  
  			if (cmd & 0x10) len = *delta++;
  			if (cmd & 0x20) len |= *delta++ << 8UL;
  			if (cmd & 0x40) len |= *delta++ << 16UL;
-			if (!len)		len = 0x10000;
+			if (!len)       len = 0x10000;
  
  			if (base_len < off + len || res_sz < len)
@@ -59,9 +59,9 @@
  			res_sz -= len;
  
-		}
-		else if (cmd) {
-			/* cmd is a literal insert instruction; copy from
-			* the delta stream itself.
-			*/
+		} else if (cmd) {
+			/*
+			 * cmd is a literal insert instruction; copy from
+			 * the delta stream itself.
+			 */
  			if (delta_end - delta < cmd || res_sz < cmd)
  				goto fail;
@@ -71,8 +71,6 @@
  			res_sz -= cmd;
  
-		}
-		else {
-			/* cmd == 0 is reserved for future encodings.
-			*/
+		} else {
+			/* cmd == 0 is reserved for future encodings. */
  			goto fail;
  		}
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -43,12 +43,33 @@
  			size_t off = 0, len = 0;
  
- 			if (cmd & 0x01) off = *delta++;
- 			if (cmd & 0x02) off |= *delta++ << 8UL;
- 			if (cmd & 0x04) off |= *delta++ << 16UL;
-			if (cmd & 0x08) off |= *delta++ << 24UL;
+ 			if (cmd & 0x01) {
+ 				if (delta >= delta_end) goto fail;
+ 				off = *delta++;
+ 			}
+ 			if (cmd & 0x02) {
+ 				if (delta >= delta_end) goto fail;
+ 				off |= *delta++ << 8UL;
+ 			}
+ 			if (cmd & 0x04) {
+ 				if (delta >= delta_end) goto fail;
+ 				off |= *delta++ << 16UL;
+ 			}
+			if (cmd & 0x08) {
+				if (delta >= delta_end) goto fail;
+				off |= *delta++ << 24UL;
+			}
  
- 			if (cmd & 0x10) len = *delta++;
- 			if (cmd & 0x20) len |= *delta++ << 8UL;
- 			if (cmd & 0x40) len |= *delta++ << 16UL;
+ 			if (cmd & 0x10) {
+ 				if (delta >= delta_end) goto fail;
+ 				len = *delta++;
+ 			}
+ 			if (cmd & 0x20) {
+ 				if (delta >= delta_end) goto fail;
+ 				len |= *delta++ << 8UL;
+ 			}
+ 			if (cmd & 0x40) {
+ 				if (delta >= delta_end) goto fail;
+ 				len |= *delta++ << 16UL;
+ 			}
 			if (!len)		len = 0x10000;
  
```

## H12. CVE-2011-1180

CVE: Multiple stack-based buffer overflows in the iriap_getvaluebyclass_indication function in net/irda/iriap.c in the Linux kernel before 2.6.39 allow remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging connectivity to an IrDA infrared network and sending a large integer value for a (1) name length or (2) attribute length.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -21,8 +21,14 @@
  
  	name_len = fp[n++];
+
+	IRDA_ASSERT(name_len < IAS_MAX_CLASSNAME + 1, return;);
+
  	memcpy(name, fp+n, name_len); n+=name_len;
  	name[name_len] = '\0';
  
  	attr_len = fp[n++];
+
+	IRDA_ASSERT(attr_len < IAS_MAX_ATTRIBNAME + 1, return;);
+
  	memcpy(attr, fp+n, attr_len); n+=attr_len;
  	attr[attr_len] = '\0';
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -21,8 +21,12 @@
  
  	name_len = fp[n++];
+ 	if (name_len > IAS_MAX_CLASSNAME)
+ 		return;
  	memcpy(name, fp+n, name_len); n+=name_len;
  	name[name_len] = '\0';
  
  	attr_len = fp[n++];
+ 	if (attr_len > IAS_MAX_ATTRIBNAME)
+ 		return;
  	memcpy(attr, fp+n, attr_len); n+=attr_len;
  	attr[attr_len] = '\0';
```

## H13. CVE-2016-5357

CVE: wiretap/netscreen.c in the NetScreen file parser in Wireshark 1.12.x before 1.12.12 and 2.x before 2.0.4 mishandles sscanf unsigned-integer processing, which allows remote attackers to cause a denial of service (application crash) via a crafted file.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -3,9 +3,5 @@
  	int *err, gchar **err_info)
  {
-	int		pkt_len;
  	char		line[NETSCREEN_LINE_LENGTH];
-	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
-	gboolean	cap_dir;
-	char		cap_dst[13];
  
  	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
@@ -21,11 +17,5 @@
  	}
  
-	pkt_len = parse_netscreen_rec_hdr(phdr, line, cap_int, &cap_dir,
-	    cap_dst, err, err_info);
-	if (pkt_len == -1)
-		return FALSE;
-	if (!parse_netscreen_hex_dump(wth->random_fh, pkt_len, cap_int,
-	    cap_dst, phdr, buf, err, err_info))
-		return FALSE;
-	return TRUE;
+	return parse_netscreen_packet(wth->random_fh, phdr, buf, line,
+	    err, err_info);
  }
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -7,5 +7,5 @@
 	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
 	gboolean	cap_dir;
-	char		cap_dst[13];
+	char		cap_dst[20];
  
  	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
```

## H14. CVE-2017-13198

CVE: A vulnerability in the Android media framework (ex) related to composition of frames lacking a color map. Product: Android. Versions: 7.0, 7.1.1, 7.1.2, 8.0, 8.1. Android ID: A-68399117.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -90,16 +90,16 @@
              }
  
-            if (cmap == NULL || cmap->ColorCount != (1 << cmap->BitsPerPixel)) {
-                ALOGW("Warning: potentially corrupt color map");
-            }
-            const unsigned char* src = (unsigned char*)frame.RasterBits;
-            Color8888* dst = outputPtr + frame.ImageDesc.Left +
-                    frame.ImageDesc.Top * outputPixelStride;
-            GifWord copyWidth, copyHeight;
-            getCopySize(frame.ImageDesc, width, height, copyWidth, copyHeight);
-            for (; copyHeight > 0; copyHeight--) {
-                copyLine(dst, src, cmap, gcb.TransparentColor, copyWidth);
-                src += frame.ImageDesc.Width;
-                dst += outputPixelStride;
+            // If a cmap is missing, the frame can't be decoded, so we skip it.
+            if (cmap) {
+                const unsigned char* src = (unsigned char*)frame.RasterBits;
+                Color8888* dst = outputPtr + frame.ImageDesc.Left +
+                        frame.ImageDesc.Top * outputPixelStride;
+                GifWord copyWidth, copyHeight;
+                getCopySize(frame.ImageDesc, width, height, copyWidth, copyHeight);
+                for (; copyHeight > 0; copyHeight--) {
+                    copyLine(dst, src, cmap, gcb.TransparentColor, copyWidth);
+                    src += frame.ImageDesc.Width;
+                    dst += outputPixelStride;
+                }
              }
          }
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -15,4 +15,10 @@
  const int height = mFrameSequence.getHeight();
  const int width = mFrameSequence.getWidth();
+ const int maxFrame = gif->ImageCount;
+
+ if (frameNr < 0 || frameNr >= maxFrame) {
+        ALOGD("Cannot drawFrame, frameNr %d out of bounds [0, %d)", frameNr, maxFrame);
+ return -1;
+ }
 
  GraphicsControlBlock gcb;
@@ -92,4 +98,5 @@
             if (cmap == NULL || cmap->ColorCount != (1 << cmap->BitsPerPixel)) {
                 ALOGW("Warning: potentially corrupt color map");
+                continue;
             }
             const unsigned char* src = (unsigned char*)frame.RasterBits;
@@ -106,5 +113,4 @@
      }
 
- const int maxFrame = gif->ImageCount;
  const int lastFrame = (frameNr + maxFrame - 1) % maxFrame;
  DGifSavedExtensionToGCB(gif, lastFrame, &gcb);
```

## H15. CVE-2018-14879

CVE: The command-line argument parser in tcpdump before 4.9.3 has a buffer overflow in tcpdump.c:get_next_file().

### Official fix
```diff
--- vulnerable
+++ patched
@@ -2,4 +2,5 @@
  {
  	char *ret;
+	size_t len;
  
  	ret = fgets(ptr, PATH_MAX, VFile);
@@ -7,6 +8,7 @@
  		return NULL;
  
-	if (ptr[strlen(ptr) - 1] == '\n')
-		ptr[strlen(ptr) - 1] = '\0';
+	len = strlen (ptr);
+	if (len > 0 && ptr[len - 1] == '\n')
+		ptr[len - 1] = '\0';
  
  	return ret;
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,13 +1,14 @@
- get_next_file(FILE *VFile, char *ptr)
- {
- 	char *ret;
- 
- 	ret = fgets(ptr, PATH_MAX, VFile);
- 	if (!ret)
- 		return NULL;
- 
-	if (ptr[strlen(ptr) - 1] == '\n')
-		ptr[strlen(ptr) - 1] = '\0';
- 
- 	return ret;
- }
+get_next_file(FILE *VFile, char *ptr)
+{
+	char *ret;
+
+	ret = fgets(ptr, PATH_MAX, VFile);
+	if (!ret)
+		return NULL;
+
+	size_t len = strlen(ptr);
+	if (len > 0 && ptr[len - 1] == '\n')
+		ptr[len - 1] = '\0';
+
+	return ret;
+}
```

## H16. CVE-2017-16526

CVE: drivers/uwb/uwbd.c in the Linux kernel before 4.13.6 allows local users to cause a denial of service (general protection fault and system crash) or possibly have unspecified other impact via a crafted USB device.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,9 +1,12 @@
  void uwbd_start(struct uwb_rc *rc)
  {
-	rc->uwbd.task = kthread_run(uwbd, rc, "uwbd");
-	if (rc->uwbd.task == NULL)
+	struct task_struct *task = kthread_run(uwbd, rc, "uwbd");
+	if (IS_ERR(task)) {
+		rc->uwbd.task = NULL;
  		printk(KERN_ERR "UWB: Cannot start management daemon; "
  		       "UWB won't work\n");
-	else
+	} else {
+		rc->uwbd.task = task;
  		rc->uwbd.pid = rc->uwbd.task->pid;
+	}
  }
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,9 +1,11 @@
- void uwbd_start(struct uwb_rc *rc)
- {
+void uwbd_start(struct uwb_rc *rc)
+{
 	rc->uwbd.task = kthread_run(uwbd, rc, "uwbd");
-	if (rc->uwbd.task == NULL)
- 		printk(KERN_ERR "UWB: Cannot start management daemon; "
- 		       "UWB won't work\n");
-	else
- 		rc->uwbd.pid = rc->uwbd.task->pid;
- }
+	if (IS_ERR(rc->uwbd.task)) {
+		printk(KERN_ERR "UWB: Cannot start management daemon; "
+		       "UWB won't work\n");
+		rc->uwbd.task = NULL;
+	} else {
+		rc->uwbd.pid = rc->uwbd.task->pid;
+	}
+}
```

## H17. CVE-2015-8953

CVE: fs/overlayfs/copy_up.c in the Linux kernel before 4.2.6 uses an incorrect cleanup code path, which allows local users to cause a denial of service (dentry reference leak) via filesystem operations on a large file in a lower overlayfs layer.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -73,4 +73,4 @@
  out_cleanup:
  	ovl_cleanup(wdir, newdentry);
-	goto out;
+	goto out2;
  }
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -47,5 +47,5 @@
 	err = ovl_set_attr(newdentry, stat);
 	if (!err && attr)
-		err = notify_change(newdentry, attr, NULL);
+		err = notify_change(newdentry, attr);
 	mutex_unlock(&newdentry->d_inode->i_mutex);
 	if (err)
@@ -60,5 +60,5 @@
 
 	/*
-	 * Non-directores become opaque when copied up.
+	 * Non-directories become opaque when copied up.
 	 */
 	if (!S_ISDIR(stat->mode))
@@ -70,7 +70,7 @@
 out:
 	return err;
- 
- out_cleanup:
- 	ovl_cleanup(wdir, newdentry);
-	goto out;
- }
+
+out_cleanup:
+	ovl_cleanup(wdir, newdentry);
+	goto out1;
+}
```

## H18. CVE-2011-2895

CVE: The LZW decompressor in (1) the BufCompressedFill function in fontfile/decompress.c in X.Org libXfont before 1.4.4 and (2) compress/compress.c in 4.3BSD, as used in zopen.c in OpenBSD before 3.8, FreeBSD, NetBSD 4.0.x and 5.0.x before 5.0.3 and 5.1.x before 5.1.1, FreeType 2.1.9, and other products, does not properly handle code words that are absent from the decompression table when encountered, 

### Official fix
```diff
--- vulnerable
+++ patched
@@ -51,4 +51,6 @@
      	while ( code >= 256 )
      	{
+	    if (stackp - de_stack >= STACK_SIZE - 1)
+		return BUFFILEEOF;
  	    *stackp++ = file->tab_suffix[code];
  	    code = file->tab_prefix[code];
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -42,4 +42,6 @@
      	 */
     	if ( code >= file->free_ent ) {
+	    if ( code != file->free_ent )
+	    	break;
 	    *stackp++ = finchar;
 	    code = oldcode;
@@ -51,4 +53,6 @@
      	while ( code >= 256 )
      	{
+	    if ( code >= file->free_ent )
+	    	break;
  	    *stackp++ = file->tab_suffix[code];
  	    code = file->tab_prefix[code];
```

## H19. CVE-2012-2870

CVE: libxslt 1.1.26 and earlier, as used in Google Chrome before 21.0.1180.89, does not properly manage memory, which might allow remote attackers to cause a denial of service (application crash) via a crafted XSLT expression that is not properly identified during XPath navigation, related to (1) the xsltCompileLocationPathPattern function in libxslt/pattern.c and (2) the xsltGenerateIdFunction functio

### Official fix
```diff
--- vulnerable
+++ patched
@@ -37,4 +37,6 @@
  	if ((CUR == '(') && !xmlXPathIsNodeType(name)) {
  	    xsltCompileIdKeyPattern(ctxt, name, 1, novar, 0);
+	    if (ctxt->error)
+		return;
  	    if ((CUR == '/') && (NXT(1) == '/')) {
  		PUSH(XSLT_OP_ANCESTOR, NULL, NULL, novar);
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -37,4 +37,7 @@
  	if ((CUR == '(') && !xmlXPathIsNodeType(name)) {
  	    xsltCompileIdKeyPattern(ctxt, name, 1, novar, 0);
+ 	    if (ctxt->error) {
+ 	        return;
+ 	    }
  	    if ((CUR == '/') && (NXT(1) == '/')) {
  		PUSH(XSLT_OP_ANCESTOR, NULL, NULL, novar);
```

## H20. CVE-2017-12192

CVE: The keyctl_read_key function in security/keys/keyctl.c in the Key Management subcomponent in the Linux kernel before 4.13.5 does not properly consider that a key may be possessed but negatively instantiated, which allows local users to cause a denial of service (OOPS and system crash) via a crafted KEYCTL_READ operation.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -14,4 +14,9 @@
  	key = key_ref_to_ptr(key_ref);
  
+	if (test_bit(KEY_FLAG_NEGATIVE, &key->flags)) {
+		ret = -ENOKEY;
+		goto error2;
+	}
+
  	/* see if we can read it directly */
  	ret = key_permission(key_ref, KEY_NEED_READ);
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -13,4 +13,9 @@
  
  	key = key_ref_to_ptr(key_ref);
+	
+	/* validate the key is in a usable state */
+	ret = key_validate(key);
+	if (ret != 0)
+		goto error2;
  
  	/* see if we can read it directly */
```

## H21. CVE-2017-13198

CVE: A vulnerability in the Android media framework (ex) related to composition of frames lacking a color map. Product: Android. Versions: 7.0, 7.1.1, 7.1.2, 8.0, 8.1. Android ID: A-68399117.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -90,16 +90,16 @@
              }
  
-            if (cmap == NULL || cmap->ColorCount != (1 << cmap->BitsPerPixel)) {
-                ALOGW("Warning: potentially corrupt color map");
-            }
-            const unsigned char* src = (unsigned char*)frame.RasterBits;
-            Color8888* dst = outputPtr + frame.ImageDesc.Left +
-                    frame.ImageDesc.Top * outputPixelStride;
-            GifWord copyWidth, copyHeight;
-            getCopySize(frame.ImageDesc, width, height, copyWidth, copyHeight);
-            for (; copyHeight > 0; copyHeight--) {
-                copyLine(dst, src, cmap, gcb.TransparentColor, copyWidth);
-                src += frame.ImageDesc.Width;
-                dst += outputPixelStride;
+            // If a cmap is missing, the frame can't be decoded, so we skip it.
+            if (cmap) {
+                const unsigned char* src = (unsigned char*)frame.RasterBits;
+                Color8888* dst = outputPtr + frame.ImageDesc.Left +
+                        frame.ImageDesc.Top * outputPixelStride;
+                GifWord copyWidth, copyHeight;
+                getCopySize(frame.ImageDesc, width, height, copyWidth, copyHeight);
+                for (; copyHeight > 0; copyHeight--) {
+                    copyLine(dst, src, cmap, gcb.TransparentColor, copyWidth);
+                    src += frame.ImageDesc.Width;
+                    dst += outputPixelStride;
+                }
              }
          }
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -92,6 +92,11 @@
             if (cmap == NULL || cmap->ColorCount != (1 << cmap->BitsPerPixel)) {
                 ALOGW("Warning: potentially corrupt color map");
+                continue;
             }
             const unsigned char* src = (unsigned char*)frame.RasterBits;
+            if (src == NULL) {
+                ALOGW("Warning: frame raster bits are NULL");
+                continue;
+            }
             Color8888* dst = outputPtr + frame.ImageDesc.Left +
                     frame.ImageDesc.Top * outputPixelStride;
```

## H22. CVE-2016-2482

CVE: The mm-video-v4l2 vdec component in mediaserver in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, and 6.x before 2016-06-01 mishandles a buffer count, which allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bug 27661749.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -23,5 +23,12 @@
          DEBUG_PRINT_LOW("Freeing the Output Memory");
          for (i = 0; i < drv_ctx.op_buf.actualcount; i++ ) {
-            free_output_buffer (&m_out_mem_ptr[i]);
+            if (BITMASK_PRESENT(&m_out_bm_count, i)) {
+                BITMASK_CLEAR(&m_out_bm_count, i);
+                client_buffers.free_output_buffer (&m_out_mem_ptr[i]);
+            }
+
+            if (release_output_done()) {
+                break;
+            }
          }
  #ifdef _ANDROID_ICS_
@@ -35,9 +42,17 @@
          DEBUG_PRINT_LOW("Freeing the Input Memory");
          for (i = 0; i<drv_ctx.ip_buf.actualcount; i++ ) {
-            if (m_inp_mem_ptr)
-                free_input_buffer (i,&m_inp_mem_ptr[i]);
-            else
-                free_input_buffer (i,NULL);
-        }
+
+            if (BITMASK_PRESENT(&m_inp_bm_count, i)) {
+                BITMASK_CLEAR(&m_inp_bm_count, i);
+                if (m_inp_mem_ptr)
+                    free_input_buffer (i,&m_inp_mem_ptr[i]);
+                else
+                    free_input_buffer (i,NULL);
+            }
+
+            if (release_input_done()) {
+                break;
+            }
+       }
      }
      free_input_buffer_header();
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -28,4 +28,6 @@
          memset(&native_buffer, 0, (sizeof(nativebuffer) * MAX_NUM_INPUT_OUTPUT_BUFFERS));
 #endif
+         free(m_out_mem_ptr);
+         m_out_mem_ptr = NULL;
  }
 
@@ -40,4 +42,12 @@
                 free_input_buffer (i,NULL);
         }
+         if (m_inp_mem_ptr) {
+             free(m_inp_mem_ptr);
+             m_inp_mem_ptr = NULL;
+         }
+         if (m_inp_heap_ptr) {
+             free(m_inp_heap_ptr);
+             m_inp_heap_ptr = NULL;
+         }
      }
      free_input_buffer_header();
```

## H23. CVE-2016-10061

CVE: The ReadGROUP4Image function in coders/tiff.c in ImageMagick before 7.0.1-10 does not check the return value of the fputc function, which allows remote attackers to cause a denial of service (crash) via a crafted image file.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -81,6 +81,8 @@
    length=WriteLSBLong(file,(long) image->resolution.x);
    length=WriteLSBLong(file,1);
+  status=MagickTrue;
    for (length=0; (c=ReadBlobByte(image)) != EOF; length++)
-    (void) fputc(c,file);
+    if (fputc(c,file) != c)
+      status=MagickFalse;
    offset=(ssize_t) fseek(file,(ssize_t) offset,SEEK_SET);
    length=WriteLSBLong(file,(unsigned int) length);
@@ -104,4 +106,6 @@
      }
    (void) RelinquishUniqueFileResource(filename);
+  if (status == MagickFalse)
+    image=DestroyImage(image);
    return(image);
  }
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -78,12 +78,22 @@
   length=WriteLSBLong(file,(size_t) (strip_offset-8));
   length=fwrite("\050\001\003\000\001\000\000\000\002\000\000\000",1,12,file);
-   length=fwrite("\000\000\000\000",1,4,file);
-   length=WriteLSBLong(file,(long) image->resolution.x);
-   length=WriteLSBLong(file,1);
-   for (length=0; (c=ReadBlobByte(image)) != EOF; length++)
-    (void) fputc(c,file);
-   offset=(ssize_t) fseek(file,(ssize_t) offset,SEEK_SET);
-   length=WriteLSBLong(file,(unsigned int) length);
-   (void) fclose(file);
+  length=fwrite("\000\000\000\000",1,4,file);
+  length=WriteLSBLong(file,(long) image->resolution.x);
+  length=WriteLSBLong(file,1);
+  status=MagickTrue;
+  for (length=0; (c=ReadBlobByte(image)) != EOF; length++)
+    {
+      if (fputc(c,file) == EOF)
+        {
+          status=MagickFalse;
+          break;
+        }
+    }
+  offset=(ssize_t) fseek(file,(ssize_t) offset,SEEK_SET);
+  if (status != MagickFalse)
+    length=WriteLSBLong(file,(unsigned int) length);
+  if (ferror(file) != 0)
+    status=MagickFalse;
+  (void) fclose(file);
   (void) CloseBlob(image);
   image=DestroyImage(image);
@@ -92,6 +102,11 @@
   */
   read_info=CloneImageInfo((ImageInfo *) NULL);
-  (void) FormatLocaleString(read_info->filename,MagickPathExtent,"%s",filename);
-  image=ReadTIFFImage(read_info,exception);
+  if (status != MagickFalse)
+    {
+      (void) FormatLocaleString(read_info->filename,MagickPathExtent,"%s",filename);
+      image=ReadTIFFImage(read_info,exception);
+    }
+  else
+    image=(Image *) NULL;
   read_info=DestroyImageInfo(read_info);
   if (image != (Image *) NULL)
@@ -101,7 +116,7 @@
       (void) CopyMagickString(image->magick_filename,image_info->filename,
         MagickPathExtent);
-       (void) CopyMagickString(image->magick,"GROUP4",MagickPathExtent);
-     }
-   (void) RelinquishUniqueFileResource(filename);
-   return(image);
- }
+      (void) CopyMagickString(image->magick,"GROUP4",MagickPathExtent);
+    }
+  (void) RelinquishUniqueFileResource(filename);
+  return(image);
+}
```

## H24. CVE-2018-11380

CVE: The parse_import_ptr() function in radare2 2.5.0 allows remote attackers to cause a denial of service (heap-based out-of-bounds read and application crash) via a crafted Mach-O file.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -27,9 +27,14 @@
  	for (i = 0; i < bin->nsects; i++) {
  		if ((bin->sects[i].flags & SECTION_TYPE) == stype) {
-			for (j=0, sym=-1; bin->sects[i].reserved1+j < bin->nindirectsyms; j++)
-				if (idx == bin->indirectsyms[bin->sects[i].reserved1 + j]) {
+			for (j = 0, sym = -1; bin->sects[i].reserved1 + j < bin->nindirectsyms; j++) {
+				int indidx = bin->sects[i].reserved1 + j;
+				if (indidx < 0 || indidx >= bin->nindirectsyms) {
+					break;
+				}
+				if (idx == bin->indirectsyms[indidx]) {
  					sym = j;
  					break;
  				}
+			}
  			reloc->offset = sym == -1 ? 0 : bin->sects[i].offset + sym * wordsize;
  			reloc->addr = sym == -1 ? 0 : bin->sects[i].addr + sym * wordsize;
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -27,9 +27,14 @@
  	for (i = 0; i < bin->nsects; i++) {
  		if ((bin->sects[i].flags & SECTION_TYPE) == stype) {
-			for (j=0, sym=-1; bin->sects[i].reserved1+j < bin->nindirectsyms; j++)
-				if (idx == bin->indirectsyms[bin->sects[i].reserved1 + j]) {
- 					sym = j;
- 					break;
- 				}
+			for (j=0, sym=-1; bin->sects[i].reserved1+j < bin->nindirectsyms; j++) {
+				int indirect_idx = bin->sects[i].reserved1 + j;
+				if (indirect_idx < 0 || indirect_idx >= bin->nindirectsyms) {
+					break;
+				}
+				if (idx == bin->indirectsyms[indirect_idx]) {
+					sym = j;
+					break;
+				}
+			}
  			reloc->offset = sym == -1 ? 0 : bin->sects[i].offset + sym * wordsize;
  			reloc->addr = sym == -1 ? 0 : bin->sects[i].addr + sym * wordsize;
```

## H25. CVE-2018-12460

CVE: libavcodec in FFmpeg 4.0 may trigger a NULL pointer dereference if the studio profile is incorrectly detected while converting a crafted AVI file to MPEG4, leading to a denial of service, related to idctdsp.c and mpegvideo.c.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,4 +1,6 @@
  av_cold void ff_mpv_idct_init(MpegEncContext *s)
  {
+    if (s->codec_id == AV_CODEC_ID_MPEG4)
+        s->idsp.mpeg4_studio_profile = s->studio_profile;
      ff_idctdsp_init(&s->idsp, s->avctx);
  
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,7 +1,13 @@
- av_cold void ff_mpv_idct_init(MpegEncContext *s)
- {
-     ff_idctdsp_init(&s->idsp, s->avctx);
- 
-     /* load & permutate scantables
+av_cold void ff_mpv_idct_init(MpegEncContext *s)
+{
+    if (!s || !s->avctx)
+        return;
+
+    ff_idctdsp_init(&s->idsp, s->avctx);
+
+    if (!s->idsp.idct_permutation)
+        return;
+
+    /* load & permutate scantables
      * note: only wmv uses different ones
      */
```

## H26. CVE-2014-4611

CVE: Integer overflow in the LZ4 algorithm implementation, as used in Yann Collet LZ4 before r118 and in the lz4_uncompress function in lib/lz4/lz4_decompress.c in the Linux kernel before 3.15.2, on 32-bit platforms might allow context-dependent attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via a crafted Literal Run that would be improperly handled

### Official fix
```diff
--- vulnerable
+++ patched
@@ -24,4 +24,6 @@
  			for (; len == 255; length += 255)
  				len = *ip++;
+			if (unlikely(length > (size_t)(length + len)))
+				goto _output_error;
  			length += len;
  		}
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -22,10 +22,17 @@
 
  			len = *ip++;
- 			for (; len == 255; length += 255)
+ 			for (; len == 255; length += 255) {
+ 				if (length > (size_t)(oend - op))
+ 					goto _output_error;
  				len = *ip++;
+ 			}
+ 			if (length > (size_t)(oend - op) - len)
+ 				goto _output_error;
  			length += len;
  		}
  
 		/* copy literals */
+		if (length > (size_t)(oend - op))
+			goto _output_error;
 		cpy = op + length;
 		if (unlikely(cpy > oend - COPYLENGTH)) {
```

## H27. CVE-2016-7166

CVE: libarchive before 3.2.0 does not limit the number of recursive decompressions, which allows remote attackers to cause a denial of service (memory consumption and application crash) via a crafted gzip file.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,5 +1,5 @@
  choose_filters(struct archive_read *a)
  {
-	int number_bidders, i, bid, best_bid;
+	int number_bidders, i, bid, best_bid, n;
  	struct archive_read_filter_bidder *bidder, *best_bidder;
  	struct archive_read_filter *filter;
@@ -7,5 +7,5 @@
  	int r;
  
-	for (;;) {
+	for (n = 0; n < 25; ++n) {
  		number_bidders = sizeof(a->bidders) / sizeof(a->bidders[0]);
  
@@ -53,3 +53,6 @@
  		}
  	}
+	archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
+	    "Input requires too many filters for decoding");
+	return (ARCHIVE_FATAL);
  }
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,14 +1,29 @@
- choose_filters(struct archive_read *a)
- {
+choose_filters(struct archive_read *a)
+{
 	int number_bidders, i, bid, best_bid;
- 	struct archive_read_filter_bidder *bidder, *best_bidder;
- 	struct archive_read_filter *filter;
- 	ssize_t avail;
- 	int r;
- 
+	struct archive_read_filter_bidder *bidder, *best_bidder;
+	struct archive_read_filter *filter;
+	ssize_t avail;
+	int r;
+	int filter_count;
+	struct archive_read_filter *tmp;
+
 	for (;;) {
- 		number_bidders = sizeof(a->bidders) / sizeof(a->bidders[0]);
- 
- 		best_bid = 0;
+		/* Count existing filters in the chain */
+		filter_count = 0;
+		tmp = a->filter;
+		while (tmp != NULL && tmp->bidder != NULL) {
+			filter_count++;
+			tmp = tmp->upstream;
+		}
+
+		/* Limit recursive decompression to prevent DoS */
+		if (filter_count >= 64) {
+			return (ARCHIVE_FATAL);
+		}
+
+		number_bidders = sizeof(a->bidders) / sizeof(a->bidders[0]);
+
+		best_bid = 0;
 		best_bidder = NULL;
 
@@ -50,6 +65,6 @@
 			__archive_read_close_filters(a);
 			__archive_read_free_filters(a);
- 			return (ARCHIVE_FATAL);
- 		}
- 	}
- }
+			return (ARCHIVE_FATAL);
+		}
+	}
+}
```

## H28. CVE-2015-5232

CVE: Race conditions in opa-fm before 10.4.0.0.196 and opa-ff before 10.4.0.0.197.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -3,4 +3,5 @@
  	int					fd, len;
  	struct sockaddr_un	unix_addr;
+	hsm_com_errno_t		res = HSM_COM_OK;
  
  	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) 
@@ -15,6 +16,6 @@
  	if(strlen(hdl->c_path) >= sizeof(unix_addr.sun_path))
  	{
-		close(fd);
-		return HSM_COM_PATH_ERR;
+		res = HSM_COM_PATH_ERR;
+		goto cleanup;
  	}
  
@@ -27,14 +28,12 @@
  	if(bind(fd, (struct sockaddr *)&unix_addr, len) < 0)
  	{
-		unlink(hdl->c_path);
-		close(fd);
-		return HSM_COM_BIND_ERR;
+		res = HSM_COM_BIND_ERR;
+		goto cleanup;
  	}
  
  	if(chmod(unix_addr.sun_path, S_IRWXU) < 0)
  	{
-		unlink(hdl->c_path);
-		close(fd);
-		return HSM_COM_CHMOD_ERR;
+		res = HSM_COM_CHMOD_ERR;
+		goto cleanup;
  	}
  
@@ -49,7 +48,6 @@
  	if (connect(fd, (struct sockaddr *) &unix_addr, len) < 0) 
  	{
-		unlink(hdl->c_path);
-		close(fd);
-		return HSM_COM_CONX_ERR;
+		res = HSM_COM_CONX_ERR;
+		goto cleanup;
  	}
  
@@ -60,9 +58,12 @@
  	{
  		hdl->client_state = HSM_COM_C_STATE_IN;
-		return HSM_COM_SEND_ERR;
+		res = HSM_COM_SEND_ERR;
  	}
  
+	return res;
  
-	return HSM_COM_OK;
+cleanup:
+	close(fd);
+	return res;
  
  }
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -23,9 +23,6 @@
 	len = SUN_LEN(&unix_addr);
 
-	unlink(unix_addr.sun_path);
- 
- 	if(bind(fd, (struct sockaddr *)&unix_addr, len) < 0)
+	if(bind(fd, (struct sockaddr *)&unix_addr, len) < 0)
  	{
-		unlink(hdl->c_path);
 		close(fd);
 		return HSM_COM_BIND_ERR;
@@ -34,5 +31,5 @@
  	if(chmod(unix_addr.sun_path, S_IRWXU) < 0)
  	{
-		unlink(hdl->c_path);
+		unlink(unix_addr.sun_path);
 		close(fd);
 		return HSM_COM_CHMOD_ERR;
```

## H29. CVE-2011-1180

CVE: Multiple stack-based buffer overflows in the iriap_getvaluebyclass_indication function in net/irda/iriap.c in the Linux kernel before 2.6.39 allow remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging connectivity to an IrDA infrared network and sending a large integer value for a (1) name length or (2) attribute length.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -21,8 +21,14 @@
  
  	name_len = fp[n++];
+
+	IRDA_ASSERT(name_len < IAS_MAX_CLASSNAME + 1, return;);
+
  	memcpy(name, fp+n, name_len); n+=name_len;
  	name[name_len] = '\0';
  
  	attr_len = fp[n++];
+
+	IRDA_ASSERT(attr_len < IAS_MAX_ATTRIBNAME + 1, return;);
+
  	memcpy(attr, fp+n, attr_len); n+=attr_len;
  	attr[attr_len] = '\0';
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -21,8 +21,12 @@
  
  	name_len = fp[n++];
+ 	if (name_len > IAS_MAX_CLASSNAME)
+ 		return;
  	memcpy(name, fp+n, name_len); n+=name_len;
  	name[name_len] = '\0';
  
  	attr_len = fp[n++];
+ 	if (attr_len > IAS_MAX_ATTRIBNAME)
+ 		return;
  	memcpy(attr, fp+n, attr_len); n+=attr_len;
  	attr[attr_len] = '\0';
```

## H30. CVE-2013-0911

CVE: Directory traversal vulnerability in Google Chrome before 25.0.1364.152 allows remote attackers to have an unspecified impact via vectors related to databases.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -4,4 +4,11 @@
                                               int64 estimated_size) {
    DCHECK(BrowserThread::CurrentlyOn(BrowserThread::FILE));
+
+  if (!DatabaseUtil::IsValidOriginIdentifier(origin_identifier)) {
+    RecordAction(UserMetricsAction("BadMessageTerminate_DBMF"));
+    BadMessageReceived();
+    return;
+  }
+
    int64 database_size = 0;
    db_tracker_->DatabaseOpened(origin_identifier, database_name, description,
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -4,4 +4,7 @@
                                               int64 estimated_size) {
    DCHECK(BrowserThread::CurrentlyOn(BrowserThread::FILE));
+   if (origin_identifier.empty() || database_name.empty()) {
+     return;
+   }
    int64 database_size = 0;
    db_tracker_->DatabaseOpened(origin_identifier, database_name, description,
```
