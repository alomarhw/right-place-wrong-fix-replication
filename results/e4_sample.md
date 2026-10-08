# E4 sample: 50 of 71 touch-but-rejected slice_grounded_full patches (repeat 1)

## 1. CVE-2014-4611 (CWE-20) item=8

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -22,6 +22,11 @@
 
  			len = *ip++;
- 			for (; len == 255; length += 255)
+ 			for (; len == 255; length += 255) {
+ 				if (length > (size_t)(oend - op))
+ 					goto _output_error;
  				len = *ip++;
+ 			}
+ 			if (length + len > (size_t)(oend - op))
+ 				goto _output_error;
  			length += len;
  		}
```

## 2. CVE-2014-4014 (CWE-264) item=9

CVE: The capabilities implementation in the Linux kernel before 3.14.8 does not properly consider that namespaces are inapplicable to inodes, which allows local users to bypass intended chmod restrictions by first creating a user namespace, as demonstrated by setting the setgid bit on a file with group ownership of root.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -21,5 +21,5 @@
  	    (!uid_eq(current_fsuid(), inode->i_uid) ||
  	     !uid_eq(attr->ia_uid, inode->i_uid)) &&
-	    !inode_capable(inode, CAP_CHOWN))
+	    !capable_wrt_inode_uidgid(inode, CAP_CHOWN))
  		return -EPERM;
  
@@ -28,5 +28,5 @@
  	    (!uid_eq(current_fsuid(), inode->i_uid) ||
  	    (!in_group_p(attr->ia_gid) && !gid_eq(attr->ia_gid, inode->i_gid))) &&
-	    !inode_capable(inode, CAP_CHOWN))
+	    !capable_wrt_inode_uidgid(inode, CAP_CHOWN))
  		return -EPERM;
  
@@ -38,5 +38,5 @@
  		if (!in_group_p((ia_valid & ATTR_GID) ? attr->ia_gid :
  				inode->i_gid) &&
-		    !inode_capable(inode, CAP_FSETID))
+		    !capable_wrt_inode_uidgid(inode, CAP_FSETID))
  			attr->ia_mode &= ~S_ISGID;
  	}
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -21,5 +21,5 @@
  	    (!uid_eq(current_fsuid(), inode->i_uid) ||
  	     !uid_eq(attr->ia_uid, inode->i_uid)) &&
-	    !inode_capable(inode, CAP_CHOWN))
+	    !capable(CAP_CHOWN))
  		return -EPERM;
  
@@ -28,5 +28,5 @@
  	    (!uid_eq(current_fsuid(), inode->i_uid) ||
  	    (!in_group_p(attr->ia_gid) && !gid_eq(attr->ia_gid, inode->i_gid))) &&
-	    !inode_capable(inode, CAP_CHOWN))
+	    !capable(CAP_CHOWN))
  		return -EPERM;
  
@@ -38,5 +38,5 @@
  		if (!in_group_p((ia_valid & ATTR_GID) ? attr->ia_gid :
  				inode->i_gid) &&
-		    !inode_capable(inode, CAP_FSETID))
+		    !capable(CAP_FSETID))
  			attr->ia_mode &= ~S_ISGID;
  	}
```

## 3. CVE-2010-1152 (CWE-20) item=12

CVE: memcached.c in memcached before 1.4.3 allows remote attackers to cause a denial of service (daemon hang or crash) via a long line that triggers excessive memory allocation.  NOTE: some of these details are obtained from third party information.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -2,4 +2,5 @@
      enum try_read_result gotdata = READ_NO_DATA_RECEIVED;
      int res;
+    int num_allocs = 0;
      assert(c != NULL);
  
@@ -12,4 +13,8 @@
      while (1) {
          if (c->rbytes >= c->rsize) {
+            if (num_allocs == 4) {
+                return gotdata;
+            }
+            ++num_allocs;
              char *new_rbuf = realloc(c->rbuf, c->rsize * 2);
              if (!new_rbuf) {
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,18 +1,28 @@
- static enum try_read_result try_read_network(conn *c) {
-     enum try_read_result gotdata = READ_NO_DATA_RECEIVED;
-     int res;
-     assert(c != NULL);
- 
-     if (c->rcurr != c->rbuf) {
+static enum try_read_result try_read_network(conn *c) {
+    enum try_read_result gotdata = READ_NO_DATA_RECEIVED;
+    int res;
+    assert(c != NULL);
+
+    if (c->rcurr != c->rbuf) {
         if (c->rbytes != 0) /* otherwise there's nothing to copy */
             memmove(c->rbuf, c->rcurr, c->rbytes);
         c->rcurr = c->rbuf;
     }
- 
-     while (1) {
-         if (c->rbytes >= c->rsize) {
-             char *new_rbuf = realloc(c->rbuf, c->rsize * 2);
-             if (!new_rbuf) {
-                 if (settings.verbose > 0)
+
+    while (1) {
+        if (c->rbytes >= c->rsize) {
+            /* Prevent unbounded buffer growth - enforce maximum size limit */
+            if (c->rsize >= 1024 * 1024) {
+                if (settings.verbose > 0)
+                    fprintf(stderr, "Input line too long\n");
+                c->rbytes = 0;
+                out_string(c, "SERVER_ERROR input line too long");
+                c->write_and_go = conn_closing;
+                return READ_MEMORY_ERROR;
+            }
+            
+            char *new_rbuf = realloc(c->rbuf, c->rsize * 2);
+            if (!new_rbuf) {
+                if (settings.verbose > 0)
                     fprintf(stderr, "Couldn't realloc input buffer\n");
                 c->rbytes = 0; /* ignore what we read */
```

## 4. CVE-2018-18349 (CWE-732) item=16

CVE: Remote frame navigations was incorrectly permitted to local resources in Blink in Google Chrome prior to 71.0.3578.80 allowed an attacker who convinced a user to install a malicious extension to access files on the local file system via a crafted Chrome Extension.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -3,4 +3,11 @@
                                       WebFrameLoadType frame_load_type,
                                       UserGestureStatus user_gesture_status) {
+  if (!origin_document.GetSecurityOrigin()->CanDisplay(url)) {
+    origin_document.AddConsoleMessage(ConsoleMessage::Create(
+        kSecurityMessageSource, kErrorMessageLevel,
+        "Not allowed to load local resource: " + url.ElidedString()));
+    return;
+  }
+
    FrameLoadRequest frame_request(&origin_document, ResourceRequest(url));
    frame_request.GetResourceRequest().SetHasUserGesture(
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -3,4 +3,13 @@
                                       WebFrameLoadType frame_load_type,
                                       UserGestureStatus user_gesture_status) {
+   // Block navigation to local resources from remote frames
+   if (url.ProtocolIsFile() || url.ProtocolIsData() || url.ProtocolIsAbout()) {
+      // Check if origin is also a local/restricted protocol
+      if (!origin_document.GetSecurityOrigin()->CanAccess(
+          SecurityOrigin::Create(url).get())) {
+         return;
+      }
+   }
+   
    FrameLoadRequest frame_request(&origin_document, ResourceRequest(url));
    frame_request.GetResourceRequest().SetHasUserGesture(
```

## 5. CVE-2013-4149 (CWE-119) item=19

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -34,16 +34,16 @@
         n->mac_table.in_use = qemu_get_be32(f);
         /* MAC_TABLE_ENTRIES may be different from the saved image */
-         if (n->mac_table.in_use <= MAC_TABLE_ENTRIES) {
-             qemu_get_buffer(f, n->mac_table.macs,
-                             n->mac_table.in_use * ETH_ALEN);
-        } else if (n->mac_table.in_use) {
-            uint8_t *buf = g_malloc0(n->mac_table.in_use);
+        if (n->mac_table.in_use <= MAC_TABLE_ENTRIES) {
+            qemu_get_buffer(f, n->mac_table.macs,
+                            n->mac_table.in_use * ETH_ALEN);
+        } else {
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

## 6. CVE-2017-8934 (CWE-20) item=20

CVE: PCManFM 1.2.5 insecurely uses /tmp for a socket file, allowing a local user to cause a denial of service (application unavailability).

### Official fix
```diff
--- vulnerable
+++ patched
@@ -12,4 +12,8 @@
      else
          dpynum = 0;
+#if GLIB_CHECK_VERSION(2, 28, 0)
+    g_snprintf(buf, len, "%s/%s-socket-%s-%d", g_get_user_runtime_dir(),
+               data->prog_name, host ? host : "", dpynum);
+#else
      g_snprintf(buf, len, "%s/.%s-socket-%s-%d-%s",
                  g_get_tmp_dir(),
@@ -18,3 +22,4 @@
                  dpynum,
                  g_get_user_name());
+#endif
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -7,14 +7,21 @@
     {
         const char* p = strrchr(dpy, ':');
-        host = g_strndup(dpy, (p - dpy));
-        dpynum = atoi(p + 1);
-     }
-     else
-         dpynum = 0;
-     g_snprintf(buf, len, "%s/.%s-socket-%s-%d-%s",
-                 g_get_tmp_dir(),
-                 data->prog_name,
-                 host ? host : "",
-                 dpynum,
-                 g_get_user_name());
- }
+        if(p)
+        {
+            host = g_strndup(dpy, (p - dpy));
+            dpynum = atoi(p + 1);
+        }
+        else
+            dpynum = 0;
+    }
+    else
+        dpynum = 0;
+    
+    g_snprintf(buf, len, "%s/.%s-socket-%s-%d-%s",
+                g_get_home_dir(),
+                data->prog_name,
+                host ? host : "",
+                dpynum,
+                g_get_user_name());
+    g_free(host);
+}
```

## 7. CVE-2018-18586 (CWE-22) item=21

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

### Agent patch
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

## 8. CVE-2016-4072 (CWE-20) item=22

CVE: The Phar extension in PHP before 5.5.34, 5.6.x before 5.6.20, and 7.x before 7.0.5 allows remote attackers to execute arbitrary code via a crafted filename, as demonstrated by mishandling of \0 characters by the phar_analyze_path function in ext/phar/phar.c.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -8,5 +8,5 @@
         PHAR_ARCHIVE_OBJECT();
  
-       if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &fname, &fname_len) == FAILURE) {
+       if (zend_parse_parameters(ZEND_NUM_ARGS(), "p", &fname, &fname_len) == FAILURE) {
                 return;
         }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -5,11 +5,17 @@
 	zval zfname;
 	phar_entry_info *entry;
-        zend_string *sfname;
-        PHAR_ARCHIVE_OBJECT();
- 
-       if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &fname, &fname_len) == FAILURE) {
-                return;
-        }
- 
+	zend_string *sfname;
+	PHAR_ARCHIVE_OBJECT();
+
+	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &fname, &fname_len) == FAILURE) {
+		return;
+	}
+
+	/* Reject filenames containing null bytes - CVE-2016-4072 */
+	if (fname_len > 0 && fname[fname_len] != '\0') {
+		zend_throw_exception_ex(spl_ce_BadMethodCallException, 0, "Entry name is not properly null-terminated");
+		return;
+	}
+
 	/* security is 0 here so that we can get a better error message than "entry doesn't exist" */
 	if (!(entry = phar_get_entry_info_dir(phar_obj->archive, fname, fname_len, 1, &error, 0))) {
```

## 9. CVE-2011-1833 (CWE-264) item=26

CVE: Race condition in the ecryptfs_mount function in fs/ecryptfs/main.c in the eCryptfs subsystem in the Linux kernel before 3.1 allows local users to bypass intended file permissions via a mount.ecryptfs_private mount with a mismatched uid.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -8,4 +8,5 @@
  	struct inode *inode;
  	struct path path;
+	uid_t check_ruid;
  	int rc;
  
@@ -16,5 +17,5 @@
  	}
  
-	rc = ecryptfs_parse_options(sbi, raw_data);
+	rc = ecryptfs_parse_options(sbi, raw_data, &check_ruid);
  	if (rc) {
  		err = "Error parsing options";
@@ -54,4 +55,13 @@
  		goto out_free;
  	}
+
+	if (check_ruid && path.dentry->d_inode->i_uid != current_uid()) {
+		rc = -EPERM;
+		printk(KERN_ERR "Mount of device (uid: %d) not owned by "
+		       "requested user (uid: %d)\n",
+		       path.dentry->d_inode->i_uid, current_uid());
+		goto out_free;
+	}
+
  	ecryptfs_set_superblock_lower(s, path.dentry->d_sb);
  	s->s_maxbytes = path.dentry->d_sb->s_maxbytes;
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -54,4 +54,11 @@
  		goto out_free;
  	}
+
+	if (path.dentry->d_inode->i_uid != current_uid()) {
+		rc = -EPERM;
+		err = "User does not have permission to mount ecryptfs on lower filesystem";
+		goto out_free;
+	}
+
  	ecryptfs_set_superblock_lower(s, path.dentry->d_sb);
  	s->s_maxbytes = path.dentry->d_sb->s_maxbytes;
```

## 10. CVE-2016-9777 (CWE-125) item=29

CVE: KVM in the Linux kernel before 4.8.12, when I/O APIC is enabled, does not properly restrict the VCPU index, which allows guest OS users to gain host OS privileges or cause a denial of service (out-of-bounds array access and host OS crash) via a crafted interrupt request, related to arch/x86/kvm/ioapic.c and arch/x86/kvm/ioapic.h.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -2,4 +2,4 @@
  {
  	ioapic->rtc_status.pending_eoi = 0;
-	bitmap_zero(ioapic->rtc_status.dest_map.map, KVM_MAX_VCPUS);
+	bitmap_zero(ioapic->rtc_status.dest_map.map, KVM_MAX_VCPU_ID);
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,5 +1,5 @@
- static void rtc_irq_eoi_tracking_reset(struct kvm_ioapic *ioapic)
- {
- 	ioapic->rtc_status.pending_eoi = 0;
-	bitmap_zero(ioapic->rtc_status.dest_map.map, KVM_MAX_VCPUS);
- }
+static void rtc_irq_eoi_tracking_reset(struct kvm_ioapic *ioapic)
+{
+	ioapic->rtc_status.pending_eoi = 0;
+	bitmap_zero(ioapic->rtc_status.dest_map.map, ioapic->kvm->online_vcpus);
+}
```

## 11. CVE-2018-7485 (CWE-119) item=34

CVE: The SQLWriteFileDSN function in odbcinst/SQLWriteFileDSN.c in unixODBC 2.3.5 has strncpy arguments in the wrong order, which allows attackers to cause a denial of service or possibly have unspecified other impact.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -9,5 +9,5 @@
  	if ( pszFileName[0] == '/' )
  	{
-		strncpy( szFileName, sizeof(szFileName) - 5, pszFileName );
+		strncpy( szFileName, pszFileName, sizeof(szFileName) - 5 );
  	}
  	else
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -6,8 +6,10 @@
 	HINI	hIni;
 	char	szFileName[ODBC_FILENAME_MAX+1];
+	size_t len;
  
  	if ( pszFileName[0] == '/' )
  	{
-		strncpy( szFileName, sizeof(szFileName) - 5, pszFileName );
+		strncpy( szFileName, pszFileName, sizeof(szFileName) - 1 );
+		szFileName[sizeof(szFileName) - 1] = '\0';
  	}
  	else
@@ -16,10 +18,11 @@
 		*szPath = '\0';
 		_odbcinst_FileINI( szPath );
-		snprintf( szFileName, sizeof(szFileName) - 5, "%s/%s", szPath, pszFileName );
+		snprintf( szFileName, sizeof(szFileName), "%s/%s", szPath, pszFileName );
 	}
 
-    if ( strlen( szFileName ) < 4 || strcmp( szFileName + strlen( szFileName ) - 4, ".dsn" ))
+	len = strlen( szFileName );
+    if ( len < 4 || strcmp( szFileName + len - 4, ".dsn" ))
     {
-        strcat( szFileName, ".dsn" );
+        snprintf( szFileName + len, sizeof(szFileName) - len, ".dsn" );
     }
 
```

## 12. CVE-2017-8924 (CWE-191) item=36

CVE: The edge_bulk_in_callback function in drivers/usb/serial/io_ti.c in the Linux kernel before 4.10.4 allows local users to obtain sensitive information (in the dmesg ringbuffer and syslog) from uninitialized kernel memory by using a crafted USB device (posing as an io_ti USB serial device) to trigger an integer underflow.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -32,5 +32,5 @@
  	port_number = edge_port->port->port_number;
  
-	if (edge_port->lsr_event) {
+	if (urb->actual_length > 0 && edge_port->lsr_event) {
  		edge_port->lsr_event = 0;
  		dev_dbg(dev, "%s ===== Port %u LSR Status = %02x, Data = %02x ======\n",
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -32,5 +32,5 @@
  	port_number = edge_port->port->port_number;
  
-	if (edge_port->lsr_event) {
+	if (edge_port->lsr_event && urb->actual_length) {
  		edge_port->lsr_event = 0;
  		dev_dbg(dev, "%s ===== Port %u LSR Status = %02x, Data = %02x ======\n",
```

## 13. CVE-2016-2105 (CWE-189) item=39

CVE: Integer overflow in the EVP_EncodeUpdate function in crypto/evp/encode.c in OpenSSL before 1.0.1t and 1.0.2 before 1.0.2h allows remote attackers to cause a denial of service (heap memory corruption) via a large amount of binary data.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -9,5 +9,5 @@
          return;
      OPENSSL_assert(ctx->length <= (int)sizeof(ctx->enc_data));
-    if ((ctx->num + inl) < ctx->length) {
+    if (ctx->length - ctx->num > inl) {
          memcpy(&(ctx->enc_data[ctx->num]), in, inl);
          ctx->num += inl;
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -9,7 +9,10 @@
          return;
      OPENSSL_assert(ctx->length <= (int)sizeof(ctx->enc_data));
-    if ((ctx->num + inl) < ctx->length) {
-         memcpy(&(ctx->enc_data[ctx->num]), in, inl);
-         ctx->num += inl;
+    if (ctx->num < 0 || inl < 0 || ctx->num > ctx->length || 
+        ctx->num > INT_MAX - inl || (ctx->num + inl) < ctx->length) {
+         if (ctx->num >= 0 && inl >= 0 && ctx->num <= INT_MAX - inl && (ctx->num + inl) < ctx->length) {
+             memcpy(&(ctx->enc_data[ctx->num]), in, inl);
+             ctx->num += inl;
+         }
          return;
     }
```

## 14. CVE-2012-2737 (CWE-362) item=43

CVE: The user_change_icon_file_authorized_cb function in /usr/libexec/accounts-daemon in AccountsService before 0.6.22 does not properly check the UID when copying an icon file to the system cache directory, which allows local users to read arbitrary files via a race condition.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,17 +1,34 @@
 get_caller_uid (GDBusMethodInvocation *context, gint *uid)
+get_caller_uid (GDBusMethodInvocation *context,
+                gint                  *uid)
  {
-        PolkitSubject *subject;
-        PolkitSubject *process;
+        GVariant      *reply;
+        GError        *error;
+
+        error = NULL;
+        reply = g_dbus_connection_call_sync (g_dbus_method_invocation_get_connection (context),
+                                             "org.freedesktop.DBus",
+                                             "/org/freedesktop/DBus",
+                                             "org.freedesktop.DBus",
+                                             "GetConnectionUnixUser",
+                                             g_variant_new ("(s)",
+                                                            g_dbus_method_invocation_get_sender (context)),
+                                             G_VARIANT_TYPE ("(u)"),
+                                             G_DBUS_CALL_FLAGS_NONE,
+                                             -1,
+                                             NULL,
+                                             &error);
+
+        if (reply == NULL) {
+                g_warning ("Could not talk to message bus to find uid of sender %s: %s",
+                           g_dbus_method_invocation_get_sender (context),
+                           error->message);
+                g_error_free (error);
  
-        subject = polkit_system_bus_name_new (g_dbus_method_invocation_get_sender (context));
-        process = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject), NULL, NULL);
-        if (!process) {
-                g_object_unref (subject);
                  return FALSE;
          }
  
-        *uid = polkit_unix_process_get_uid (POLKIT_UNIX_PROCESS (process));
-        g_object_unref (subject);
-        g_object_unref (process);
+        g_variant_get (reply, "(u)", uid);
+        g_variant_unref (reply);
  
          return TRUE;
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,18 +1,17 @@
 get_caller_uid (GDBusMethodInvocation *context, gint *uid)
- {
+{
         PolkitSubject *subject;
         PolkitSubject *process;
- 
+        gboolean result = FALSE;
+
         subject = polkit_system_bus_name_new (g_dbus_method_invocation_get_sender (context));
         process = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject), NULL, NULL);
-        if (!process) {
-                g_object_unref (subject);
-                 return FALSE;
-         }
- 
-        *uid = polkit_unix_process_get_uid (POLKIT_UNIX_PROCESS (process));
+        if (process) {
+                *uid = polkit_unix_process_get_uid (POLKIT_UNIX_PROCESS (process));
+                g_object_unref (process);
+                result = TRUE;
+        }
         g_object_unref (subject);
-        g_object_unref (process);
- 
-         return TRUE;
- }
+
+        return result;
+}
```

## 15. CVE-2017-15906 (CWE-269) item=44

CVE: The process_open function in sftp-server.c in OpenSSH before 7.6 does not properly prevent write operations in readonly mode, which allows attackers to create zero-length files.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -17,6 +17,6 @@
  	    name, string_from_portable(pflags), mode);
  	if (readonly &&
-	    ((flags & O_ACCMODE) == O_WRONLY ||
-	    (flags & O_ACCMODE) == O_RDWR)) {
+	    ((flags & O_ACCMODE) != O_RDONLY ||
+	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
  		verbose("Refusing open request in read-only mode");
  		status = SSH2_FX_PERMISSION_DENIED;
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -17,9 +17,13 @@
  	    name, string_from_portable(pflags), mode);
  	if (readonly &&
-	    ((flags & O_ACCMODE) == O_WRONLY ||
-	    (flags & O_ACCMODE) == O_RDWR)) {
+	    (((flags & O_ACCMODE) == O_WRONLY ||
+	    (flags & O_ACCMODE) == O_RDWR) ||
+	    (flags & O_CREAT))) {
  		verbose("Refusing open request in read-only mode");
  		status = SSH2_FX_PERMISSION_DENIED;
- 	} else {
+ 	} else if (readonly && (flags & O_CREAT)) {
+ 		verbose("Refusing open request in read-only mode");
+ 		status = SSH2_FX_PERMISSION_DENIED;
+	} else {
 		fd = open(name, flags, mode);
 		if (fd < 0) {
```

## 16. CVE-2016-8693 (CWE-415) item=45

CVE: Double free vulnerability in the mem_close function in jas_stream.c in JasPer before 1.900.10 allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted BMP image to the imginfo command.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -3,7 +3,8 @@
  	unsigned char *buf;
  
-	assert(m->buf_);
+	//assert(m->buf_);
  	assert(bufsize >= 0);
-	if (!(buf = jas_realloc2(m->buf_, bufsize, sizeof(unsigned char)))) {
+	if (!(buf = jas_realloc2(m->buf_, bufsize, sizeof(unsigned char))) &&
+	  bufsize) {
  		return -1;
  	}
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,12 +1,13 @@
 static int mem_resize(jas_stream_memobj_t *m, int bufsize)
- {
- 	unsigned char *buf;
- 
+{
+	unsigned char *buf;
+
 	assert(m->buf_);
- 	assert(bufsize >= 0);
-	if (!(buf = jas_realloc2(m->buf_, bufsize, sizeof(unsigned char)))) {
- 		return -1;
- 	}
- 	m->buf_ = buf;
+	assert(bufsize >= 0);
+	buf = jas_realloc2(m->buf_, bufsize, sizeof(unsigned char));
+	if (!buf) {
+		return -1;
+	}
+	m->buf_ = buf;
 	m->bufsize_ = bufsize;
 	return 0;
```

## 17. CVE-2019-15163 (CWE-476) item=47

CVE: rpcapd/daemon.c in libpcap before 1.9.1 allows attackers to cause a denial of service (NULL pointer dereference and daemon crash) if a crypt() call fails.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -64,4 +64,5 @@
  	struct spwd *usersp;
  #endif
+	char *crypt_password;
  
  	if ((user = getpwnam(username)) == NULL)
@@ -92,5 +93,11 @@
  #endif
  
-	if (strcmp(user_password, (char *) crypt(password, user_password)) != 0)
+	crypt_password = crypt(password, user_password);
+	if (crypt_password == NULL)
+	{
+		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed");
+		return -1;
+	}
+	if (strcmp(user_password, crypt_password) != 0)
  	{
  		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: user name or password incorrect");
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -61,4 +61,5 @@
 	struct passwd *user;
 	char *user_password;
+	char *crypt_result;
  #ifdef HAVE_GETSPNAM
  	struct spwd *usersp;
@@ -92,5 +93,6 @@
  #endif
  
-	if (strcmp(user_password, (char *) crypt(password, user_password)) != 0)
+	crypt_result = crypt(password, user_password);
+	if (crypt_result == NULL || strcmp(user_password, crypt_result) != 0)
  	{
  		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: user name or password incorrect");
```

## 18. CVE-2016-1631 (CWE-264) item=49

CVE: The PPB_Flash_MessageLoop_Impl::InternalRun function in content/renderer/pepper/ppb_flash_message_loop_impl.cc in the Pepper plugin in Google Chrome before 49.0.2623.75 mishandles nested message loops, which allows remote attackers to bypass the Same Origin Policy via a crafted web site.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -13,5 +13,9 @@
      base::MessageLoop::ScopedNestableTaskAllower allow(
          base::MessageLoop::current());
+    blink::WebView::willEnterModalLoop();
+
      base::MessageLoop::current()->Run();
+
+    blink::WebView::didExitModalLoop();
    }
  
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -2,4 +2,9 @@
     const RunFromHostProxyCallback& callback) {
   if (state_->run_called()) {
+    if (!callback.is_null())
+      callback.Run(PP_ERROR_FAILED);
+    return PP_ERROR_FAILED;
+  }
+  if (state_->run_depth() > 0) {
     if (!callback.is_null())
       callback.Run(PP_ERROR_FAILED);
@@ -10,10 +15,8 @@
 
   scoped_refptr<State> state_protector(state_);
-   {
-     base::MessageLoop::ScopedNestableTaskAllower allow(
-         base::MessageLoop::current());
-     base::MessageLoop::current()->Run();
-   }
- 
+  {
+    base::MessageLoop::current()->Run();
+  }
+
   return state_protector->result();
 }
```

## 19. CVE-2016-5220 (CWE-200) item=52

CVE: PDFium in Google Chrome prior to 55.0.2883.75 for Mac, Windows and Linux, and 55.0.2883.84 for Android incorrectly handled navigation within PDFs, which allowed a remote attacker to read local files via a crafted PDF file.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,4 +1,7 @@
  bool OmniboxViewViews::ShouldShowPlaceholderText() const {
+  bool show_with_caret = base::FeatureList::IsEnabled(
+      omnibox::kUIExperimentShowPlaceholderWhenCaretShowing);
    return Textfield::ShouldShowPlaceholderText() &&
-         !model()->is_caret_visible() && !model()->is_keyword_selected();
+         (show_with_caret || !model()->is_caret_visible()) &&
+         !model()->is_keyword_selected();
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,4 +1,10 @@
- bool OmniboxViewViews::ShouldShowPlaceholderText() const {
-   return Textfield::ShouldShowPlaceholderText() &&
-         !model()->is_caret_visible() && !model()->is_keyword_selected();
- }
+bool OmniboxViewViews::ShouldShowPlaceholderText() const {
+  if (!Textfield::ShouldShowPlaceholderText()) {
+    return false;
+  }
+  OmniboxEditModel* m = model();
+  if (!m) {
+    return false;
+  }
+  return !m->is_caret_visible() && !m->is_keyword_selected();
+}
```

## 20. CVE-2017-6892 (CWE-119) item=54

CVE: In libsndfile version 1.0.28, an error in the "aiff_read_chanmap()" function (aiff.c) can be exploited to cause an out-of-bounds read memory access via a specially crafted AIFF file.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -17,5 +17,5 @@
  
  	if (map_info->channel_map != NULL)
-	{	size_t chanmap_size = psf->sf.channels * sizeof (psf->channel_map [0]) ;
+	{	size_t chanmap_size = SF_MIN (psf->sf.channels, layout_tag & 0xffff) * sizeof (psf->channel_map [0]) ;
  
  		free (psf->channel_map) ;
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -17,12 +17,15 @@
  
  	if (map_info->channel_map != NULL)
-	{	size_t chanmap_size = psf->sf.channels * sizeof (psf->channel_map [0]) ;
- 
+	{	size_t chanmap_size, source_size ;
+
  		free (psf->channel_map) ;
  
+		chanmap_size = psf->sf.channels * sizeof (psf->channel_map [0]) ;
+		source_size = map_info->channels * sizeof (psf->channel_map [0]) ;
+
 		if ((psf->channel_map = malloc (chanmap_size)) == NULL)
 			return SFE_MALLOC_FAILED ;
 
-		memcpy (psf->channel_map, map_info->channel_map, chanmap_size) ;
+		memcpy (psf->channel_map, map_info->channel_map, (chanmap_size < source_size) ? chanmap_size : source_size) ;
 		} ;
 
```

## 21. CVE-2011-2200 (CWE-20) item=55

CVE: The _dbus_header_byteswap function in dbus-marshal-header.c in D-Bus (aka DBus) 1.2.x before 1.2.28, 1.4.x before 1.4.12, and 1.5.x before 1.5.4 does not properly handle a non-native byte order, which allows local users to cause a denial of service (connection loss), obtain potentially sensitive information, or conduct unspecified state-modification attacks via crafted messages.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -2,7 +2,12 @@
                         int         new_order)
  {
+  unsigned char byte_order;
+
    if (header->byte_order == new_order)
      return;
  
+  byte_order = _dbus_string_get_byte (&header->data, BYTE_ORDER_OFFSET);
+  _dbus_assert (header->byte_order == byte_order);
+
    _dbus_marshal_byteswap (&_dbus_header_signature_str,
                            0, header->byte_order,
@@ -10,4 +15,5 @@
                            &header->data, 0);
  
+  _dbus_string_set_byte (&header->data, BYTE_ORDER_OFFSET, new_order);
    header->byte_order = new_order;
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,13 +1,22 @@
- _dbus_header_byteswap (DBusHeader *header,
-                        int         new_order)
- {
-   if (header->byte_order == new_order)
-     return;
- 
-   _dbus_marshal_byteswap (&_dbus_header_signature_str,
-                           0, header->byte_order,
-                           new_order,
-                           &header->data, 0);
- 
-   header->byte_order = new_order;
- }
+dbus_bool_t
+_dbus_header_byteswap (DBusHeader *header,
+                       int         new_order)
+{
+  if (header == NULL)
+    return FALSE;
+  
+  if (new_order != DBUS_LITTLE_ENDIAN && new_order != DBUS_BIG_ENDIAN)
+    return FALSE;
+
+  if (header->byte_order == new_order)
+    return TRUE;
+
+  _dbus_marshal_byteswap (&_dbus_header_signature_str,
+                          0, header->byte_order,
+                          new_order,
+                          &header->data, 0);
+
+  header->byte_order = new_order;
+  
+  return TRUE;
+}
```

## 22. CVE-2015-8953 (CWE-399) item=61

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -70,7 +70,9 @@
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
+	dput(upper);
+	newdentry = NULL;
+	goto out1;
+}
```

## 23. CVE-2019-5759 (CWE-416) item=65

CVE: Incorrect lifetime handling in HTML select elements in Google Chrome on Android and Mac prior to 72.0.3626.81 allowed a remote attacker to potentially perform a sandbox escape via a crafted HTML page.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -6,5 +6,9 @@
  
    blink::WebScopedUserGesture gesture(frame_);
-  external_popup_menu_->DidSelectItems(canceled, selected_indices);
-  external_popup_menu_.reset();
+  // We need to reset |external_popup_menu_| before calling DidSelectItems(),
+  // which might delete |this|.
+  // See ExternalPopupMenuRemoveTest.RemoveFrameOnChange
+  std::unique_ptr<ExternalPopupMenu> popup;
+  popup.swap(external_popup_menu_);
+  popup->DidSelectItems(canceled, selected_indices);
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,10 +1,10 @@
- void RenderFrameImpl::OnSelectPopupMenuItems(
+void RenderFrameImpl::OnSelectPopupMenuItems(
     bool canceled,
     const std::vector<int>& selected_indices) {
   if (!external_popup_menu_)
-     return;
- 
-   blink::WebScopedUserGesture gesture(frame_);
-  external_popup_menu_->DidSelectItems(canceled, selected_indices);
-  external_popup_menu_.reset();
- }
+    return;
+
+  blink::WebScopedUserGesture gesture(frame_);
+  auto popup_menu = std::move(external_popup_menu_);
+  popup_menu->DidSelectItems(canceled, selected_indices);
+}
```

## 24. CVE-2016-7126 (CWE-787) item=67

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -12,6 +12,6 @@
  	ZEND_FETCH_RESOURCE(im, gdImagePtr, &IM, -1, "Image", le_gd);
  
-	if (ncolors <= 0) {
-		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Number of colors has to be greater than zero");
+	if (ncolors <= 0 || ncolors > 256) {
+		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Number of colors has to be greater than zero and less than or equal to 256");
  		RETURN_FALSE;
  	}
```

## 25. CVE-2013-4270 (CWE-20) item=70

CVE: The net_ctl_permissions function in net/sysctl_net.c in the Linux kernel before 3.11.5 does not properly determine uid and gid values, which allows local users to bypass intended /proc/sys/net restrictions via a crafted application.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -8,10 +8,10 @@
  	/* Allow network administrator to have same access as root. */
  	if (ns_capable(net->user_ns, CAP_NET_ADMIN) ||
-	    uid_eq(root_uid, current_uid())) {
+	    uid_eq(root_uid, current_euid())) {
  		int mode = (table->mode >> 6) & 7;
  		return (mode << 6) | (mode << 3) | mode;
  	}
  	/* Allow netns root group to have the same access as the root group */
-	if (gid_eq(root_gid, current_gid())) {
+	if (in_egroup_p(root_gid)) {
  		int mode = (table->mode >> 3) & 7;
  		return (mode << 3) | mode;
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -5,16 +5,18 @@
 	kuid_t root_uid = make_kuid(net->user_ns, 0);
 	kgid_t root_gid = make_kgid(net->user_ns, 0);
- 
- 	/* Allow network administrator to have same access as root. */
- 	if (ns_capable(net->user_ns, CAP_NET_ADMIN) ||
-	    uid_eq(root_uid, current_uid())) {
- 		int mode = (table->mode >> 6) & 7;
- 		return (mode << 6) | (mode << 3) | mode;
- 	}
- 	/* Allow netns root group to have the same access as the root group */
-	if (gid_eq(root_gid, current_gid())) {
- 		int mode = (table->mode >> 3) & 7;
- 		return (mode << 3) | mode;
- 	}
+	kuid_t current_uid_mapped = make_kuid(net->user_ns, from_kuid_munged(current_user_ns(), current_uid()));
+	kgid_t current_gid_mapped = make_kgid(net->user_ns, from_kgid_munged(current_user_ns(), current_gid()));
+
+	/* Allow network administrator to have same access as root. */
+	if (ns_capable(net->user_ns, CAP_NET_ADMIN) ||
+	    uid_eq(root_uid, current_uid_mapped)) {
+		int mode = (table->mode >> 6) & 7;
+		return (mode << 6) | (mode << 3) | mode;
+	}
+	/* Allow netns root group to have the same access as the root group */
+	if (gid_eq(root_gid, current_gid_mapped)) {
+		int mode = (table->mode >> 3) & 7;
+		return (mode << 3) | mode;
+	}
 	return table->mode;
 }
```

## 26. CVE-2012-6538 (CWE-200) item=72

CVE: The copy_to_user_auth function in net/xfrm/xfrm_user.c in the Linux kernel before 3.6 uses an incorrect C library function for copying a string, which allows local users to obtain sensitive information from kernel heap memory by leveraging the CAP_NET_ADMIN capability.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -10,5 +10,5 @@
  
  	algo = nla_data(nla);
-	strcpy(algo->alg_name, auth->alg_name);
+	strncpy(algo->alg_name, auth->alg_name, sizeof(algo->alg_name));
  	memcpy(algo->alg_key, auth->alg_key, (auth->alg_key_len + 7) / 8);
  	algo->alg_key_len = auth->alg_key_len;
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -10,5 +10,6 @@
  
  	algo = nla_data(nla);
-	strcpy(algo->alg_name, auth->alg_name);
+	strncpy(algo->alg_name, auth->alg_name, sizeof(algo->alg_name) - 1);
+	algo->alg_name[sizeof(algo->alg_name) - 1] = '\0';
  	memcpy(algo->alg_key, auth->alg_key, (auth->alg_key_len + 7) / 8);
  	algo->alg_key_len = auth->alg_key_len;
```

## 27. CVE-2017-5552 (CWE-772) item=76

CVE: Memory leak in the virgl_resource_attach_backing function in hw/display/virtio-gpu-3d.c in QEMU (aka Quick Emulator) allows local guest OS users to cause a denial of service (host memory consumption) via a large number of VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING commands.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -15,5 +15,8 @@
      }
  
-    virgl_renderer_resource_attach_iov(att_rb.resource_id,
-                                       res_iovs, att_rb.nr_entries);
+    ret = virgl_renderer_resource_attach_iov(att_rb.resource_id,
+                                             res_iovs, att_rb.nr_entries);
+
+    if (ret != 0)
+        virtio_gpu_cleanup_mapping_iov(res_iovs, att_rb.nr_entries);
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -12,8 +12,9 @@
     if (ret != 0) {
         cmd->error = VIRTIO_GPU_RESP_ERR_UNSPEC;
-         return;
-     }
- 
+        return;
+    }
+
     virgl_renderer_resource_attach_iov(att_rb.resource_id,
                                        res_iovs, att_rb.nr_entries);
- }
+    g_free(res_iovs);
+}
```

## 28. CVE-2015-5232 (CWE-362) item=77

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

### Agent patch
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

## 29. CVE-2018-10887 (CWE-125) item=81

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -43,15 +43,36 @@
  			size_t off = 0, len = 0;
  
- 			if (cmd & 0x01) off = *delta++;
- 			if (cmd & 0x02) off |= *delta++ << 8UL;
- 			if (cmd & 0x04) off |= *delta++ << 16UL;
-			if (cmd & 0x08) off |= *delta++ << 24UL;
+ 			if (cmd & 0x01) {
+ 				if (delta >= delta_end) goto fail;
+ 				off = (size_t)((unsigned char)*delta++);
+ 			}
+ 			if (cmd & 0x02) {
+ 				if (delta >= delta_end) goto fail;
+ 				off |= ((size_t)((unsigned char)*delta++)) << 8UL;
+ 			}
+ 			if (cmd & 0x04) {
+ 				if (delta >= delta_end) goto fail;
+ 				off |= ((size_t)((unsigned char)*delta++)) << 16UL;
+ 			}
+			if (cmd & 0x08) {
+				if (delta >= delta_end) goto fail;
+				off |= ((size_t)((unsigned char)*delta++)) << 24UL;
+			}
  
- 			if (cmd & 0x10) len = *delta++;
- 			if (cmd & 0x20) len |= *delta++ << 8UL;
- 			if (cmd & 0x40) len |= *delta++ << 16UL;
-			if (!len)		len = 0x10000;
+ 			if (cmd & 0x10) {
+ 				if (delta >= delta_end) goto fail;
+ 				len = (size_t)((unsigned char)*delta++);
+ 			}
+ 			if (cmd & 0x20) {
+ 				if (delta >= delta_end) goto fail;
+ 				len |= ((size_t)((unsigned char)*delta++)) << 8UL;
+ 			}
+ 			if (cmd & 0x40) {
+ 				if (delta >= delta_end) goto fail;
+ 				len |= ((size_t)((unsigned char)*delta++)) << 16UL;
+ 			}
+			if (!len) len = 0x10000;
  
- 			if (base_len < off + len || res_sz < len)
+ 			if (off > base_len || base_len - off < len || res_sz < len)
  				goto fail;
  			memcpy(res_dp, base + off, len);
```

## 30. CVE-2017-13198 (CWE-20) item=82

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -5,4 +5,10 @@
  if (!gif) {
         ALOGD("Cannot drawFrame, mGif is NULL");
+ return -1;
+ }
+
+ const int maxFrame = gif->ImageCount;
+ if (frameNr < 0 || frameNr >= maxFrame) {
+        ALOGD("Cannot drawFrame, frameNr %d out of bounds [0, %d)", frameNr, maxFrame);
  return -1;
  }
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

## 31. CVE-2017-13189 (CWE-770) item=85

CVE: A vulnerability in the Android media framework (libavc) related to handling dec_hdl memory allocation failures. Product: Android. Versions: 7.0, 7.1.1, 7.1.2, 8.0, 8.1. Android ID: A-68300072.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,17 +1,35 @@
  WORD32 ih264d_create(iv_obj_t *dec_hdl, void *pv_api_ip, void *pv_api_op)
  {
+    ih264d_create_ip_t *ps_create_ip;
      ih264d_create_op_t *ps_create_op;
  
      WORD32 ret;
  
+    ps_create_ip = (ih264d_create_ip_t *)pv_api_ip;
      ps_create_op = (ih264d_create_op_t *)pv_api_op;
  
      ps_create_op->s_ivd_create_op_t.u4_error_code = 0;
+    dec_hdl = NULL;
      ret = ih264d_allocate_static_bufs(&dec_hdl, pv_api_ip, pv_api_op);
  
      /* If allocation of some buffer fails, then free buffers allocated till then */
-    if((IV_FAIL == ret) && (NULL != dec_hdl))
+    if(IV_FAIL == ret)
      {
-        ih264d_free_static_bufs(dec_hdl);
+        if(dec_hdl)
+        {
+            if(dec_hdl->pv_codec_handle)
+            {
+                ih264d_free_static_bufs(dec_hdl);
+            }
+            else
+            {
+                void (*pf_aligned_free)(void *pv_mem_ctxt, void *pv_buf);
+                void *pv_mem_ctxt;
+
+                pf_aligned_free = ps_create_ip->s_ivd_create_ip_t.pf_aligned_free;
+                pv_mem_ctxt  = ps_create_ip->s_ivd_create_ip_t.pv_mem_ctxt;
+                pf_aligned_free(pv_mem_ctxt, dec_hdl);
+            }
+        }
          ps_create_op->s_ivd_create_op_t.u4_error_code = IVD_MEM_ALLOC_FAILED;
          ps_create_op->s_ivd_create_op_t.u4_error_code = 1 << IVD_FATALERROR;
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,23 +1,21 @@
- WORD32 ih264d_create(iv_obj_t *dec_hdl, void *pv_api_ip, void *pv_api_op)
- {
-     ih264d_create_op_t *ps_create_op;
- 
-     WORD32 ret;
- 
-     ps_create_op = (ih264d_create_op_t *)pv_api_op;
- 
-     ps_create_op->s_ivd_create_op_t.u4_error_code = 0;
-     ret = ih264d_allocate_static_bufs(&dec_hdl, pv_api_ip, pv_api_op);
- 
-     /* If allocation of some buffer fails, then free buffers allocated till then */
-    if((IV_FAIL == ret) && (NULL != dec_hdl))
-     {
-        ih264d_free_static_bufs(dec_hdl);
-         ps_create_op->s_ivd_create_op_t.u4_error_code = IVD_MEM_ALLOC_FAILED;
-         ps_create_op->s_ivd_create_op_t.u4_error_code = 1 << IVD_FATALERROR;
- 
- return IV_FAIL;
- }
+WORD32 ih264d_create(iv_obj_t *dec_hdl, void *pv_api_ip, void *pv_api_op)
+{
+    ih264d_create_op_t *ps_create_op;
 
- return IV_SUCCESS;
+    WORD32 ret;
+
+    ps_create_op = (ih264d_create_op_t *)pv_api_op;
+
+    ps_create_op->s_ivd_create_op_t.u4_error_code = 0;
+    ret = ih264d_allocate_static_bufs(&dec_hdl, pv_api_ip, pv_api_op);
+
+    if(IV_FAIL == ret)
+    {
+        ps_create_op->s_ivd_create_op_t.u4_error_code = IVD_MEM_ALLOC_FAILED;
+        ps_create_op->s_ivd_create_op_t.u4_error_code = 1 << IVD_FATALERROR;
+
+        return IV_FAIL;
+    }
+
+    return IV_SUCCESS;
 }
```

## 32. CVE-2019-12111 (CWE-476) item=90

CVE: A Denial Of Service vulnerability in MiniUPnP MiniUPnPd through 2.1 exists due to a NULL pointer dereference in copyIPv6IfDifferent in pcpserver.c.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,5 +1,5 @@
  static void copyIPv6IfDifferent(void * dest, const void * src)
  {
-	if(dest != src) {
+	if(dest != src && src != NULL) {
  		memcpy(dest, src, sizeof(struct in6_addr));
  	}
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,6 +1,6 @@
- static void copyIPv6IfDifferent(void * dest, const void * src)
- {
-	if(dest != src) {
- 		memcpy(dest, src, sizeof(struct in6_addr));
- 	}
- }
+static void copyIPv6IfDifferent(void * dest, const void * src)
+{
+	if(dest != NULL && src != NULL && dest != src) {
+		memcpy(dest, src, sizeof(struct in6_addr));
+	}
+}
```

## 33. CVE-2013-0925 (CWE-264) item=92

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,11 +1,16 @@
 DictionaryValue* ExtensionTabUtil::CreateTabValue(
     const WebContents* contents,
-     TabStripModel* tab_strip,
-     int tab_index,
-     const Extension* extension) {
-  bool has_permission = extension && extension->HasAPIPermissionForTab(
-      GetTabId(contents), APIPermission::kTab);
+    TabStripModel* tab_strip,
+    int tab_index,
+    const Extension* extension) {
+  bool has_permission = false;
+  
+  if (extension != NULL) {
+    has_permission = extension->HasAPIPermissionForTab(
+        GetTabId(contents), APIPermission::kTab);
+  }
+  
   return CreateTabValue(contents, tab_strip, tab_index,
                         has_permission ? INCLUDE_PRIVACY_SENSITIVE_FIELDS :
                             OMIT_PRIVACY_SENSITIVE_FIELDS);
- }
+}
```

## 34. CVE-2016-6561 (CWE-476) item=95

CVE: illumos smbsrv NULL pointer dereference allows system crash.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,5 +1,4 @@
  smb2_flush(smb_request_t *sr)
  {
-	smb_ofile_t *of = NULL;
  	uint16_t StructSize;
  	uint16_t reserved1;
@@ -29,12 +28,6 @@
  		return (SDRC_SUCCESS);
  	}
-	of = sr->fid_ofile;
  
-	/*
-	 * XXX - todo:
-	 * Flush named pipe should drain writes.
-	 */
-	if ((of->f_node->flags & NODE_FLAGS_WRITE_THROUGH) == 0)
-		(void) smb_fsop_commit(sr, of->f_cr, of->f_node);
+	smb_ofile_flush(sr, sr->fid_ofile);
  
  	/*
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,8 +1,8 @@
- smb2_flush(smb_request_t *sr)
- {
+smb2_flush(smb_request_t *sr)
+{
 	smb_ofile_t *of = NULL;
- 	uint16_t StructSize;
- 	uint16_t reserved1;
- 	uint32_t reserved2;
+	uint16_t StructSize;
+	uint16_t reserved1;
+	uint32_t reserved2;
 	smb2fid_t smb2fid;
 	uint32_t status;
@@ -25,10 +25,14 @@
 
 	status = smb2sr_lookup_fid(sr, &smb2fid);
+	of = sr->fid_ofile;
+	if (of == NULL) {
+		smb2sr_put_error(sr, status ? status : NT_STATUS_FILE_CLOSED);
+		return (SDRC_SUCCESS);
+	}
 	if (status) {
- 		smb2sr_put_error(sr, status);
- 		return (SDRC_SUCCESS);
- 	}
-	of = sr->fid_ofile;
- 
+		smb2sr_put_error(sr, status);
+		return (SDRC_SUCCESS);
+	}
+
 	/*
 	 * XXX - todo:
@@ -37,7 +41,7 @@
 	if ((of->f_node->flags & NODE_FLAGS_WRITE_THROUGH) == 0)
 		(void) smb_fsop_commit(sr, of->f_cr, of->f_node);
- 
- 	/*
- 	 * SMB2 Flush reply
+
+	/*
+	 * SMB2 Flush reply
 	 */
 	(void) smb_mbc_encodef(
```

## 35. CVE-2014-3615 (CWE-200) item=97

CVE: The VGA emulator in QEMU allows local guest users to read host memory by setting the display to a high resolution.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -2,9 +2,21 @@
  {
      QXLDevSurfaceCreate surface;
+    uint64_t surface_size;
  
      memset(&surface, 0, sizeof(surface));
  
-    dprint(1, "%s/%d: %dx%d\n", __func__, ssd->qxl.id,
-           surface_width(ssd->ds), surface_height(ssd->ds));
+    surface_size = (uint64_t) surface_width(ssd->ds) *
+        surface_height(ssd->ds) * 4;
+    assert(surface_size > 0);
+    assert(surface_size < INT_MAX);
+    if (ssd->bufsize < surface_size) {
+        ssd->bufsize = surface_size;
+        g_free(ssd->buf);
+        ssd->buf = g_malloc(ssd->bufsize);
+    }
+
+    dprint(1, "%s/%d: %ux%u (size %" PRIu64 "/%d)\n", __func__, ssd->qxl.id,
+           surface_width(ssd->ds), surface_height(ssd->ds),
+           surface_size, ssd->bufsize);
  
      surface.format     = SPICE_SURFACE_FMT_32_xRGB;
@@ -37,6 +49,4 @@
          ssd->num_surfaces = 1024;
      }
-    ssd->bufsize = (16 * 1024 * 1024);
-    ssd->buf = g_malloc(ssd->bufsize);
  }
  
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,51 +1,35 @@
- void qemu_spice_create_host_primary(SimpleSpiceDisplay *ssd)
- {
-     QXLDevSurfaceCreate surface;
- 
-     memset(&surface, 0, sizeof(surface));
- 
+void qemu_spice_create_host_primary(SimpleSpiceDisplay *ssd)
+{
+    QXLDevSurfaceCreate surface;
+    uint64_t required_size;
+
+    memset(&surface, 0, sizeof(surface));
+
     dprint(1, "%s/%d: %dx%d\n", __func__, ssd->qxl.id,
            surface_width(ssd->ds), surface_height(ssd->ds));
- 
-     surface.format     = SPICE_SURFACE_FMT_32_xRGB;
-     surface.width      = surface_width(ssd->ds);
-{
-    dprint(1, "%s/%d:\n", __func__, ssd->qxl.id);
 
-    qemu_spice_destroy_primary_surface(ssd, 0, QXL_SYNC);
+    surface.format     = SPICE_SURFACE_FMT_32_xRGB;
+    surface.width      = surface_width(ssd->ds);
+    surface.height     = surface_height(ssd->ds);
+    
+    /* Calculate required buffer size: 4 bytes per pixel (32-bit xRGB) */
+    required_size = (uint64_t)surface.width * surface.height * 4;
+    
+    /* Limit to reasonable maximum to prevent overflow */
+    if (required_size > (16 * 1024 * 1024)) {
+        required_size = 16 * 1024 * 1024;
+    }
+    
+    ssd->bufsize = required_size;
+    g_free(ssd->buf);
+    ssd->buf = g_malloc(ssd->bufsize);
+    
+    surface.stride      = surface.width * 4;
+    surface.mouse_mode = true;
+    surface.flags      = 0;
+    surface.type       = 0;
+    surface.mem        = (uintptr_t)ssd->buf;
+    surface.group_id   = SPICE_SURFACE_GROUP_DEFAULT;
+
+    qxl_send_cmd(&ssd->qxl, QXL_CMD_SURFACE, (uintptr_t)&surface);
 }
-
-void qemu_spice_display_init_common(SimpleSpiceDisplay *ssd)
-{
-    qemu_mutex_init(&ssd->lock);
-    QTAILQ_INIT(&ssd->updates);
-    ssd->mouse_x = -1;
-    ssd->mouse_y = -1;
-    if (ssd->num_surfaces == 0) {
-        ssd->num_surfaces = 1024;
-    }
-    ssd->bufsize = (16 * 1024 * 1024);
-    ssd->buf = g_malloc(ssd->bufsize);
-}
-
-/* display listener callbacks */
-
-void qemu_spice_display_update(SimpleSpiceDisplay *ssd,
-                               int x, int y, int w, int h)
-{
-     if (ssd->num_surfaces == 0) {
-         ssd->num_surfaces = 1024;
-     }
-    ssd->bufsize = (16 * 1024 * 1024);
-    ssd->buf = g_malloc(ssd->bufsize);
- }
- 
- /* display listener callbacks */
-    update_area.top = y;
-    update_area.bottom = y + h;
-
-    if (qemu_spice_rect_is_empty(&ssd->dirty)) {
-        ssd->notify++;
-    }
-    qemu_spice_rect_union(&ssd->dirty, &update_area);
-}
```

## 36. CVE-2019-15903 (CWE-611) item=98

CVE: In libexpat before 2.2.8, crafted XML input could fool the parser into changing from DTD parsing to document parsing too early; a consecutive call to XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber) then resulted in a heap-based buffer over-read.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -20,5 +20,5 @@
          = XmlPrologTok(parser->m_internalEncoding, textStart, textEnd, &next);
      result = doProlog(parser, parser->m_internalEncoding, textStart, textEnd,
-                      tok, next, &next, XML_FALSE);
+                      tok, next, &next, XML_FALSE, XML_TRUE);
    } else
  #endif /* XML_DTD */
@@ -47,5 +47,5 @@
      tok = XmlPrologTok(parser->m_encoding, s, end, &next);
      return doProlog(parser, parser->m_encoding, s, end, tok, next, nextPtr,
-                    (XML_Bool)! parser->m_parsingStatus.finalBuffer);
+                    (XML_Bool)! parser->m_parsingStatus.finalBuffer, XML_TRUE);
    } else
  #endif /* XML_DTD */
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,2 +1,3 @@
+enum XML_Error
 internalEntityProcessor(XML_Parser parser, const char *s, const char *end,
                         const char **nextPtr) {
@@ -43,9 +44,5 @@
 #ifdef XML_DTD
   if (entity->is_param) {
-    int tok;
-     parser->m_processor = prologProcessor;
-     tok = XmlPrologTok(parser->m_encoding, s, end, &next);
-     return doProlog(parser, parser->m_encoding, s, end, tok, next, nextPtr,
-                    (XML_Bool)! parser->m_parsingStatus.finalBuffer);
+    return XML_ERROR_NONE;
    } else
  #endif /* XML_DTD */
```

## 37. CVE-2017-5850 (CWE-770) item=100

CVE: httpd in OpenBSD allows remote attackers to cause a denial of service (memory consumption) via a series of requests for a large file using an HTTP Range header.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,16 +1,20 @@
 parse_range(char *str, size_t file_sz, int *nranges)
+int
+parse_ranges(struct client *clt, char *str, size_t file_sz)
  {
-	static struct range	 ranges[MAX_RANGES];
  	int			 i = 0;
  	char			*p, *q;
+	struct range_data	*r = &clt->clt_ranges;
+
+	memset(r, 0, sizeof(*r));
  
  	/* Extract range unit */
  	if ((p = strchr(str, '=')) == NULL)
-		return (NULL);
+		return (-1);
  
  	*p++ = '\0';
  	/* Check if it's a bytes range spec */
  	if (strcmp(str, "bytes") != 0)
-		return (NULL);
+		return (-1);
  
  	while ((q = strchr(p, ',')) != NULL) {
@@ -18,18 +22,19 @@
  
  		/* Extract start and end positions */
-		if (parse_range_spec(p, file_sz, &ranges[i]) == 0)
+		if (parse_range_spec(p, file_sz, &r->range[i]) == 0)
  			continue;
  
  		i++;
-		if (i == MAX_RANGES)
-			return (NULL);
+		if (i == SERVER_MAX_RANGES)
+			return (-1);
  
  		p = q;
  	}
  
-	if (parse_range_spec(p, file_sz, &ranges[i]) != 0)
+	if (parse_range_spec(p, file_sz, &r->range[i]) != 0)
  		i++;
  
-	*nranges = i;
-	return (i ? ranges : NULL);
+	r->range_total = file_sz;
+	r->range_count = i;
+	return (i);
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,35 +1,37 @@
 parse_range(char *str, size_t file_sz, int *nranges)
- {
+{
 	static struct range	 ranges[MAX_RANGES];
- 	int			 i = 0;
- 	char			*p, *q;
- 
- 	/* Extract range unit */
- 	if ((p = strchr(str, '=')) == NULL)
+	int			 i = 0;
+	char			*p, *q;
+
+	/* Extract range unit */
+	if ((p = strchr(str, '=')) == NULL)
 		return (NULL);
- 
- 	*p++ = '\0';
- 	/* Check if it's a bytes range spec */
- 	if (strcmp(str, "bytes") != 0)
+
+	*p++ = '\0';
+	/* Check if it's a bytes range spec */
+	if (strcmp(str, "bytes") != 0)
 		return (NULL);
- 
- 	while ((q = strchr(p, ',')) != NULL) {
- 		*q++ = '\0';
- 
- 		/* Extract start and end positions */
-		if (parse_range_spec(p, file_sz, &ranges[i]) == 0)
- 			continue;
- 
- 		i++;
-		if (i == MAX_RANGES)
+
+	while ((q = strchr(p, ',')) != NULL) {
+		*q++ = '\0';
+
+		/* Extract start and end positions */
+		if (parse_range_spec(p, file_sz, &ranges[i]) == 0) {
+			p = q;
+			continue;
+		}
+
+		if (i >= MAX_RANGES - 1)
 			return (NULL);
- 
- 		p = q;
- 	}
- 
-	if (parse_range_spec(p, file_sz, &ranges[i]) != 0)
- 		i++;
- 
+
+		i++;
+		p = q;
+	}
+
+	if (i < MAX_RANGES && parse_range_spec(p, file_sz, &ranges[i]) != 0)
+		i++;
+
 	*nranges = i;
 	return (i ? ranges : NULL);
- }
+}
```

## 38. CVE-2016-2482 (CWE-119) item=102

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -22,5 +22,9 @@
      if (m_out_mem_ptr) {
          DEBUG_PRINT_LOW("Freeing the Output Memory");
-         for (i = 0; i < drv_ctx.op_buf.actualcount; i++ ) {
+         unsigned out_count = drv_ctx.op_buf.actualcount;
+         if (out_count > drv_ctx.op_buf.mincount) {
+             out_count = drv_ctx.op_buf.mincount;
+         }
+         for (i = 0; i < out_count; i++ ) {
             free_output_buffer (&m_out_mem_ptr[i]);
          }
@@ -34,5 +38,9 @@
      if (m_inp_mem_ptr || m_inp_heap_ptr) {
          DEBUG_PRINT_LOW("Freeing the Input Memory");
-         for (i = 0; i<drv_ctx.ip_buf.actualcount; i++ ) {
+         unsigned inp_count = drv_ctx.ip_buf.actualcount;
+         if (inp_count > drv_ctx.ip_buf.mincount) {
+             inp_count = drv_ctx.ip_buf.mincount;
+         }
+         for (i = 0; i < inp_count; i++ ) {
             if (m_inp_mem_ptr)
                 free_input_buffer (i,&m_inp_mem_ptr[i]);
```

## 39. CVE-2013-6624 (CWE-399) item=107

CVE: Use-after-free vulnerability in Google Chrome before 31.0.1650.48 allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors involving the string values of id attributes.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,7 +1,8 @@
 void HTMLDocument::addItemToMap(HashCountedSet<StringImpl*>& map, const AtomicString& name)
+void HTMLDocument::addItemToMap(HashCountedSet<AtomicString>& map, const AtomicString& name)
  {
      if (name.isEmpty())
          return;
-    map.add(name.impl());
+    map.add(name);
      if (Frame* f = frame())
          f->script()->namedItemAdded(this, name);
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,8 +1,10 @@
 void HTMLDocument::addItemToMap(HashCountedSet<StringImpl*>& map, const AtomicString& name)
- {
-     if (name.isEmpty())
-         return;
-    map.add(name.impl());
-     if (Frame* f = frame())
-         f->script()->namedItemAdded(this, name);
- }
+{
+    if (name.isEmpty())
+        return;
+    StringImpl* impl = name.impl();
+    impl->ref();
+    map.add(impl);
+    if (Frame* f = frame())
+        f->script()->namedItemAdded(this, name);
+}
```

## 40. CVE-2016-5357 (CWE-20) item=108

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,14 +1,15 @@
+gboolean
 netscreen_seek_read(wtap *wth, gint64 seek_off,
- 	struct wtap_pkthdr *phdr, Buffer *buf,
- 	int *err, gchar **err_info)
- {
+	struct wtap_pkthdr *phdr, Buffer *buf,
+	int *err, gchar **err_info)
+{
 	int		pkt_len;
- 	char		line[NETSCREEN_LINE_LENGTH];
+	char		line[NETSCREEN_LINE_LENGTH];
 	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
 	gboolean	cap_dir;
 	char		cap_dst[13];
- 
- 	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
- 		return FALSE;
+
+	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
+		return FALSE;
 	}
 
@@ -18,14 +19,26 @@
 			*err = WTAP_ERR_SHORT_READ;
 		}
- 		return FALSE;
- 	}
- 
+		return FALSE;
+	}
+
 	pkt_len = parse_netscreen_rec_hdr(phdr, line, cap_int, &cap_dir,
 	    cap_dst, err, err_info);
 	if (pkt_len == -1)
 		return FALSE;
+	if (pkt_len <= 0 || pkt_len > WTAP_MAX_PACKET_SIZE) {
+		*err = WTAP_ERR_BAD_FILE;
+		if (err_info != NULL)
+			*err_info = g_strdup("Invalid packet length");
+		return FALSE;
+	}
+	if (cap_int[0] == '\0' || cap_dst[0] == '\0') {
+		*err = WTAP_ERR_BAD_FILE;
+		if (err_info != NULL)
+			*err_info = g_strdup("Invalid capture interface or destination");
+		return FALSE;
+	}
 	if (!parse_netscreen_hex_dump(wth->random_fh, pkt_len, cap_int,
 	    cap_dst, phdr, buf, err, err_info))
 		return FALSE;
 	return TRUE;
- }
+}
```

## 41. CVE-2018-11380 (CWE-125) item=116

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

### Agent patch
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

## 42. CVE-2018-14879 (CWE-120) item=117

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,13 +1,15 @@
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
+char *
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

## 43. CVE-2012-4565 (CWE-189) item=119

CVE: The tcp_illinois_info function in net/ipv4/tcp_illinois.c in the Linux kernel before 3.4.19, when the net.ipv4.tcp_congestion_control illinois setting is enabled, allows local users to cause a denial of service (divide-by-zero error and OOPS) by reading TCP stats.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -10,9 +10,11 @@
  			.tcpv_minrtt = ca->base_rtt,
  		};
-		u64 t = ca->sum_rtt;
  
-		do_div(t, ca->cnt_rtt);
-		info.tcpv_rtt = t;
+		if (info.tcpv_rttcnt > 0) {
+			u64 t = ca->sum_rtt;
  
+			do_div(t, info.tcpv_rttcnt);
+			info.tcpv_rtt = t;
+		}
  		nla_put(skb, INET_DIAG_VEGASINFO, sizeof(info), &info);
  	}
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -7,13 +7,14 @@
 		struct tcpvegas_info info = {
 			.tcpv_enabled = 1,
- 			.tcpv_rttcnt = ca->cnt_rtt,
- 			.tcpv_minrtt = ca->base_rtt,
- 		};
+			.tcpv_rttcnt = ca->cnt_rtt,
+			.tcpv_minrtt = ca->base_rtt,
+		};
 		u64 t = ca->sum_rtt;
- 
-		do_div(t, ca->cnt_rtt);
-		info.tcpv_rtt = t;
- 
- 		nla_put(skb, INET_DIAG_VEGASINFO, sizeof(info), &info);
- 	}
- }
+
+		if (ca->cnt_rtt > 0) {
+			do_div(t, ca->cnt_rtt);
+			info.tcpv_rtt = t;
+			nla_put(skb, INET_DIAG_VEGASINFO, sizeof(info), &info);
+		}
+	}
+}
```

## 44. CVE-2012-5156 (CWE-399) item=124

CVE: Use-after-free vulnerability in Google Chrome before 24.0.1312.52 allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors involving PDF fields.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -2,5 +2,18 @@
    DCHECK(caller_task_runner_->BelongsToCurrentThread());
  
-  if (ipc_enabled_)
-    worker_delegate_->OnChannelConnected();
+  if (!ipc_enabled_)
+    return;
+
+  // Verify |peer_pid| because it is controlled by the client and cannot be
+  // trusted.
+  DWORD actual_pid = launcher_delegate_->GetProcessId();
+  if (peer_pid != static_cast<int32>(actual_pid)) {
+    LOG(ERROR) << "The actual client PID " << actual_pid
+               << " does not match the one reported by the client: "
+               << peer_pid;
+    StopWorker();
+    return;
+  }
+
+  worker_delegate_->OnChannelConnected(peer_pid);
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,6 +1,7 @@
- void WorkerProcessLauncher::Core::OnChannelConnected(int32 peer_pid) {
-   DCHECK(caller_task_runner_->BelongsToCurrentThread());
- 
-  if (ipc_enabled_)
-    worker_delegate_->OnChannelConnected();
- }
+void WorkerProcessLauncher::Core::OnChannelConnected(int32 peer_pid) {
+  DCHECK(caller_task_runner_->BelongsToCurrentThread());
+
+  WorkerProcessLauncher::Delegate* delegate = worker_delegate_;
+  if (ipc_enabled_ && delegate)
+    delegate->OnChannelConnected();
+}
```

## 45. CVE-2016-3921 (CWE-264) item=128

CVE: libsysutils/src/FrameworkListener.cpp in Framework Listener in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, 6.x before 2016-10-01, and 7.0 before 2016-10-01 allows attackers to gain privileges via a crafted application, aka internal bug 29831647.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -8,8 +8,13 @@
          SLOGE("read() failed (%s)", strerror(errno));
          return false;
-    } else if (!len)
+    } else if (!len) {
          return false;
-   if(buffer[len-1] != '\0')
+    } else if (buffer[len-1] != '\0') {
          SLOGW("String is not zero-terminated");
+        android_errorWriteLog(0x534e4554, "29831647");
+        c->sendMsg(500, "Command too large for buffer", false);
+        mSkipToNextNullByte = true;
+        return false;
+    }
  
      int offset = 0;
@@ -20,9 +25,14 @@
          if (buffer[i] == '\0') {
              /* IMPORTANT: dispatchCommand() expects a zero-terminated string */
-            dispatchCommand(c, buffer + offset);
+            if (mSkipToNextNullByte) {
+                mSkipToNextNullByte = false;
+            } else {
+                dispatchCommand(c, buffer + offset);
+            }
              offset = i + 1;
          }
      }
  
+    mSkipToNextNullByte = false;
      return true;
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,28 +1,34 @@
- bool FrameworkListener::onDataAvailable(SocketClient *c) {
- char buffer[CMD_BUF_SIZE];
- int len;
+bool FrameworkListener::onDataAvailable(SocketClient *c) {
+    char buffer[CMD_BUF_SIZE];
+    int len;
 
     len = TEMP_FAILURE_RETRY(read(c->getSocket(), buffer, sizeof(buffer)));
 
-     if (len < 0) {
-         SLOGE("read() failed (%s)", strerror(errno));
-         return false;
+    if (len < 0) {
+        SLOGE("read() failed (%s)", strerror(errno));
+        return false;
     } else if (!len)
-         return false;
-   if(buffer[len-1] != '\0')
-         SLOGW("String is not zero-terminated");
- 
-     int offset = 0;
-     int i;
+        return false;
+    
+    if (len >= CMD_BUF_SIZE) {
+        SLOGE("Command buffer overflow");
+        return false;
+    }
+    
+    if (buffer[len-1] != '\0') {
+        buffer[len] = '\0';
+    }
 
+    int offset = 0;
+    int i;
 
-     for (i = 0; i < len; i++) {
-         if (buffer[i] == '\0') {
-             /* IMPORTANT: dispatchCommand() expects a zero-terminated string */
+    for (i = 0; i < len; i++) {
+        if (buffer[i] == '\0') {
+            /* IMPORTANT: dispatchCommand() expects a zero-terminated string */
             dispatchCommand(c, buffer + offset);
-             offset = i + 1;
-         }
-     }
- 
-     return true;
- }
+            offset = i + 1;
+        }
+    }
+
+    return true;
+}
```

## 46. CVE-2017-5940 (CWE-269) item=129

CVE: Firejail before 0.9.44.6 and 0.9.38.x LTS before 0.9.38.10 LTS does not comprehensively address dotfile cases during its attempt to prevent accessing user files with an euid of zero, which allows local users to conduct sandbox-escape attacks via vectors involving a symlink and the --private option. NOTE: this vulnerability exists because of an incomplete fix for CVE-2017-5180.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -7,26 +7,15 @@
  		if (stat(fname, &s) == 0)
  			return;
+		if (is_link(fname)) { // stat on dangling symlinks fails, try again using lstat
+			fprintf(stderr, "Error: invalid %s file\n", fname);
+			exit(1);
+		}
  		if (stat("/etc/skel/.zshrc", &s) == 0) {
-			if (is_link("/etc/skel/.zshrc")) {
-				fprintf(stderr, "Error: invalid /etc/skel/.zshrc file\n");
-				exit(1);
-			}
-			if (copy_file("/etc/skel/.zshrc", fname) == 0) {
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				fs_logger("clone /etc/skel/.zshrc");
-			}
+			copy_file_as_user("/etc/skel/.zshrc", fname, u, g, 0644); // regular user
+			fs_logger("clone /etc/skel/.zshrc");
  		}
-		else { // 
-			FILE *fp = fopen(fname, "w");
-			if (fp) {
-				fprintf(fp, "\n");
-				fclose(fp);
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				if (chmod(fname, S_IRUSR | S_IWUSR) < 0)
-					errExit("chown");
-				fs_logger2("touch", fname);
-			}
+		else {
+			touch_file_as_user(fname, u, g, 0644);
+			fs_logger2("touch", fname);
  		}
  		free(fname);
@@ -38,27 +27,15 @@
  		if (stat(fname, &s) == 0)
  			return;
+		if (is_link(fname)) { // stat on dangling symlinks fails, try again using lstat
+			fprintf(stderr, "Error: invalid %s file\n", fname);
+			exit(1);
+		}
  		if (stat("/etc/skel/.cshrc", &s) == 0) {
-			if (is_link("/etc/skel/.cshrc")) {
-				fprintf(stderr, "Error: invalid /etc/skel/.cshrc file\n");
-				exit(1);
-			}
-			if (copy_file("/etc/skel/.cshrc", fname) == 0) {
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				fs_logger("clone /etc/skel/.cshrc");
-			}
+			copy_file_as_user("/etc/skel/.cshrc", fname, u, g, 0644); // regular user
+			fs_logger("clone /etc/skel/.cshrc");
  		}
-		else { // 
-			/* coverity[toctou] */
-			FILE *fp = fopen(fname, "w");
-			if (fp) {
-				fprintf(fp, "\n");
-				fclose(fp);
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				if (chmod(fname, S_IRUSR | S_IWUSR) < 0)
-					errExit("chown");
-				fs_logger2("touch", fname);
-			}
+		else {
+			touch_file_as_user(fname, u, g, 0644);
+			fs_logger2("touch", fname);
  		}
  		free(fname);
@@ -68,17 +45,13 @@
  			errExit("asprintf");
  		struct stat s;
-		if (stat(fname, &s) == 0)
+		if (stat(fname, &s) == 0) 
  			return;
+		if (is_link(fname)) { // stat on dangling symlinks fails, try again using lstat
+			fprintf(stderr, "Error: invalid %s file\n", fname);
+			exit(1);
+		}
  		if (stat("/etc/skel/.bashrc", &s) == 0) {
-			if (is_link("/etc/skel/.bashrc")) {
-				fprintf(stderr, "Error: invalid /etc/skel/.bashrc file\n");
-				exit(1);
-			}
-			if (copy_file("/etc/skel/.bashrc", fname) == 0) {
-				/* coverity[toctou] */
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				fs_logger("clone /etc/skel/.bashrc");
-			}
+			copy_file_as_user("/etc/skel/.bashrc", fname, u, g, 0644); // regular user
+			fs_logger("clone /etc/skel/.bashrc");
  		}
  		free(fname);
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -5,8 +5,14 @@
 			errExit("asprintf");
 		struct stat s;
- 		if (stat(fname, &s) == 0)
+ 		if (lstat(fname, &s) == 0) {
+ 			if (S_ISLNK(s.st_mode)) {
+ 				fprintf(stderr, "Error: invalid %s/.zshrc file\n", homedir);
+ 				exit(1);
+ 			}
+ 			free(fname);
  			return;
- 		if (stat("/etc/skel/.zshrc", &s) == 0) {
-			if (is_link("/etc/skel/.zshrc")) {
+ 		}
+ 		if (lstat("/etc/skel/.zshrc", &s) == 0) {
+			if (S_ISLNK(s.st_mode)) {
 				fprintf(stderr, "Error: invalid /etc/skel/.zshrc file\n");
 				exit(1);
@@ -18,14 +24,18 @@
 			}
  		}
-		else { // 
-			FILE *fp = fopen(fname, "w");
-			if (fp) {
-				fprintf(fp, "\n");
-				fclose(fp);
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				if (chmod(fname, S_IRUSR | S_IWUSR) < 0)
-					errExit("chown");
-				fs_logger2("touch", fname);
+		else {
+			int fd = open(fname, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
+			if (fd != -1) {
+				FILE *fp = fdopen(fd, "w");
+				if (fp) {
+					fprintf(fp, "\n");
+					fclose(fp);
+					if (chown(fname, u, g) == -1)
+						errExit("chown");
+					fs_logger2("touch", fname);
+				}
+				else {
+					close(fd);
+				}
 			}
  		}
@@ -36,8 +46,14 @@
 			errExit("asprintf");
 		struct stat s;
- 		if (stat(fname, &s) == 0)
+ 		if (lstat(fname, &s) == 0) {
+ 			if (S_ISLNK(s.st_mode)) {
+ 				fprintf(stderr, "Error: invalid %s/.cshrc file\n", homedir);
+ 				exit(1);
+ 			}
+ 			free(fname);
  			return;
- 		if (stat("/etc/skel/.cshrc", &s) == 0) {
-			if (is_link("/etc/skel/.cshrc")) {
+ 		}
+ 		if (lstat("/etc/skel/.cshrc", &s) == 0) {
+			if (S_ISLNK(s.st_mode)) {
 				fprintf(stderr, "Error: invalid /etc/skel/.cshrc file\n");
 				exit(1);
@@ -49,15 +65,18 @@
 			}
  		}
-		else { // 
-			/* coverity[toctou] */
-			FILE *fp = fopen(fname, "w");
-			if (fp) {
-				fprintf(fp, "\n");
-				fclose(fp);
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				if (chmod(fname, S_IRUSR | S_IWUSR) < 0)
-					errExit("chown");
-				fs_logger2("touch", fname);
+		else {
+			int fd = open(fname, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
+			if (fd != -1) {
+				FILE *fp = fdopen(fd, "w");
+				if (fp) {
+					fprintf(fp, "\n");
+					fclose(fp);
+					if (chown(fname, u, g) == -1)
+						errExit("chown");
+					fs_logger2("touch", fname);
+				}
+				else {
+					close(fd);
+				}
 			}
  		}
@@ -68,13 +87,18 @@
  			errExit("asprintf");
  		struct stat s;
-		if (stat(fname, &s) == 0)
+		if (lstat(fname, &s) == 0) {
+			if (S_ISLNK(s.st_mode)) {
+				fprintf(stderr, "Error: invalid %s/.bashrc file\n", homedir);
+				exit(1);
+			}
+ 			free(fname);
  			return;
- 		if (stat("/etc/skel/.bashrc", &s) == 0) {
-			if (is_link("/etc/skel/.bashrc")) {
+ 		}
+ 		if (lstat("/etc/skel/.bashrc", &s) == 0) {
+			if (S_ISLNK(s.st_mode)) {
 				fprintf(stderr, "Error: invalid /etc/skel/.bashrc file\n");
 				exit(1);
 			}
 			if (copy_file("/etc/skel/.bashrc", fname) == 0) {
-				/* coverity[toctou] */
 				if (chown(fname, u, g) == -1)
 					errExit("chown");
```

## 47. CVE-2016-10251 (CWE-190) item=135

CVE: Integer overflow in the jpc_pi_nextcprl function in jpc_t2cod.c in JasPer before 1.900.20 allows remote attackers to have unspecified impact via a crafted file, which triggers use of an uninitialized value.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -24,16 +24,16 @@
  	  ++pi->picomp) {
  		pirlvl = pi->picomp->pirlvls;
-		pi->xstep = pi->picomp->hsamp * (1 << (pirlvl->prcwidthexpn +
-		  pi->picomp->numrlvls - 1));
-		pi->ystep = pi->picomp->vsamp * (1 << (pirlvl->prcheightexpn +
-		  pi->picomp->numrlvls - 1));
+		pi->xstep = pi->picomp->hsamp * (JAS_CAST(uint_fast32_t, 1) <<
+		  (pirlvl->prcwidthexpn + pi->picomp->numrlvls - 1));
+		pi->ystep = pi->picomp->vsamp * (JAS_CAST(uint_fast32_t, 1) <<
+		  (pirlvl->prcheightexpn + pi->picomp->numrlvls - 1));
  		for (rlvlno = 1, pirlvl = &pi->picomp->pirlvls[1];
  		  rlvlno < pi->picomp->numrlvls; ++rlvlno, ++pirlvl) {
-			pi->xstep = JAS_MIN(pi->xstep, pi->picomp->hsamp * (1 <<
-			  (pirlvl->prcwidthexpn + pi->picomp->numrlvls -
-			  rlvlno - 1)));
-			pi->ystep = JAS_MIN(pi->ystep, pi->picomp->vsamp * (1 <<
-			  (pirlvl->prcheightexpn + pi->picomp->numrlvls -
-			  rlvlno - 1)));
+			pi->xstep = JAS_MIN(pi->xstep, pi->picomp->hsamp *
+			  (JAS_CAST(uint_fast32_t, 1) << (pirlvl->prcwidthexpn +
+			  pi->picomp->numrlvls - rlvlno - 1)));
+			pi->ystep = JAS_MIN(pi->ystep, pi->picomp->vsamp *
+			  (JAS_CAST(uint_fast32_t, 1) << (pirlvl->prcheightexpn +
+			  pi->picomp->numrlvls - rlvlno - 1)));
  		}
  		for (pi->y = pi->ystart; pi->y < pi->yend;
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -12,4 +12,5 @@
 	uint_fast32_t rpx;
 	uint_fast32_t rpy;
+	int shiftamount;
 
 	pchg = pi->pchg;
@@ -24,16 +25,26 @@
  	  ++pi->picomp) {
  		pirlvl = pi->picomp->pirlvls;
-		pi->xstep = pi->picomp->hsamp * (1 << (pirlvl->prcwidthexpn +
-		  pi->picomp->numrlvls - 1));
-		pi->ystep = pi->picomp->vsamp * (1 << (pirlvl->prcheightexpn +
-		  pi->picomp->numrlvls - 1));
+		shiftamount = pirlvl->prcwidthexpn + pi->picomp->numrlvls - 1;
+		if (shiftamount < 0 || shiftamount >= 31) {
+			return 1;
+		}
+		pi->xstep = pi->picomp->hsamp * (1 << shiftamount);
+		shiftamount = pirlvl->prcheightexpn + pi->picomp->numrlvls - 1;
+		if (shiftamount < 0 || shiftamount >= 31) {
+			return 1;
+		}
+		pi->ystep = pi->picomp->vsamp * (1 << shiftamount);
  		for (rlvlno = 1, pirlvl = &pi->picomp->pirlvls[1];
  		  rlvlno < pi->picomp->numrlvls; ++rlvlno, ++pirlvl) {
-			pi->xstep = JAS_MIN(pi->xstep, pi->picomp->hsamp * (1 <<
-			  (pirlvl->prcwidthexpn + pi->picomp->numrlvls -
-			  rlvlno - 1)));
-			pi->ystep = JAS_MIN(pi->ystep, pi->picomp->vsamp * (1 <<
-			  (pirlvl->prcheightexpn + pi->picomp->numrlvls -
-			  rlvlno - 1)));
+			shiftamount = pirlvl->prcwidthexpn + pi->picomp->numrlvls - rlvlno - 1;
+			if (shiftamount < 0 || shiftamount >= 31) {
+				return 1;
+			}
+			pi->xstep = JAS_MIN(pi->xstep, pi->picomp->hsamp * (1 << shiftamount));
+			shiftamount = pirlvl->prcheightexpn + pi->picomp->numrlvls - rlvlno - 1;
+			if (shiftamount < 0 || shiftamount >= 31) {
+				return 1;
+			}
+			pi->ystep = JAS_MIN(pi->ystep, pi->picomp->vsamp * (1 << shiftamount));
  		}
  		for (pi->y = pi->ystart; pi->y < pi->yend;
@@ -53,4 +64,7 @@
 					rpx = r + pi->pirlvl->prcwidthexpn;
 					rpy = r + pi->pirlvl->prcheightexpn;
+					if (rpx >= 31 || rpy >= 31) {
+						continue;
+					}
 					if (((pi->x == pi->xstart && ((trx0 << r) % (1 << rpx))) ||
 					  !(pi->x % (pi->picomp->hsamp << rpx))) &&
```

## 48. CVE-2013-0911 (CWE-22) item=137

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -4,4 +4,11 @@
                                               int64 estimated_size) {
    DCHECK(BrowserThread::CurrentlyOn(BrowserThread::FILE));
+   
+   // Validate origin_identifier and database_name to prevent directory traversal
+   if (origin_identifier.find(FILE_PATH_LITERAL("..")) != string16::npos ||
+       database_name.find(FILE_PATH_LITERAL("..")) != string16::npos) {
+     return;
+   }
+   
    int64 database_size = 0;
    db_tracker_->DatabaseOpened(origin_identifier, database_name, description,
```

## 49. CVE-2013-0839 (CWE-399) item=141

CVE: Use-after-free vulnerability in Google Chrome before 24.0.1312.56 allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors related to the handling of fonts in CANVAS elements.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,27 +1,8 @@
 GDataEntry* GDataDirectory::FromDocumentEntry(
-    GDataDirectory* parent,
-    DocumentEntry* doc,
-    GDataDirectoryService* directory_service) {
-  DCHECK(doc->is_folder());
-  GDataDirectory* dir = new GDataDirectory(parent, directory_service);
-  dir->title_ = UTF16ToUTF8(doc->title());
-  dir->SetBaseNameFromTitle();
-  dir->file_info_.last_modified = doc->updated_time();
-  dir->file_info_.last_accessed = doc->updated_time();
-  dir->file_info_.creation_time = doc->published_time();
-  dir->resource_id_ = doc->resource_id();
-  dir->content_url_ = doc->content_url();
-  dir->deleted_ = doc->deleted();
-  const Link* edit_link = doc->GetLinkByType(Link::EDIT);
-  DCHECK(edit_link) << "No edit link for dir " << dir->title_;
-  if (edit_link)
-    dir->edit_url_ = edit_link->href();
-  const Link* parent_link = doc->GetLinkByType(Link::PARENT);
-  if (parent_link)
-    dir->parent_resource_id_ = ExtractResourceId(parent_link->href());
+void GDataDirectory::InitFromDocumentEntry(DocumentEntry* doc) {
+  GDataEntry::InitFromDocumentEntry(doc);
  
    const Link* upload_link = doc->GetLinkByType(Link::RESUMABLE_CREATE_MEDIA);
    if (upload_link)
-    dir->upload_url_ = upload_link->href();
-  return dir;
+    upload_url_ = upload_link->href();
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -3,5 +3,7 @@
     DocumentEntry* doc,
     GDataDirectoryService* directory_service) {
-  DCHECK(doc->is_folder());
+  if (!doc || !doc->is_folder())
+    return NULL;
+  
   GDataDirectory* dir = new GDataDirectory(parent, directory_service);
   dir->title_ = UTF16ToUTF8(doc->title());
@@ -13,15 +15,20 @@
   dir->content_url_ = doc->content_url();
   dir->deleted_ = doc->deleted();
+  
   const Link* edit_link = doc->GetLinkByType(Link::EDIT);
-  DCHECK(edit_link) << "No edit link for dir " << dir->title_;
-  if (edit_link)
-    dir->edit_url_ = edit_link->href();
+  if (!edit_link) {
+    delete dir;
+    return NULL;
+  }
+  dir->edit_url_ = edit_link->href();
+  
   const Link* parent_link = doc->GetLinkByType(Link::PARENT);
   if (parent_link)
     dir->parent_resource_id_ = ExtractResourceId(parent_link->href());
  
-   const Link* upload_link = doc->GetLinkByType(Link::RESUMABLE_CREATE_MEDIA);
-   if (upload_link)
+  const Link* upload_link = doc->GetLinkByType(Link::RESUMABLE_CREATE_MEDIA);
+  if (upload_link)
     dir->upload_url_ = upload_link->href();
+  
   return dir;
- }
+}
```

## 50. CVE-2016-3920 (CWE-20) item=147

CVE: id3/ID3.cpp in libstagefright in mediaserver in Android 5.0.x before 5.0.2, 5.1.x before 5.1.1, 6.x before 2016-10-01, and 7.0 before 2016-10-01 allows remote attackers to cause a denial of service (device hang or reboot) via a crafted file, aka internal bug 30744884.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -38,4 +38,8 @@
      }
  
+    if (n <= 0) {
+       return;
+    }
+
      if (encoding == 0x00) {
          id->setTo((const char*)frameData + 1, n);
@@ -48,9 +52,14 @@
          char16_t *framedatacopy = NULL;
  #if BYTE_ORDER == LITTLE_ENDIAN
-        framedatacopy = new char16_t[len];
-        for (int i = 0; i < len; i++) {
-            framedatacopy[i] = bswap_16(framedata[i]);
+        if (len > 0) {
+            framedatacopy = new (std::nothrow) char16_t[len];
+            if (framedatacopy == NULL) {
+                return;
+            }
+            for (int i = 0; i < len; i++) {
+                framedatacopy[i] = bswap_16(framedata[i]);
+            }
+            framedata = framedatacopy;
          }
-        framedata = framedatacopy;
  #endif
          id->setTo(framedata, len);
@@ -64,11 +73,24 @@
          char16_t *framedatacopy = NULL;
          if (*framedata == 0xfffe) {
-            framedatacopy = new char16_t[len];
+            // endianness marker != host endianness, convert & skip
+            if (len <= 1) {
+                return;         // nothing after the marker
+            }
+            framedatacopy = new (std::nothrow) char16_t[len];
+            if (framedatacopy == NULL) {
+                return;
+            }
              for (int i = 0; i < len; i++) {
                  framedatacopy[i] = bswap_16(framedata[i]);
              }
              framedata = framedatacopy;
-        }
-        if (*framedata == 0xfeff) {
+            // and skip over the marker
+            framedata++;
+            len--;
+        } else if (*framedata == 0xfeff) {
+            // endianness marker == host endianness, skip it
+            if (len <= 1) {
+                return;         // nothing after the marker
+            }
              framedata++;
              len--;
@@ -84,10 +106,14 @@
          }
          if (eightBit) {
-            char *frame8 = new char[len];
-            for (int i = 0; i < len; i++) {
-                frame8[i] = framedata[i];
+            char *frame8 = new (std::nothrow) char[len];
+            if (frame8 != NULL) {
+                for (int i = 0; i < len; i++) {
+                    frame8[i] = framedata[i];
+                }
+                id->setTo(frame8, len);
+                delete [] frame8;
+            } else {
+                id->setTo(framedata, len);
              }
-            id->setTo(frame8, len);
-            delete [] frame8;
          } else {
              id->setTo(framedata, len);
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -2,99 +2,105 @@
     id->setTo("");
 
- const uint8_t *frameData = mFrameData;
- if (frameData == NULL) {
- return;
- }
+    const uint8_t *frameData = mFrameData;
+    if (frameData == NULL) {
+        return;
+    }
 
- uint8_t encoding = *frameData;
+    uint8_t encoding = *frameData;
 
- if (mParent.mVersion == ID3_V1 || mParent.mVersion == ID3_V1_1) {
- if (mOffset == 126 || mOffset == 127) {
- char tmp[16];
+    if (mParent.mVersion == ID3_V1 || mParent.mVersion == ID3_V1_1) {
+        if (mOffset == 126 || mOffset == 127) {
+            char tmp[16];
             sprintf(tmp, "%d", (int)*frameData);
 
             id->setTo(tmp);
- return;
- }
+            return;
+        }
 
         id->setTo((const char*)frameData, mFrameSize);
- return;
- }
+        return;
+    }
 
- if (mFrameSize < getHeaderLength() + 1) {
- return;
- }
- size_t n = mFrameSize - getHeaderLength() - 1;
- if (otherdata) {
+    size_t headerLen = getHeaderLength();
+    if (mFrameSize <= headerLen + 1) {
+        return;
+    }
+    size_t n = mFrameSize - headerLen - 1;
+    if (otherdata) {
+        if (n < 4) {
+            return;
+        }
         frameData += 4;
- int32_t i = n - 4;
- while(--i >= 0 && *++frameData != 0) ;
- int skipped = (frameData - mFrameData);
- if (skipped >= (int)n) {
- return;
- }
+        int32_t i = n - 4;
+        while(--i >= 0 && *++frameData != 0) ;
+        int skipped = (frameData - mFrameData);
+        if (skipped >= (int)mFrameSize) {
+            return;
+        }
 
-         n -= skipped;
-     }
- 
-     if (encoding == 0x00) {
-         id->setTo((const char*)frameData + 1, n);
- } else if (encoding == 0x03) {
+        n = mFrameSize - skipped - 1;
+        if ((int)n <= 0) {
+            return;
+        }
+    }
+
+    if (encoding == 0x00) {
+        id->setTo((const char*)frameData + 1, n);
+    } else if (encoding == 0x03) {
         id->setTo((const char *)(frameData + 1), n);
- } else if (encoding == 0x02) {
- int len = n / 2;
+    } else if (encoding == 0x02) {
+        int len = n / 2;
 
-         const char16_t *framedata = (const char16_t *) (frameData + 1);
-         char16_t *framedatacopy = NULL;
- #if BYTE_ORDER == LITTLE_ENDIAN
+        const char16_t *framedata = (const char16_t *) (frameData + 1);
+        char16_t *framedatacopy = NULL;
+#if BYTE_ORDER == LITTLE_ENDIAN
         framedatacopy = new char16_t[len];
         for (int i = 0; i < len; i++) {
             framedatacopy[i] = bswap_16(framedata[i]);
-         }
+        }
         framedata = framedatacopy;
- #endif
-         id->setTo(framedata, len);
-         if (framedatacopy != NULL) {
- delete[] framedatacopy;
- }
- } else if (encoding == 0x01) {
- int len = n / 2;
+#endif
+        id->setTo(framedata, len);
+        if (framedatacopy != NULL) {
+            delete[] framedatacopy;
+        }
+    } else if (encoding == 0x01) {
+        int len = n / 2;
 
-         const char16_t *framedata = (const char16_t *) (frameData + 1);
-         char16_t *framedatacopy = NULL;
-         if (*framedata == 0xfffe) {
+        const char16_t *framedata = (const char16_t *) (frameData + 1);
+        char16_t *framedatacopy = NULL;
+        if (len > 0 && *framedata == 0xfffe) {
             framedatacopy = new char16_t[len];
-             for (int i = 0; i < len; i++) {
-                 framedatacopy[i] = bswap_16(framedata[i]);
-             }
-             framedata = framedatacopy;
+            for (int i = 0; i < len; i++) {
+                framedatacopy[i] = bswap_16(framedata[i]);
+            }
+            framedata = framedatacopy;
         }
-        if (*framedata == 0xfeff) {
-             framedata++;
-             len--;
-         }
+        if (len > 0 && *framedata == 0xfeff) {
+            framedata++;
+            len--;
+        }
 
- bool eightBit = true;
- for (int i = 0; i < len; i++) {
- if (framedata[i] > 0xff) {
+        bool eightBit = true;
+        for (int i = 0; i < len; i++) {
+            if (framedata[i] > 0xff) {
                 eightBit = false;
- break;
- }
-
-         }
-         if (eightBit) {
+                break;
+            }
+        }
+        if (eightBit) {
             char *frame8 = new char[len];
             for (int i = 0; i < len; i++) {
                 frame8[i] = framedata[i];
-             }
+            }
             id->setTo(frame8, len);
             delete [] frame8;
-         } else {
-             id->setTo(framedata, len);
-         }
+        } else {
+            id->setTo(framedata, len);
+        }
 
- if (framedatacopy != NULL) {
- delete[] framedatacopy;
- }
- }
+        if (framedatacopy != NULL) {
+            delete[] framedatacopy;
+        }
+    }
 }
```
