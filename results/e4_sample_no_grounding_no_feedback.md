# E4 sample: 41 of 41 touch-but-rejected no_grounding_no_feedback patches (repeat 1)

## 1. CVE-2014-4502 (CWE-119) item=7

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

### Agent patch
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

## 2. CVE-2014-4611 (CWE-20) item=8

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
@@ -22,6 +22,9 @@
 
  			len = *ip++;
- 			for (; len == 255; length += 255)
+ 			for (; len == 255; length += 255) {
  				len = *ip++;
+ 				if (unlikely(length > osize))
+ 					goto _output_error;
+ 			}
  			length += len;
  		}
@@ -56,6 +59,9 @@
 		length = token & ML_MASK;
 		if (length == ML_MASK) {
-			for (; *ip == 255; length += 255)
+			for (; *ip == 255; length += 255) {
 				ip++;
+				if (unlikely(length > osize))
+					goto _output_error;
+			}
 			length += *ip++;
 		}
```

## 3. CVE-2018-18349 (CWE-732) item=16

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
@@ -3,4 +3,7 @@
                                       WebFrameLoadType frame_load_type,
                                       UserGestureStatus user_gesture_status) {
+   if (!url.IsValid()) {
+     return;
+   }
    FrameLoadRequest frame_request(&origin_document, ResourceRequest(url));
    frame_request.GetResourceRequest().SetHasUserGesture(
```

## 4. CVE-2016-7166 (CWE-399) item=18

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,24 +1,20 @@
- choose_filters(struct archive_read *a)
- {
-	int number_bidders, i, bid, best_bid;
- 	struct archive_read_filter_bidder *bidder, *best_bidder;
- 	struct archive_read_filter *filter;
- 	ssize_t avail;
- 	int r;
- 
+choose_filters(struct archive_read *a)
+{
+	int i, bid, best_bid;
+	struct archive_read_filter_bidder *bidder, *best_bidder;
+	struct archive_read_filter *filter;
+	ssize_t avail;
+	int r;
+
 	for (;;) {
- 		number_bidders = sizeof(a->bidders) / sizeof(a->bidders[0]);
- 
- 		best_bid = 0;
+		best_bid = 0;
 		best_bidder = NULL;
 
 		bidder = a->bidders;
-		for (i = 0; i < number_bidders; i++, bidder++) {
-			if (bidder->bid != NULL) {
-				bid = (bidder->bid)(bidder, a->filter);
-				if (bid > best_bid) {
-					best_bid = bid;
-					best_bidder = bidder;
-				}
+		for (i = 0; bidder->bid != NULL; i++, bidder++) {
+			bid = (bidder->bid)(bidder, a->filter);
+			if (bid > best_bid) {
+				best_bid = bid;
+				best_bidder = bidder;
 			}
 		}
@@ -50,6 +46,6 @@
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
@@ -7,6 +7,11 @@
     {
         const char* p = strrchr(dpy, ':');
-        host = g_strndup(dpy, (p - dpy));
-        dpynum = atoi(p + 1);
+        if(p)
+        {
+            host = g_strndup(dpy, (p - dpy));
+            dpynum = atoi(p + 1);
+        }
+        else
+            dpynum = 0;
      }
      else
@@ -18,3 +23,4 @@
                  dpynum,
                  g_get_user_name());
+     g_free(host);
  }
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
@@ -3,5 +3,5 @@
 {
   unsigned char *p, *name, c, *fe, sep, slash;
-  unsigned int x;
+  unsigned int x, total_len;
   sep   = (isunix) ? '/'  : '\\'; /* the path-seperator */
   slash = (isunix) ? '\\' : '/';  /* the other slash */
@@ -11,6 +11,7 @@
   if (utf8) x *= 3;
   /* length of output directory */
-  if (dir) x += strlen((char *) dir);
-  if (!(name = (unsigned char *) malloc(x + 2))) {
+  total_len = x;
+  if (dir) total_len += strlen((char *) dir) + 1; /* +1 for separator */
+  if (!(name = (unsigned char *) malloc(total_len + 1))) {
     fprintf(stderr, "out of memory!\n");
     return NULL;
@@ -94,3 +95,3 @@
   }
   return (char *) name;
- }
+}
```

## 8. CVE-2018-6651 (CWE-352) item=25

CVE: In the uncurl_ws_accept function in uncurl.c in uncurl before 0.07, as used in Parsec before 140-3, insufficient Origin header validation (accepting an arbitrary substring match) for WebSocket API requests allows remote attackers to bypass intended access restrictions. In Parsec, this means full control over the victim's computer.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -13,7 +13,10 @@
  	if (e != UNCURL_OK) return e;
  
+	//the substring MUST came at the end of the origin header, thus a strstr AND a strcmp
  	bool origin_ok = false;
-	for (int32_t x = 0; x < n_origins; x++)
-		if (strstr(origin, origins[x])) {origin_ok = true; break;}
+	for (int32_t x = 0; x < n_origins; x++) {
+		char *match = strstr(origin, origins[x]);
+		if (match && !strcmp(match, origins[x])) {origin_ok = true; break;}
+	}
  
  	if (!origin_ok) return UNCURL_WS_ERR_ORIGIN;
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -15,5 +15,5 @@
  	bool origin_ok = false;
 	for (int32_t x = 0; x < n_origins; x++)
-		if (strstr(origin, origins[x])) {origin_ok = true; break;}
+		if (origin != NULL && origins[x] != NULL && strcmp(origin, origins[x]) == 0) {origin_ok = true; break;}
  
  	if (!origin_ok) return UNCURL_WS_ERR_ORIGIN;
```

## 9. CVE-2018-16066 (CWE-416) item=28

CVE: A use after free in Blink in Google Chrome prior to 69.0.3497.81 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -2,4 +2,11 @@
      ContainerNode* insertion_point) {
    HTMLElement::InsertedInto(insertion_point);
-  return kInsertionShouldCallDidNotifySubtreeInsertions;
+  if (isConnected()) {
+    if (StyleElement::ProcessStyleSheet(GetDocument(), *this) ==
+        StyleElement::kProcessingFatalError) {
+      NotifyLoadedSheetAndAllCriticalSubresources(
+          kErrorOccurredLoadingSubresource);
+    }
+  }
+  return kInsertionDone;
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,5 +1,5 @@
- Node::InsertionNotificationRequest HTMLStyleElement::InsertedInto(
-     ContainerNode* insertion_point) {
-   HTMLElement::InsertedInto(insertion_point);
-  return kInsertionShouldCallDidNotifySubtreeInsertions;
- }
+Node::InsertionNotificationRequest HTMLStyleElement::InsertedInto(
+    ContainerNode* insertion_point) {
+  Node::InsertionNotificationRequest result = HTMLElement::InsertedInto(insertion_point);
+  return result | kInsertionShouldCallDidNotifySubtreeInsertions;
+}
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
+	bitmap_zero(ioapic->rtc_status.dest_map.map, ioapic->rtc_status.dest_map.len);
+}
```

## 11. CVE-2019-15163 (CWE-476) item=47

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
+	crypt_result = (char *) crypt(password, user_password);
+	if (crypt_result == NULL || strcmp(user_password, crypt_result) != 0)
  	{
  		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: user name or password incorrect");
```

## 12. CVE-2017-13010 (CWE-125) item=48

CVE: The BEEP parser in tcpdump before 4.9.2 has a buffer over-read in print-beep.c:l_strnstart().

### Official fix
```diff
--- vulnerable
+++ patched
@@ -2,17 +2,17 @@
  {
  
-	if (l_strnstart("MSG", 4, (const char *)bp, length)) /* A REQuest */
+	if (l_strnstart(ndo, "MSG", 4, (const char *)bp, length)) /* A REQuest */
  		ND_PRINT((ndo, " BEEP MSG"));
-	else if (l_strnstart("RPY ", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "RPY ", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP RPY"));
-	else if (l_strnstart("ERR ", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "ERR ", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP ERR"));
-	else if (l_strnstart("ANS ", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "ANS ", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP ANS"));
-	else if (l_strnstart("NUL ", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "NUL ", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP NUL"));
-	else if (l_strnstart("SEQ ", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "SEQ ", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP SEQ"));
-	else if (l_strnstart("END", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "END", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP END"));
  	else
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,20 +1,23 @@
- beep_print(netdissect_options *ndo, const u_char *bp, u_int length)
- {
- 
-	if (l_strnstart("MSG", 4, (const char *)bp, length)) /* A REQuest */
- 		ND_PRINT((ndo, " BEEP MSG"));
-	else if (l_strnstart("RPY ", 4, (const char *)bp, length))
- 		ND_PRINT((ndo, " BEEP RPY"));
-	else if (l_strnstart("ERR ", 4, (const char *)bp, length))
- 		ND_PRINT((ndo, " BEEP ERR"));
-	else if (l_strnstart("ANS ", 4, (const char *)bp, length))
- 		ND_PRINT((ndo, " BEEP ANS"));
-	else if (l_strnstart("NUL ", 4, (const char *)bp, length))
- 		ND_PRINT((ndo, " BEEP NUL"));
-	else if (l_strnstart("SEQ ", 4, (const char *)bp, length))
- 		ND_PRINT((ndo, " BEEP SEQ"));
-	else if (l_strnstart("END", 4, (const char *)bp, length))
- 		ND_PRINT((ndo, " BEEP END"));
- 	else
- 		ND_PRINT((ndo, " BEEP (payload or undecoded)"));
+void
+beep_print(netdissect_options *ndo, const u_char *bp, u_int length)
+{
+	if (length < 3)
+		return;
+
+	if (l_strnstart("MSG", 3, (const char *)bp, length)) /* A REQuest */
+		ND_PRINT((ndo, " BEEP MSG"));
+	else if (length >= 4 && l_strnstart("RPY ", 4, (const char *)bp, length))
+		ND_PRINT((ndo, " BEEP RPY"));
+	else if (length >= 4 && l_strnstart("ERR ", 4, (const char *)bp, length))
+		ND_PRINT((ndo, " BEEP ERR"));
+	else if (length >= 4 && l_strnstart("ANS ", 4, (const char *)bp, length))
+		ND_PRINT((ndo, " BEEP ANS"));
+	else if (length >= 4 && l_strnstart("NUL ", 4, (const char *)bp, length))
+		ND_PRINT((ndo, " BEEP NUL"));
+	else if (length >= 4 && l_strnstart("SEQ ", 4, (const char *)bp, length))
+		ND_PRINT((ndo, " BEEP SEQ"));
+	else if (l_strnstart("END", 3, (const char *)bp, length))
+		ND_PRINT((ndo, " BEEP END"));
+	else
+		ND_PRINT((ndo, " BEEP (payload or undecoded)"));
 }
```

## 13. CVE-2018-12232 (CWE-362) item=50

CVE: In net/socket.c in the Linux kernel through 4.17.1, there is a race condition between fchownat and close in cases where they target the same socket file descriptor, related to the sock_close and sockfs_setattr functions. fchownat does not increment the file descriptor reference count, which allows close to set the socket to NULL during fchownat's execution, leading to a NULL pointer dereference an

### Official fix
```diff
--- vulnerable
+++ patched
@@ -1,5 +1,5 @@
  static int sock_close(struct inode *inode, struct file *filp)
  {
-	sock_release(SOCKET_I(inode));
+	__sock_release(SOCKET_I(inode), inode);
  	return 0;
  }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,5 +1,7 @@
- static int sock_close(struct inode *inode, struct file *filp)
- {
-	sock_release(SOCKET_I(inode));
- 	return 0;
- }
+static int sock_close(struct inode *inode, struct file *filp)
+{
+	struct socket *sock = SOCKET_I(inode);
+	if (sock)
+		sock_release(sock);
+	return 0;
+}
```

## 14. CVE-2011-1180 (CWE-119) item=60

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

### Agent patch
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

## 15. CVE-2015-8953 (CWE-399) item=61

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

## 16. CVE-2018-7648 (CWE-119) item=63

CVE: An issue was discovered in mj2/opj_mj2_extract.c in OpenJPEG 2.3.0. The output prefix was not checked for length, which could overflow a buffer, when providing a prefix with 50 or more characters on the command line.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -68,5 +68,10 @@
                file); /* Assuming that jp and ftyp markers size do*/
  
-        sprintf(outfilename, "%s_%05d.j2k", argv[2], snum);
+        int num = snprintf(outfilename, sizeof(outfilename), "%s_%05d.j2k", argv[2], snum);
+        if (num >= sizeof(outfilename)) {
+            fprintf(stderr, "maximum length of output prefix exceeded\n");
+            return 1;
+        }
+
          outfile = fopen(outfilename, "wb");
          if (!outfile) {
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -68,5 +68,5 @@
                file); /* Assuming that jp and ftyp markers size do*/
  
-        sprintf(outfilename, "%s_%05d.j2k", argv[2], snum);
+        snprintf(outfilename, sizeof(outfilename), "%s_%05d.j2k", argv[2], snum);
          outfile = fopen(outfilename, "wb");
          if (!outfile) {
```

## 17. CVE-2019-5759 (CWE-416) item=65

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
@@ -1,3 +1,3 @@
- void RenderFrameImpl::OnSelectPopupMenuItems(
+void RenderFrameImpl::OnSelectPopupMenuItems(
     bool canceled,
     const std::vector<int>& selected_indices) {
@@ -5,6 +5,6 @@
      return;
  
-   blink::WebScopedUserGesture gesture(frame_);
-  external_popup_menu_->DidSelectItems(canceled, selected_indices);
-  external_popup_menu_.reset();
- }
+  auto popup_menu = std::move(external_popup_menu_);
+  blink::WebScopedUserGesture gesture(frame_);
+  popup_menu->DidSelectItems(canceled, selected_indices);
+}
```

## 18. CVE-2016-7126 (CWE-787) item=67

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
+		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Number of colors must be between 1 and 256");
  		RETURN_FALSE;
  	}
```

## 19. CVE-2013-4270 (CWE-20) item=70

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
@@ -8,10 +8,10 @@
  	/* Allow network administrator to have same access as root. */
  	if (ns_capable(net->user_ns, CAP_NET_ADMIN) ||
-	    uid_eq(root_uid, current_uid())) {
+	    (uid_valid(root_uid) && uid_eq(root_uid, current_euid()))) {
  		int mode = (table->mode >> 6) & 7;
  		return (mode << 6) | (mode << 3) | mode;
  	}
  	/* Allow netns root group to have the same access as the root group */
-	if (gid_eq(root_gid, current_gid())) {
+	if (gid_valid(root_gid) && gid_eq(root_gid, current_egid())) {
  		int mode = (table->mode >> 3) & 7;
  		return (mode << 3) | mode;
```

## 20. CVE-2012-6538 (CWE-200) item=72

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

## 21. CVE-2017-5552 (CWE-772) item=76

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

## 22. CVE-2017-16526 (CWE-119) item=80

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -1,9 +1,10 @@
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
+	} else
+		rc->uwbd.pid = rc->uwbd.task->pid;
+}
```

## 23. CVE-2017-13198 (CWE-20) item=82

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

## 24. CVE-2019-12111 (CWE-476) item=90

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
+	if(dest != src && dest != NULL && src != NULL) {
+		memcpy(dest, src, sizeof(struct in6_addr));
+	}
+}
```

## 25. CVE-2013-0925 (CWE-264) item=92

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
@@ -4,8 +4,8 @@
      int tab_index,
      const Extension* extension) {
-  bool has_permission = extension && extension->HasAPIPermissionForTab(
+  bool has_permission = extension && contents && extension->HasAPIPermissionForTab(
       GetTabId(contents), APIPermission::kTab);
   return CreateTabValue(contents, tab_strip, tab_index,
                         has_permission ? INCLUDE_PRIVACY_SENSITIVE_FIELDS :
                             OMIT_PRIVACY_SENSITIVE_FIELDS);
- }
+}
```

## 26. CVE-2016-6561 (CWE-476) item=95

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
@@ -26,9 +26,11 @@
 	status = smb2sr_lookup_fid(sr, &smb2fid);
 	if (status) {
- 		smb2sr_put_error(sr, status);
- 		return (SDRC_SUCCESS);
- 	}
+		smb2sr_put_error(sr, status);
+		return (SDRC_SUCCESS);
+	}
 	of = sr->fid_ofile;
- 
+	if (of == NULL)
+		return (SDRC_ERROR);
+
 	/*
 	 * XXX - todo:
@@ -37,7 +39,7 @@
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

## 27. CVE-2014-3615 (CWE-200) item=97

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
@@ -1,17 +1,21 @@
- void qemu_spice_create_host_primary(SimpleSpiceDisplay *ssd)
- {
-     QXLDevSurfaceCreate surface;
- 
-     memset(&surface, 0, sizeof(surface));
- 
+void qemu_spice_create_host_primary(SimpleSpiceDisplay *ssd)
+{
+    QXLDevSurfaceCreate surface;
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
+    surface.stride     = surface_stride(ssd->ds);
+    surface.mouse_mode = 0;
+    surface.flags      = 0;
+    surface.type       = 0;
+    surface.mem        = (uintptr_t)&ssd->buf;
+
+    qemu_spice_create_primary_surface(ssd, 0, &surface, QXL_SYNC);
 }
 
@@ -29,17 +33,11 @@
 }
 
-/* display listener callbacks */
-
 void qemu_spice_display_update(SimpleSpiceDisplay *ssd,
                                int x, int y, int w, int h)
 {
-     if (ssd->num_surfaces == 0) {
-         ssd->num_surfaces = 1024;
-     }
-    ssd->bufsize = (16 * 1024 * 1024);
-    ssd->buf = g_malloc(ssd->bufsize);
- }
- 
- /* display listener callbacks */
+    QXLRect update_area;
+
+    update_area.left = x;
+    update_area.right = x + w;
     update_area.top = y;
     update_area.bottom = y + h;
```

## 28. CVE-2017-5850 (CWE-770) item=100

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
@@ -4,13 +4,23 @@
  	int			 i = 0;
  	char			*p, *q;
+	char			*str_copy;
+ 
+	/* Make a copy to avoid modifying the original string */
+	str_copy = strdup(str);
+	if (str_copy == NULL)
+		return (NULL);
  
  	/* Extract range unit */
- 	if ((p = strchr(str, '=')) == NULL)
+ 	if ((p = strchr(str_copy, '=')) == NULL) {
+		free(str_copy);
 		return (NULL);
+	}
  
  	*p++ = '\0';
  	/* Check if it's a bytes range spec */
- 	if (strcmp(str, "bytes") != 0)
+ 	if (strcmp(str_copy, "bytes") != 0) {
+		free(str_copy);
 		return (NULL);
+	}
  
  	while ((q = strchr(p, ',')) != NULL) {
@@ -18,10 +28,14 @@
  
  		/* Extract start and end positions */
-		if (parse_range_spec(p, file_sz, &ranges[i]) == 0)
- 			continue;
+		if (parse_range_spec(p, file_sz, &ranges[i]) == 0) {
+ 			p = q;
+			continue;
+		}
  
  		i++;
-		if (i == MAX_RANGES)
+		if (i == MAX_RANGES) {
+			free(str_copy);
 			return (NULL);
+		}
  
  		p = q;
@@ -32,4 +46,5 @@
  
 	*nranges = i;
+	free(str_copy);
 	return (i ? ranges : NULL);
  }
```

## 29. CVE-2016-2482 (CWE-119) item=102

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
@@ -28,4 +28,6 @@
          memset(&native_buffer, 0, (sizeof(nativebuffer) * MAX_NUM_INPUT_OUTPUT_BUFFERS));
 #endif
+     free(m_out_mem_ptr);
+     m_out_mem_ptr = NULL;
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

## 30. CVE-2013-6624 (CWE-399) item=107

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
@@ -1,8 +1,11 @@
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
+    if (!impl)
+        return;
+    map.add(impl);
+    if (Frame* f = frame())
+        f->script()->namedItemAdded(this, name);
+}
```

## 31. CVE-2016-5357 (CWE-20) item=108

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
@@ -7,5 +7,5 @@
 	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
 	gboolean	cap_dir;
-	char		cap_dst[13];
+	char		cap_dst[20];
  
  	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
```

## 32. CVE-2018-11380 (CWE-125) item=116

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
@@ -27,9 +27,13 @@
  	for (i = 0; i < bin->nsects; i++) {
  		if ((bin->sects[i].flags & SECTION_TYPE) == stype) {
-			for (j=0, sym=-1; bin->sects[i].reserved1+j < bin->nindirectsyms; j++)
+			for (j=0, sym=-1; bin->sects[i].reserved1+j < bin->nindirectsyms; j++) {
+				if (bin->sects[i].reserved1 + j < 0 || bin->sects[i].reserved1 + j >= bin->nindirectsyms) {
+					break;
+				}
 				if (idx == bin->indirectsyms[bin->sects[i].reserved1 + j]) {
  					sym = j;
  					break;
  				}
+			}
  			reloc->offset = sym == -1 ? 0 : bin->sects[i].offset + sym * wordsize;
  			reloc->addr = sym == -1 ? 0 : bin->sects[i].addr + sym * wordsize;
```

## 33. CVE-2018-14879 (CWE-120) item=117

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

## 34. CVE-2012-5156 (CWE-399) item=124

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
@@ -1,6 +1,6 @@
- void WorkerProcessLauncher::Core::OnChannelConnected(int32 peer_pid) {
-   DCHECK(caller_task_runner_->BelongsToCurrentThread());
- 
-  if (ipc_enabled_)
+void WorkerProcessLauncher::Core::OnChannelConnected(int32 peer_pid) {
+  DCHECK(caller_task_runner_->BelongsToCurrentThread());
+
+  if (ipc_enabled_ && worker_delegate_)
     worker_delegate_->OnChannelConnected();
- }
+}
```

## 35. CVE-2017-13007 (CWE-125) item=126

CVE: The Apple PKTAP parser in tcpdump before 4.9.2 has a buffer over-read in print-pktap.c:pktap_if_print().

### Official fix
```diff
--- vulnerable
+++ patched
@@ -7,4 +7,5 @@
  	if_printer printer;
  	const pktap_header_t *hdr;
+	struct pcap_pkthdr nhdr;
  
  	if (caplen < sizeof(pktap_header_t) || length < sizeof(pktap_header_t)) {
@@ -47,5 +48,8 @@
  	case PKT_REC_PACKET:
  		if ((printer = lookup_printer(dlt)) != NULL) {
-			hdrlen += printer(ndo, h, p);
+			nhdr = *h;
+			nhdr.caplen = caplen;
+			nhdr.len = length;
+			hdrlen += printer(ndo, &nhdr, p);
  		} else {
  			if (!ndo->ndo_eflag)
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -7,4 +7,5 @@
  	if_printer printer;
  	const pktap_header_t *hdr;
+ 	struct pcap_pkthdr h_adjusted;
  
  	if (caplen < sizeof(pktap_header_t) || length < sizeof(pktap_header_t)) {
@@ -47,5 +48,8 @@
  	case PKT_REC_PACKET:
  		if ((printer = lookup_printer(dlt)) != NULL) {
-			hdrlen += printer(ndo, h, p);
+			h_adjusted = *h;
+			h_adjusted.caplen = caplen;
+			h_adjusted.len = length;
+			hdrlen += printer(ndo, &h_adjusted, p);
  		} else {
  			if (!ndo->ndo_eflag)
```

## 36. CVE-2016-3921 (CWE-264) item=128

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
@@ -1,3 +1,3 @@
- bool FrameworkListener::onDataAvailable(SocketClient *c) {
+bool FrameworkListener::onDataAvailable(SocketClient *c) {
  char buffer[CMD_BUF_SIZE];
  int len;
@@ -24,4 +24,8 @@
          }
      }
+     
+     if (offset < len) {
+         SLOGW("Incomplete command at end of buffer");
+     }
  
      return true;
```

## 37. CVE-2017-5940 (CWE-269) item=129

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
@@ -5,6 +5,8 @@
 			errExit("asprintf");
 		struct stat s;
- 		if (stat(fname, &s) == 0)
+ 		if (lstat(fname, &s) == 0) {
+ 			free(fname);
  			return;
+ 		}
  		if (stat("/etc/skel/.zshrc", &s) == 0) {
 			if (is_link("/etc/skel/.zshrc")) {
@@ -36,6 +38,8 @@
 			errExit("asprintf");
 		struct stat s;
- 		if (stat(fname, &s) == 0)
+ 		if (lstat(fname, &s) == 0) {
+ 			free(fname);
  			return;
+ 		}
  		if (stat("/etc/skel/.cshrc", &s) == 0) {
 			if (is_link("/etc/skel/.cshrc")) {
@@ -50,5 +54,4 @@
  		}
 		else { // 
-			/* coverity[toctou] */
 			FILE *fp = fopen(fname, "w");
 			if (fp) {
@@ -68,6 +71,8 @@
  			errExit("asprintf");
  		struct stat s;
-		if (stat(fname, &s) == 0)
+		if (lstat(fname, &s) == 0) {
+ 			free(fname);
  			return;
+ 		}
  		if (stat("/etc/skel/.bashrc", &s) == 0) {
 			if (is_link("/etc/skel/.bashrc")) {
@@ -76,5 +81,4 @@
 			}
 			if (copy_file("/etc/skel/.bashrc", fname) == 0) {
-				/* coverity[toctou] */
 				if (chown(fname, u, g) == -1)
 					errExit("chown");
@@ -82,4 +86,16 @@
 			}
  		}
+ 		else {
+			FILE *fp = fopen(fname, "w");
+			if (fp) {
+				fprintf(fp, "\n");
+				fclose(fp);
+				if (chown(fname, u, g) == -1)
+					errExit("chown");
+				if (chmod(fname, S_IRUSR | S_IWUSR) < 0)
+					errExit("chown");
+				fs_logger2("touch", fname);
+			}
+ 		}
  		free(fname);
  	}
```

## 38. CVE-2015-7804 (CWE-189) item=132

CVE: Off-by-one error in the phar_parse_zipfile function in ext/phar/zip.c in PHP before 5.5.30 and 5.6.x before 5.6.14 allows remote attackers to cause a denial of service (uninitialized pointer dereference and application crash) by including the / filename in a .zip PHAR archive.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -5,5 +5,5 @@
         while ((s = zend_memrchr(filename, '/', filename_len))) {
                 filename_len = s - filename;
-               if (FAILURE == zend_hash_add_empty_element(&phar->virtual_dirs, filename, filename_len)) {
+               if (!filename_len || FAILURE == zend_hash_add_empty_element(&phar->virtual_dirs, filename, filename_len)) {
                         break;
                 }
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -2,11 +2,16 @@
 {
 	const char *s;
- 
-        while ((s = zend_memrchr(filename, '/', filename_len))) {
-                filename_len = s - filename;
-               if (FAILURE == zend_hash_add_empty_element(&phar->virtual_dirs, filename, filename_len)) {
-                        break;
-                }
-        }
+	char c;
+
+	while ((s = zend_memrchr(filename, '/', filename_len))) {
+		filename_len = s - filename;
+		c = filename[filename_len];
+		filename[filename_len] = '\0';
+		if (FAILURE == zend_hash_add_empty_element(&phar->virtual_dirs, filename, filename_len)) {
+			filename[filename_len] = c;
+			break;
+		}
+		filename[filename_len] = c;
+	}
 }
 /* }}} */
```

## 39. CVE-2013-0911 (CWE-22) item=137

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
@@ -4,4 +4,7 @@
                                               int64 estimated_size) {
    DCHECK(BrowserThread::CurrentlyOn(BrowserThread::FILE));
+   if (origin_identifier.empty() || database_name.empty()) {
+     return;
+   }
    int64 database_size = 0;
    db_tracker_->DatabaseOpened(origin_identifier, database_name, description,
```

## 40. CVE-2011-2895 (CWE-119) item=148

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

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -42,4 +42,6 @@
      	 */
     	if ( code >= file->free_ent ) {
+	    if (stackp >= file->de_stack + STACKSIZE)
+	    	break;
 	    *stackp++ = finchar;
 	    code = oldcode;
@@ -51,4 +53,6 @@
      	while ( code >= 256 )
      	{
+	    if (code >= file->maxmaxcode || stackp >= file->de_stack + STACKSIZE)
+	    	break;
  	    *stackp++ = file->tab_suffix[code];
  	    code = file->tab_prefix[code];
```

## 41. CVE-2013-2929 (CWE-264) item=149

CVE: The Linux kernel before 3.12.2 does not properly use the get_dumpable function, which allows local users to bypass intended ptrace restrictions or obtain sensitive information from IA64 scratch registers via a crafted application, related to kernel/ptrace.c and arch/ia64/include/asm/processor.h.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -34,5 +34,6 @@
  		dumpable = get_dumpable(task->mm);
  	rcu_read_lock();
-	if (!dumpable && !ptrace_has_cap(__task_cred(task)->user_ns, mode)) {
+	if (dumpable != SUID_DUMP_USER &&
+	    !ptrace_has_cap(__task_cred(task)->user_ns, mode)) {
  		rcu_read_unlock();
  		return -EPERM;
```

### Agent patch
```diff
--- vulnerable
+++ patched
@@ -34,5 +34,5 @@
  		dumpable = get_dumpable(task->mm);
  	rcu_read_lock();
-	if (!dumpable && !ptrace_has_cap(__task_cred(task)->user_ns, mode)) {
+	if (!dumpable && !ptrace_has_cap(tcred->user_ns, mode)) {
  		rcu_read_unlock();
  		return -EPERM;
```
