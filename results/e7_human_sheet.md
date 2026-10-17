# Why is the fix wrong? Blind check of right-place-wrong-fix patches

For each case read the CVE, the official fix and the candidate patch, and write ONE category in results/e7_human_labels.csv: incomplete_condition (handles some but not all cases), wrong_bound_or_operator, wrong_remedy_type (a different kind of remedy at the right place), missing_companion_change (the marked change is right, a second change elsewhere is absent), different_bug (fixes something else), cannot_tell. The arm and repeat are hidden.

## W01. CVE-2017-16526

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

## W02. CVE-2016-2482

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

## W03. CVE-2014-3615

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

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,51 +1,40 @@
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
+    static const uint32_t MAX_SURFACE_WIDTH = 2560;
+    static const uint32_t MAX_SURFACE_HEIGHT = 2048;
+
+    memset(&surface, 0, sizeof(surface));
+
+    /* Validate surface dimensions to prevent host memory access */
+    if (surface_width(ssd->ds) > MAX_SURFACE_WIDTH ||
+        surface_height(ssd->ds) > MAX_SURFACE_HEIGHT) {
+        dprint(1, "%s/%d: surface dimensions too large\n", __func__, ssd->qxl.id);
+        return;
+    }
+
+    /* Check that surface size fits within allocated buffer */
+    required_size = (uint64_t)surface_width(ssd->ds) * 
+                    surface_height(ssd->ds) * 4; /* 4 bytes per pixel for 32-bit */
+    if (required_size > ssd->bufsize) {
+        dprint(1, "%s/%d: surface size exceeds buffer\n", __func__, ssd->qxl.id);
+        return;
+    }
+
     dprint(1, "%s/%d: %dx%d\n", __func__, ssd->qxl.id,
            surface_width(ssd->ds), surface_height(ssd->ds));
- 
-     surface.format     = SPICE_SURFACE_FMT_32_xRGB;
-     surface.width      = surface_width(ssd->ds);
-{
+
+    surface.format     = SPICE_SURFACE_FMT_32_xRGB;
+    surface.width      = surface_width(ssd->ds);
+    surface.height     = surface_height(ssd->ds);
+    surface.stride     = surface_width(ssd->ds) * 4;
+    surface.mouse_mode = 0;
+    surface.flags      = 0;
+    surface.type       = 0;
+    surface.mem        = ssd->bufsize;
+
     dprint(1, "%s/%d:\n", __func__, ssd->qxl.id);
 
     qemu_spice_destroy_primary_surface(ssd, 0, QXL_SYNC);
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

## W04. CVE-2015-3331

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

## W05. CVE-2013-0839

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

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,8 +1,7 @@
 GDataEntry* GDataDirectory::FromDocumentEntry(
-    GDataDirectory* parent,
     DocumentEntry* doc,
     GDataDirectoryService* directory_service) {
   DCHECK(doc->is_folder());
-  GDataDirectory* dir = new GDataDirectory(parent, directory_service);
+  GDataDirectory* dir = new GDataDirectory(directory_service);
   dir->title_ = UTF16ToUTF8(doc->title());
   dir->SetBaseNameFromTitle();
@@ -21,7 +20,7 @@
     dir->parent_resource_id_ = ExtractResourceId(parent_link->href());
  
-   const Link* upload_link = doc->GetLinkByType(Link::RESUMABLE_CREATE_MEDIA);
-   if (upload_link)
+  const Link* upload_link = doc->GetLinkByType(Link::RESUMABLE_CREATE_MEDIA);
+  if (upload_link)
     dir->upload_url_ = upload_link->href();
   return dir;
- }
+}
```

## W06. CVE-2011-3906

CVE: The PDF parser in Google Chrome before 16.0.912.63 allows remote attackers to cause a denial of service (out-of-bounds read) via unspecified vectors.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -11,5 +11,7 @@
      if (windowInfo.windowSize.isEmpty()) {
          bool includeScrollbars = !InspectorInstrumentation::shouldApplyScreenWidthOverride(mainFrame);
-        windowInfo.windowSize = mainFrame->view()->visibleContentRect(includeScrollbars).size(); // FIXME: Check that this is always in logical (density-independent) pixels (see wkbug.com/87440).
+        windowInfo.windowSize = mainFrame->view()->visibleContentRect(includeScrollbars).size();
+        if (!m_document->settings()->applyPageScaleFactorInCompositor())
+            windowInfo.windowSize.scale(1 / m_document->page()->deviceScaleFactor());
      }
  
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -5,13 +5,15 @@
 
     Frame* mainFrame = m_document->page()->mainFrame();
+    if (!mainFrame)
+        return false;
 
     TextAutosizingWindowInfo windowInfo;
 
-     windowInfo.windowSize = m_document->settings()->textAutosizingWindowSizeOverride();
-     if (windowInfo.windowSize.isEmpty()) {
-         bool includeScrollbars = !InspectorInstrumentation::shouldApplyScreenWidthOverride(mainFrame);
-        windowInfo.windowSize = mainFrame->view()->visibleContentRect(includeScrollbars).size(); // FIXME: Check that this is always in logical (density-independent) pixels (see wkbug.com/87440).
-     }
- 
+    windowInfo.windowSize = m_document->settings()->textAutosizingWindowSizeOverride();
+    if (windowInfo.windowSize.isEmpty()) {
+        bool includeScrollbars = !InspectorInstrumentation::shouldApplyScreenWidthOverride(mainFrame);
+        windowInfo.windowSize = mainFrame->view()->visibleContentRect(includeScrollbars).size();
+    }
+
     windowInfo.minLayoutSize = mainFrame->view()->layoutSize();
     for (Frame* frame = m_document->frame(); frame; frame = frame->tree()->parent()) {
@@ -21,6 +23,12 @@
 
     RenderBlock* container = layoutRoot->isRenderBlock() ? toRenderBlock(layoutRoot) : layoutRoot->containingBlock();
+    if (!container)
+        return false;
+
     while (container && !isAutosizingContainer(container))
         container = container->containingBlock();
+
+    if (!container)
+        return false;
 
     RenderBlock* cluster = container;
```

## W07. CVE-2017-16526

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

## W08. CVE-2015-3331

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

## W09. CVE-2017-5850

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

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,35 +1,46 @@
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
+	size_t			 total_size = 0;
+	size_t			 max_size = file_sz; /* Limit total output to file size */
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
+
+	while ((q = strchr(p, ',')) != NULL) {
+		*q++ = '\0';
+
+		/* Extract start and end positions */
 		if (parse_range_spec(p, file_sz, &ranges[i]) == 0)
- 			continue;
- 
- 		i++;
+			continue;
+
+		/* Check if cumulative size exceeds limit */
+		total_size += ranges[i].end - ranges[i].start + 1;
+		if (total_size > max_size)
+			return (NULL);
+
+		i++;
 		if (i == MAX_RANGES)
 			return (NULL);
- 
- 		p = q;
- 	}
- 
-	if (parse_range_spec(p, file_sz, &ranges[i]) != 0)
- 		i++;
- 
+
+		p = q;
+	}
+
+	if (parse_range_spec(p, file_sz, &ranges[i]) != 0) {
+		total_size += ranges[i].end - ranges[i].start + 1;
+		if (total_size > max_size)
+			return (NULL);
+		i++;
+	}
+
 	*nranges = i;
 	return (i ? ranges : NULL);
- }
+}
```

## W10. CVE-2016-7126

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

## W11. CVE-2018-12232

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

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,5 +1,10 @@
- static int sock_close(struct inode *inode, struct file *filp)
- {
-	sock_release(SOCKET_I(inode));
- 	return 0;
- }
+static int sock_close(struct inode *inode, struct file *filp)
+{
+	struct socket *sock = SOCKET_I(inode);
+	
+	if (filp->private_data) {
+		filp->private_data = NULL;
+		sock_release(sock);
+	}
+	return 0;
+}
```

## W12. CVE-2013-0911

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

## W13. CVE-2010-5331

CVE: In the Linux kernel before 2.6.34, a range check issue in drivers/gpu/drm/radeon/atombios.c could cause an off by one (buffer overflow) problem. NOTE: At least one Linux maintainer believes that this CVE is incorrectly assigned and should be rejected because the value is hard coded and are not user-controllable where it is used

### Official fix
```diff
--- vulnerable
+++ patched
@@ -17,5 +17,5 @@
  	case 1:
  		tv_info = (ATOM_ANALOG_TV_INFO *)(mode_info->atom_context->bios + data_offset);
-		if (index > MAX_SUPPORTED_TV_TIMING)
+		if (index >= MAX_SUPPORTED_TV_TIMING)
  			return false;
  
@@ -55,5 +55,5 @@
  	case 2:
  		tv_info_v1_2 = (ATOM_ANALOG_TV_INFO_V1_2 *)(mode_info->atom_context->bios + data_offset);
-		if (index > MAX_SUPPORTED_TV_TIMING_V1_2)
+		if (index >= MAX_SUPPORTED_TV_TIMING_V1_2)
  			return false;
  
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -17,5 +17,5 @@
  	case 1:
  		tv_info = (ATOM_ANALOG_TV_INFO *)(mode_info->atom_context->bios + data_offset);
-		if (index > MAX_SUPPORTED_TV_TIMING)
+		if (index < 0 || index > MAX_SUPPORTED_TV_TIMING)
  			return false;
  
@@ -55,5 +55,5 @@
  	case 2:
  		tv_info_v1_2 = (ATOM_ANALOG_TV_INFO_V1_2 *)(mode_info->atom_context->bios + data_offset);
-		if (index > MAX_SUPPORTED_TV_TIMING_V1_2)
+		if (index < 0 || index > MAX_SUPPORTED_TV_TIMING_V1_2)
  			return false;
  
```

## W14. CVE-2016-3921

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

### Candidate patch
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
+         SLOGW("Incomplete command received");
+     }
  
      return true;
```

## W15. CVE-2016-7126

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
+		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Number of colors has to be greater than zero and less than or equal to 256");
  		RETURN_FALSE;
  	}
```

## W16. CVE-2018-6080

CVE: Lack of access control checks in Instrumentation in Google Chrome prior to 65.0.3325.146 allowed a remote attacker who had compromised the renderer process to obtain memory metadata from privileged processes .

### Official fix
```diff
--- vulnerable
+++ patched
@@ -33,4 +33,7 @@
        &memory_instrumentation::CoordinatorImpl::BindCoordinatorRequest,
        base::Unretained(memory_instrumentation_coordinator_.get())));
+  registry_.AddInterface(base::BindRepeating(
+      &memory_instrumentation::CoordinatorImpl::BindHeapProfilerHelperRequest,
+      base::Unretained(memory_instrumentation_coordinator_.get())));
  
    tracing_agent_registry_ = std::make_unique<tracing::AgentRegistry>();
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -27,13 +27,6 @@
   coordination_unit_manager_.set_ukm_recorder(ukm_recorder_.get());
 
-  memory_instrumentation_coordinator_ =
-      std::make_unique<memory_instrumentation::CoordinatorImpl>(
-          context()->connector());
-   registry_.AddInterface(base::BindRepeating(
-       &memory_instrumentation::CoordinatorImpl::BindCoordinatorRequest,
-       base::Unretained(memory_instrumentation_coordinator_.get())));
- 
-   tracing_agent_registry_ = std::make_unique<tracing::AgentRegistry>();
-   registry_.AddInterface(
+  tracing_agent_registry_ = std::make_unique<tracing::AgentRegistry>();
+  registry_.AddInterface(
       base::BindRepeating(&tracing::AgentRegistry::BindAgentRegistryRequest,
                           base::Unretained(tracing_agent_registry_.get())));
```

## W17. CVE-2016-5357

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
@@ -25,4 +25,6 @@
 	if (pkt_len == -1)
 		return FALSE;
+	if (pkt_len < 0)
+		return FALSE;
 	if (!parse_netscreen_hex_dump(wth->random_fh, pkt_len, cap_int,
 	    cap_dst, phdr, buf, err, err_info))
```

## W18. CVE-2018-16066

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

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,5 +1,8 @@
- Node::InsertionNotificationRequest HTMLStyleElement::InsertedInto(
-     ContainerNode* insertion_point) {
-   HTMLElement::InsertedInto(insertion_point);
-  return kInsertionShouldCallDidNotifySubtreeInsertions;
- }
+Node::InsertionNotificationRequest HTMLStyleElement::InsertedInto(
+    ContainerNode* insertion_point) {
+  HTMLElement::InsertedInto(insertion_point);
+  if (insertion_point->isConnected()) {
+    UpdateStyleSheetInternal();
+  }
+  return kInsertionDone;
+}
```

## W19. CVE-2017-12192

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

## W20. CVE-2019-15163

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

### Candidate patch
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

## W21. CVE-2017-16526

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

## W22. CVE-2011-2895

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
@@ -42,5 +42,6 @@
      	 */
     	if ( code >= file->free_ent ) {
-	    *stackp++ = finchar;
+	    if (stackp < file->de_stack + STACK_SIZE)
+	        *stackp++ = finchar;
 	    code = oldcode;
     	}
@@ -51,4 +52,6 @@
      	while ( code >= 256 )
      	{
+	    if (stackp >= file->de_stack + STACK_SIZE)
+	        break;
  	    *stackp++ = file->tab_suffix[code];
  	    code = file->tab_prefix[code];
```

## W23. CVE-2016-5357

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
@@ -1,2 +1,3 @@
+gboolean
 netscreen_seek_read(wtap *wth, gint64 seek_off,
  	struct wtap_pkthdr *phdr, Buffer *buf,
@@ -25,4 +26,8 @@
 	if (pkt_len == -1)
 		return FALSE;
+	if (pkt_len < 0 || strlen(cap_dst) >= sizeof(cap_dst)) {
+		*err = WTAP_ERR_BAD_FILE;
+		return FALSE;
+	}
 	if (!parse_netscreen_hex_dump(wth->random_fh, pkt_len, cap_int,
 	    cap_dst, phdr, buf, err, err_info))
```

## W24. CVE-2013-2929

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

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -29,10 +29,8 @@
 	return -EPERM;
 ok:
-	rcu_read_unlock();
 	smp_rmb();
  	if (task->mm)
  		dumpable = get_dumpable(task->mm);
- 	rcu_read_lock();
-	if (!dumpable && !ptrace_has_cap(__task_cred(task)->user_ns, mode)) {
+	if (!dumpable && !ptrace_has_cap(tcred->user_ns, mode)) {
  		rcu_read_unlock();
  		return -EPERM;
```

## W25. CVE-2015-1214

CVE: Integer overflow in the SkAutoSTArray implementation in include/core/SkTemplates.h in the filters implementation in Skia, as used in Google Chrome before 41.0.2272.76, allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors that trigger a reset action with a large count value, leading to an out-of-bounds write operation.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -6,4 +6,6 @@
    fetcher->SetLoadFlags(net::LOAD_DO_NOT_SEND_COOKIES |
                          net::LOAD_DO_NOT_SAVE_COOKIES);
+  data_use_measurement::DataUseUserData::AttachToFetcher(
+      fetcher.get(), data_use_measurement::DataUseUserData::SIGNIN);
  
   fetcher->SetAutomaticallyRetryOnNetworkChanges(1);
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,11 +1,20 @@
-GaiaCookieManagerService::ExternalCcResultFetcher::CreateFetcher(
+std::unique_ptr<net::URLFetcher> CreateFetcher(
     const GURL& url) {
+  if (!url.is_valid()) {
+    return nullptr;
+  }
+  
   std::unique_ptr<net::URLFetcher> fetcher =
       net::URLFetcher::Create(0, url, net::URLFetcher::GET, this);
-   fetcher->SetRequestContext(helper_->request_context());
-   fetcher->SetLoadFlags(net::LOAD_DO_NOT_SEND_COOKIES |
-                         net::LOAD_DO_NOT_SAVE_COOKIES);
- 
+  
+  if (!fetcher) {
+    return nullptr;
+  }
+  
+  fetcher->SetRequestContext(helper_->request_context());
+  fetcher->SetLoadFlags(net::LOAD_DO_NOT_SEND_COOKIES |
+                        net::LOAD_DO_NOT_SAVE_COOKIES);
   fetcher->SetAutomaticallyRetryOnNetworkChanges(1);
+  
   return fetcher;
 }
```

## W26. CVE-2016-2105

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

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -9,5 +9,5 @@
          return;
      OPENSSL_assert(ctx->length <= (int)sizeof(ctx->enc_data));
-    if ((ctx->num + inl) < ctx->length) {
+    if (inl < ctx->length - ctx->num) {
          memcpy(&(ctx->enc_data[ctx->num]), in, inl);
          ctx->num += inl;
```

## W27. CVE-2019-14975

CVE: Artifex MuPDF before 1.16.0 has a heap-based buffer over-read in fz_chartorune in fitz/string.c because pdf/pdf-op-filter.c does not check for a missing string.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -3,5 +3,5 @@
         int rune;
  
-       if (str->utf8 == NULL)
+       if (str->utf8 == NULL || str->pos == -1)
                 return;
  
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -3,5 +3,5 @@
         int rune;
  
-       if (str->utf8 == NULL)
+       if (str->utf8 == NULL || str->utf8[str->pos] == '\0')
                 return;
  
```

## W28. CVE-2012-6538

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

### Candidate patch
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

## W29. CVE-2011-3088

CVE: Google Chrome before 19.0.1084.46 does not properly draw hairlines, which allows remote attackers to cause a denial of service (out-of-bounds read) via unspecified vectors.

### Official fix
```diff
--- vulnerable
+++ patched
@@ -13,11 +13,21 @@
          restore_started_(base::TimeTicks::Now()),
          browser_shown_(false) {
-    if (profiles_getting_restored == NULL)
-      profiles_getting_restored = new std::set<const Profile*>();
  
-    CHECK(profiles_getting_restored->find(profile) ==
-          profiles_getting_restored->end());
+    // Iterate the active session restorers to find if there is a
+    // SessionRestoreImpl referring the same profile. This should not happen but
+    // for some reason it happens still. TODO(marja): figure out why.
+    if (active_session_restorers == NULL)
+      active_session_restorers = new std::set<SessionRestoreImpl*>();
+
+    std::set<SessionRestoreImpl*>::const_iterator it;
+    for (it = active_session_restorers->begin();
+         it != active_session_restorers->end(); ++it) {
+      if ((*it)->profile_ == profile)
+        break;
+    }
+    DCHECK(it == active_session_restorers->end());
+
+    active_session_restorers->insert(this);
  
-    profiles_getting_restored->insert(profile);
     g_browser_process->AddRefModule();
   }
```

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -16,7 +16,4 @@
       profiles_getting_restored = new std::set<const Profile*>();
  
-    CHECK(profiles_getting_restored->find(profile) ==
-          profiles_getting_restored->end());
- 
     profiles_getting_restored->insert(profile);
     g_browser_process->AddRefModule();
```

## W30. CVE-2011-2200

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

### Candidate patch
```diff
--- vulnerable
+++ patched
@@ -1,13 +1,20 @@
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
+void
+_dbus_header_byteswap (DBusHeader *header,
+                       int         new_order)
+{
+  if (header == NULL)
+    return;
+
+  if (new_order != DBUS_LITTLE_ENDIAN && new_order != DBUS_BIG_ENDIAN)
+    return;
+
+  if (header->byte_order == new_order)
+    return;
+
+  _dbus_marshal_byteswap (&_dbus_header_signature_str,
+                          0, header->byte_order,
+                          new_order,
+                          &header->data, 0);
+
+  header->byte_order = new_order;
+}
```
