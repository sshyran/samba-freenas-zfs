/* 
 * implementation of an Shadow Copy module for zfs.
 *
 * Copyright (C) Andrew Tridgell     2007
 * Copyright (C) Ed Plese            2009
 * Copyright (C) XStor Systems Inc   2011
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "ntioctl.h"
#include <libzfs.h>

/*

  This is an implemetation of a shadow copy module for exposing zfs
  snapshots to windows clients as shadow copies. It is based heavily
  on vfs_shadow_copy2.

  Module options:

      shadow:filesystem = <the zfs filesystem that the snapshots are from>

      The zfs filesystem hosting the share. It takes the form
      <poolname>[/<fs>...] .

      shadow:sort = asc/desc

      This is an optional parameter that specifies how that the shadow
      copy directories should be sorted before sending them to the
      client. The default is in descending order.

      shadow:include = <list of glob patterns of snapshot names>

      This is an optional parameter that selects the snapshots to
      return to clients. If not specified, all snapshots are included.
      This list is subject to the exlusions below.

      shadow:exclude = <list of glob patterns of snapshot names>

      This is an optional parameter that specifies the snapshots to
      exclude from those selected by shadow:include. If not specified
      none are excluded, i.e. all selected snapshots are shown.

 */

static int vfs_shadow_copy_zfs_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_shadow_copy_zfs_debug_level

#define GMT_NAME_LEN 24 /* length of a @GMT- name */
#define SHADOW_COPY_ZFS_GMT_FORMAT "@GMT-%Y.%m.%d-%H.%M.%S"

#define SHADOW_COPY_ZFS_DEFAULT_SORT "desc"
#define SHADOW_COPY_ZFS_SNAP_DIR ".zfs/snapshot"
#define MAX_CACHE_TIME 10.0

struct snapshot_entry {
	SHADOW_COPY_LABEL label;
	char name[1];
};

struct snapshot_list {
	time_t timestamp;
	char *mountpoint;
	int (*cmpfunc)(const void *, const void *);
	size_t num_entries;
	struct snapshot_entry *entries[1];
};

struct iter_info {
	struct snapshot_list *snapshots;
	const char **inclusions;
	const char **exclusions;
};

static const char *null_string = NULL;
static const char **empty_list = &null_string;


/*
  make very sure it is one of our special names
 */
static inline bool shadow_copy_zfs_match_name(const char *name,
					      const char **gmt_start)
{
	unsigned year, month, day, hr, min, sec;
	const char *p;
	if (gmt_start) {
		(*gmt_start) = NULL;
	}
	p = strstr_m(name, "@GMT-");
	if (p == NULL) return false;
	if (p > name && p[-1] != '/') return False;
	if (sscanf(p, "@GMT-%04u.%02u.%02u-%02u.%02u.%02u", &year, &month,
		   &day, &hr, &min, &sec) != 6) {
		return False;
	}
	if (p[24] != 0 && p[24] != '/') {
		return False;
	}
	if (gmt_start) {
		(*gmt_start) = p;
	}
	return True;
}

/*
  shadow copy paths can also come into the server in this form:

    /foo/bar/@GMT-XXXXX/some/file

  This function normalises the filename to be of the form:

    @GMT-XXXX/foo/bar/some/file
 */
static const char *shadow_copy_zfs_normalise_path(TALLOC_CTX *mem_ctx,
						  const char *path,
						  const char *gmt_start)
{
	char *pcopy;
	char buf[GMT_NAME_LEN];
	size_t prefix_len;

	if (path == gmt_start) {
		return path;
	}

	prefix_len = gmt_start - path - 1;

	DEBUG(10, ("path=%s, gmt_start=%s, prefix_len=%d\n", path, gmt_start,
		   (int)prefix_len));

	/*
	 * We've got a/b/c/@GMT-YYYY.MM.DD-HH.MM.SS/d/e. convert to
	 * @GMT-YYYY.MM.DD-HH.MM.SS/a/b/c/d/e before further
	 * processing. As many VFS calls provide a const char *,
	 * unfortunately we have to make a copy.
	 */

	pcopy = talloc_strdup(mem_ctx, path);
	if (pcopy == NULL) {
		return NULL;
	}

	gmt_start = pcopy + prefix_len;

	/*
	 * Copy away "@GMT-YYYY.MM.DD-HH.MM.SS"
	 */
	memcpy(buf, gmt_start+1, GMT_NAME_LEN);

	/*
	 * Make space for it including a trailing /
	 */
	memmove(pcopy + GMT_NAME_LEN + 1, pcopy, prefix_len);

	/*
	 * Move in "@GMT-YYYY.MM.DD-HH.MM.SS/" at the beginning again
	 */
	memcpy(pcopy, buf, GMT_NAME_LEN);
	pcopy[GMT_NAME_LEN] = '/';

	DEBUG(10, ("shadow_copy_zfs_normalise_path: %s -> %s\n", path, pcopy));

	return pcopy;
}

/*
  convert a name to the shadow directory
 */

#define _SHADOW2_NEXT(op, args, rtype, eret, extra) do { \
	const char *name = fname; \
	const char *gmt_start; \
	if (shadow_copy_zfs_match_name(fname, &gmt_start)) { \
		char *name2; \
		rtype ret; \
		name2 = convert_shadow_zfs_name(handle, fname, gmt_start, \
						True); \
		if (name2 == NULL) { \
			errno = EINVAL; \
			return eret; \
		} \
		name = name2; \
		ret = SMB_VFS_NEXT_ ## op args; \
		talloc_free(name2); \
		if (ret != eret) extra; \
		return ret; \
	} else { \
		return SMB_VFS_NEXT_ ## op args; \
	} \
} while (0)

#define _SHADOW2_NEXT_SMB_FNAME(op, args, rtype, eret, extra) do { \
	const char *gmt_start; \
	if (shadow_copy_zfs_match_name(smb_fname->base_name, &gmt_start)) { \
		char *name2; \
		char *smb_base_name_tmp = NULL; \
		rtype ret; \
		name2 = convert_shadow_zfs_name(handle, smb_fname->base_name, \
						gmt_start, True); \
		if (name2 == NULL) { \
			errno = EINVAL; \
			return eret; \
		} \
		smb_base_name_tmp = smb_fname->base_name; \
		smb_fname->base_name = name2; \
		ret = SMB_VFS_NEXT_ ## op args; \
		smb_fname->base_name = smb_base_name_tmp; \
		talloc_free(name2); \
		if (ret != eret) extra; \
		return ret; \
	} else { \
		return SMB_VFS_NEXT_ ## op args; \
	} \
} while (0)

/*
  convert a name to the shadow directory: NTSTATUS-specific handling
 */

#define _SHADOW2_NTSTATUS_NEXT(op, args, eret, extra) do { \
	const char *name = fname; \
	const char *gmt_start; \
	if (shadow_copy_zfs_match_name(fname, &gmt_start)) { \
		char *name2; \
		NTSTATUS ret; \
		name2 = convert_shadow_zfs_name(handle, fname, gmt_start, \
						True); \
		if (name2 == NULL) { \
			errno = EINVAL; \
			return eret; \
		} \
		name = name2; \
		ret = SMB_VFS_NEXT_ ## op args; \
		talloc_free(name2); \
		if (!NT_STATUS_EQUAL(ret, eret)) extra; \
		return ret; \
	} else { \
		return SMB_VFS_NEXT_ ## op args; \
	} \
} while (0)

#define SHADOW2_NTSTATUS_NEXT(op, args, eret) \
				_SHADOW2_NTSTATUS_NEXT(op, args, eret, )

#define SHADOW2_NEXT(op, args, rtype, eret) \
				_SHADOW2_NEXT(op, args, rtype, eret, )

#define SHADOW2_NEXT_SMB_FNAME(op, args, rtype, eret) \
				_SHADOW2_NEXT_SMB_FNAME(op, args, rtype, eret, )

#define SHADOW2_NEXT2(op, args) do { \
	const char *gmt_start1, *gmt_start2; \
	if (shadow_copy_zfs_match_name(oldname, &gmt_start1) || \
	    shadow_copy_zfs_match_name(newname, &gmt_start2)) { \
		errno = EROFS; \
		return -1; \
	} else { \
		return SMB_VFS_NEXT_ ## op args; \
	} \
} while (0)

#define SHADOW2_NEXT2_SMB_FNAME(op, args) do { \
	const char *gmt_start1, *gmt_start2; \
	if (shadow_copy_zfs_match_name(smb_fname_src->base_name, &gmt_start1) || \
	    shadow_copy_zfs_match_name(smb_fname_dst->base_name, &gmt_start2)) { \
		errno = EROFS; \
		return -1; \
	} else { \
		return SMB_VFS_NEXT_ ## op args; \
	} \
} while (0)

#define SHADOW2_XATTR_NEXT(op, args, rtype, eret, extra) do { \
	const char *name = fname; \
	const char *gmt_start; \
	if (shadow_copy_zfs_match_name(fname, &gmt_start)) { \
		char *name2; \
		rtype ret; \
		name2 = convert_shadow_zfs_name(handle, fname, gmt_start, \
						True); \
		if (name2 == NULL) { \
			errno = EINVAL; \
			return eret; \
		} \
		name = name2; \
		ret = SMB_VFS_NEXT_ ## op args; \
		extra; \
		talloc_free(name2); \
		return ret; \
	} else { \
		return SMB_VFS_NEXT_ ## op args; \
	} \
} while (0)

static int shadow_copy_zfs_label_cmp_asc(const void *x, const void *y)
{
	return strncmp((*((struct snapshot_entry **) x))->label,
		       (*((struct snapshot_entry **) y))->label,
		       sizeof(SHADOW_COPY_LABEL));
}

static int shadow_copy_zfs_label_cmp_desc(const void *x, const void *y)
{
	return -strncmp((*((struct snapshot_entry **) x))->label,
			(*((struct snapshot_entry **) y))->label,
			sizeof(SHADOW_COPY_LABEL));
}

/*
  sort the shadow copy data in ascending or descending order
 */
static void shadow_copy_zfs_sort_data(vfs_handle_struct *handle,
				      struct snapshot_list *snapshots)
{
	const char *sort;

	if (snapshots->num_entries <= 0) {
		return;
	}

	sort = lp_parm_const_string(SNUM(handle->conn), "shadow",
				    "sort", SHADOW_COPY_ZFS_DEFAULT_SORT);

	if (strcmp(sort, "asc") == 0) {
		snapshots->cmpfunc = shadow_copy_zfs_label_cmp_asc;
	} else {
		snapshots->cmpfunc = shadow_copy_zfs_label_cmp_desc;
	}

	TYPESAFE_QSORT(snapshots->entries, snapshots->num_entries,
		       snapshots->cmpfunc);

	return;
}

static void shadow_copy_zfs_free_snapshots(void **datap)
{
	TALLOC_FREE(*datap);
}

static bool shadow_copy_zfs_is_snapshot_included(struct iter_info *info,
						 const char *snap_name)
{
	const char **pattern;

	pattern = info->inclusions;
	while (*pattern) {
		if (unix_wild_match(*pattern, snap_name)) {
			break;
		}
		pattern++;
	}

	if (*info->inclusions && !*pattern) {
		DEBUG(2,("shadow_copy_zfs_add_snapshot: snapshot %s "
			 "not in inclusion list\n", snap_name));
		return False;
	}

	pattern = info->exclusions;
	while (*pattern) {
		if (unix_wild_match(*pattern, snap_name)) {
			DEBUG(2,("shadow_copy_zfs_add_snapshot: snapshot %s "
				 "in exclusion list\n", snap_name));
			return False;
		}
		pattern++;
	}

	return True;
}

static int shadow_copy_zfs_add_snapshot(zfs_handle_t *snap, void *data)
{
	struct iter_info *info = (struct iter_info *) data;
	struct snapshot_entry *entry;
	const char *snap_name;
	char ts_buf[20];
	time_t timestamp_t;
	struct tm timestamp;
	int rc;
	size_t req_mem, name_len;

	/* ignore excluded snapshots */
	snap_name = strchr(zfs_get_name(snap), '@') + 1;

	if (!shadow_copy_zfs_is_snapshot_included(info, snap_name)) {
		return 0;
	}

	/* get creation date */
	rc = zfs_prop_get(snap, ZFS_PROP_CREATION, ts_buf, sizeof(ts_buf),
			  NULL, NULL, 0, 1);
	if (rc != 0) {
		DEBUG(0,("shadow_copy_zfs_add_snapshot: error getting "
			 "creation date: %s\n", strerror(errno)));
		return -2;
	}

	sscanf(ts_buf, "%lu", &timestamp_t);

	/* expand list if necessary */
	req_mem = sizeof(*info->snapshots) +
		  info->snapshots->num_entries *
		  sizeof(info->snapshots->entries[0]);

	if (req_mem > talloc_get_size(info->snapshots)) {
		req_mem += info->snapshots->num_entries / 2 *
			   sizeof(info->snapshots->entries[0]);
		info->snapshots = TALLOC_REALLOC(talloc_parent(info->snapshots),
						 info->snapshots, req_mem);
		if (info->snapshots == NULL) {
			DEBUG(0,("shadow_copy_zfs_add_snapshot: out of memory "
				 "(requested %d bytes)\n", req_mem));
			return -2;
		}
	}

	/* add entry */
	name_len = strlen(snap_name);

	entry = talloc_size(info->snapshots, sizeof(*entry) + name_len);
	if (entry == NULL) {
		DEBUG(0,("shadow_copy_zfs_add_snapshot: out of memory "
			 "(requested %d bytes)\n", sizeof(*entry) + name_len));
		return -2;
	}

	info->snapshots->entries[info->snapshots->num_entries++] = entry;

	gmtime_r(&timestamp_t, &timestamp);
	strftime(entry->label, sizeof(entry->label), SHADOW_COPY_ZFS_GMT_FORMAT,
		 &timestamp);

	strlcpy(entry->name, snap_name, name_len + 1);

	return 0;
}

/*
  work out the mountpoint of the filesystem
 */
static struct snapshot_list *shadow_copy_zfs_list_snapshots(
				vfs_handle_struct *handle, bool force_read)
{
	struct snapshot_list *snapshots = NULL;
	struct iter_info iter_info;
	size_t initial_size;
	const char *fs;
	libzfs_handle_t *libzfs = NULL;
	zfs_handle_t *zfs = NULL;
	int rc;

	/* look in cache first, unless force_read is set */
	if (!force_read && SMB_VFS_HANDLE_TEST_DATA(handle)) {
		SMB_VFS_HANDLE_GET_DATA(handle, snapshots, struct snapshot_list,
					return NULL);
		return snapshots;
	}

	SMB_VFS_HANDLE_FREE_DATA(handle);

	/* initialize our result */
	initial_size = sizeof(*snapshots) + 10 * sizeof(snapshots->entries[0]);
	snapshots = talloc_size(handle->conn, initial_size);

	if (snapshots == NULL) {
		DEBUG(0,("shadow_copy_zfs_list_snapshots: out of memory"
			 "(requested %d bytes)\n", initial_size));
		goto error;
	}

	snapshots->mountpoint = NULL;
	snapshots->num_entries = 0;

	/* get our zfs handle */
	fs = lp_parm_const_string(SNUM(handle->conn), "shadow", "filesystem",
				  NULL);

	if (fs == NULL) {
		DEBUG(0,("shadow_copy_zfs_list_snapshots: 'shadow:filesystem' "
			 "config parameter not defined for share [%s]\n",
			 volume_label(SNUM(handle->conn))));
		goto error;
	}

	libzfs = libzfs_init();

	if (!libzfs) {
		DEBUG(0,("shadow_copy_zfs_list_snapshots: error opening "
			 "libzfs: %s\n", strerror(errno)));
		goto error;
	}

	zfs = zfs_open(libzfs, fs, ZFS_TYPE_DATASET);

	if (!zfs) {
		DEBUG(0,("shadow_copy_zfs_list_snapshots: error opening "
			 "filesystem '%s': %s\n", fs, strerror(errno)));
		goto error;
	}

	/* get mountpoint */
	snapshots->mountpoint = talloc_size(snapshots, ZFS_MAXPROPLEN + 1);

	if (snapshots->mountpoint == NULL) {
		DEBUG(0,("shadow_copy_zfs_list_snapshots: out of memory "
			 "(requested %d bytes)\n",  ZFS_MAXPROPLEN + 1));
		goto error;
	}

	rc = zfs_prop_get(zfs, ZFS_PROP_MOUNTPOINT, snapshots->mountpoint,
			  talloc_get_size(snapshots->mountpoint), NULL, NULL,
			  0, 0);

	if (rc != 0) {
		DEBUG(0,("shadow_copy_zfs_list_snapshots: error getting "
			 "mountpoint for '%s': %s\n", fs, strerror(errno)));
		goto error;
	}

	/* get snapshots */
	iter_info.snapshots = snapshots;
	iter_info.inclusions = lp_parm_string_list(SNUM(handle->conn), "shadow",
						   "include", empty_list);
	iter_info.exclusions = lp_parm_string_list(SNUM(handle->conn), "shadow",
						   "exclude", empty_list);

	if (iter_info.inclusions == NULL) {
		DEBUG(0,("shadow_copy_zfs_list_snapshots: error getting "
			 "shadow:include parameter\n"));
		goto error;
	}

	if (iter_info.exclusions == NULL) {
		DEBUG(0,("shadow_copy_zfs_list_snapshots: error getting "
			 "shadow:exclude parameter\n"));
		goto error;
	}

	rc = zfs_iter_snapshots(zfs, shadow_copy_zfs_add_snapshot, &iter_info);

	if (rc != 0) {
		DEBUG(0,("shadow_copy_zfs_list_snapshots: error getting "
			 "snapshots for '%s': %s\n", fs, strerror(errno)));
		goto error;
	}

	snapshots = iter_info.snapshots;
	time(&snapshots->timestamp);

	/* sort by date, so we can use bsearch for faster lookup */
	shadow_copy_zfs_sort_data(handle, snapshots);

	/* cache the info */
	SMB_VFS_HANDLE_SET_DATA(handle, snapshots,
				shadow_copy_zfs_free_snapshots,
				struct snapshot_list, return NULL);

	goto done;

error:
	TALLOC_FREE(snapshots);

done:
	if (zfs)
		zfs_close(zfs);
	if (libzfs)
		libzfs_fini(libzfs);

	return snapshots;
}

/*
  convert a filename from a share relative path, to a path in the
  snapshot directory
 */
static char *convert_shadow_zfs_name(vfs_handle_struct *handle,
				     const char *fname, const char *gmt_path,
				     const bool incl_rel)
{
	TALLOC_CTX *tmp_ctx = talloc_new(handle->data);
	struct snapshot_list *snapshots;
	struct snapshot_entry entry_buf, *entry = &entry_buf;
	const char *relpath, *mpoffset, *mountpoint, *snapshot;
	size_t mplen;
	char *ret, *prefix;
	unsigned idx;

	/* get the snapshot info */
	snapshots = shadow_copy_zfs_list_snapshots(handle, False);
	if (snapshots == NULL) {
		talloc_free(tmp_ctx);
		return NULL;
	}

	/* get the mountpoint */
	mountpoint = snapshots->mountpoint;
	mplen = strlen(mountpoint);
	mpoffset = handle->conn->connectpath + mplen;

	/* some sanity checks */
	if (strncmp(mountpoint, handle->conn->connectpath, mplen) != 0 ||
	    (handle->conn->connectpath[mplen] != 0 &&
	     handle->conn->connectpath[mplen] != '/')) {
		DEBUG(0,("convert_shadow_zfs_name: mountpoint %s is not a "
			 "parent of %s\n", mountpoint,
			 handle->conn->connectpath));
		talloc_free(tmp_ctx);
		return NULL;
	}

	/* check if we've already normalized this */
	prefix = talloc_asprintf(tmp_ctx, "%s/%s/", mountpoint,
				 SHADOW_COPY_ZFS_SNAP_DIR);
	if (strncmp(fname, prefix, (talloc_get_size(prefix)-1)) == 0) {
		/* this looks like as we have already normalized it, leave it
		   untouched
		*/
		talloc_free(tmp_ctx);
		return talloc_strdup(handle->data, fname);
	}

	if (strncmp(fname, "@GMT-", 5) != 0) {
		fname = shadow_copy_zfs_normalise_path(tmp_ctx, fname, gmt_path);
		if (fname == NULL) {
			talloc_free(tmp_ctx);
			return NULL;
		}
	}

	/* get snapshot name */
	strlcpy(entry->label, fname, GMT_NAME_LEN+1);
	snapshot = bsearch(&entry, snapshots->entries, snapshots->num_entries,
			   sizeof(snapshots->entries[0]), snapshots->cmpfunc);
	for (idx = 0; idx < snapshots->num_entries; idx++) {
		if (strncmp(fname, snapshots->entries[idx]->label, GMT_NAME_LEN)
				== 0) {
			snapshot = snapshots->entries[idx]->name;
			break;
		}
	}

	if (snapshot == NULL) {
		DEBUG(1,("convert_shadow_zfs_name: no snapshot found for %s\n",
			 fname));
		talloc_free(tmp_ctx);
		return NULL;
	}

	/* assemble the new path */
	relpath = fname + GMT_NAME_LEN;

	if (*relpath == '/') relpath++;
	if (*mpoffset == '/') mpoffset++;

	ret = talloc_asprintf(handle->data, "%s/%s/%s%s%s%s%s",
			      mountpoint,
			      SHADOW_COPY_ZFS_SNAP_DIR,
			      snapshot,
			      *mpoffset ? "/" : "",
			      mpoffset,
			      *relpath ? "/" : "",
			      incl_rel ? relpath : "");
	DEBUG(6,("convert_shadow_zfs_name: '%s' -> '%s'\n", fname, ret));
	talloc_free(tmp_ctx);
	return ret;
}

static int shadow_copy_zfs_rename(vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname_src,
				  const struct smb_filename *smb_fname_dst)
{
	if (shadow_copy_zfs_match_name(smb_fname_src->base_name, NULL)) {
		errno = EXDEV;
		return -1;
	}
	SHADOW2_NEXT2_SMB_FNAME(RENAME,
				(handle, smb_fname_src, smb_fname_dst));
}

static int shadow_copy_zfs_symlink(vfs_handle_struct *handle,
				   const char *oldname, const char *newname)
{
	SHADOW2_NEXT2(SYMLINK, (handle, oldname, newname));
}

static int shadow_copy_zfs_link(vfs_handle_struct *handle, const char *oldname,
				const char *newname)
{
	SHADOW2_NEXT2(LINK, (handle, oldname, newname));
}

static int shadow_copy_zfs_open(vfs_handle_struct *handle,
				struct smb_filename *smb_fname,
				files_struct *fsp, int flags, mode_t mode)
{
	SHADOW2_NEXT_SMB_FNAME(OPEN,
			       (handle, smb_fname, fsp, flags, mode),
			       int, -1);
}

static SMB_STRUCT_DIR *shadow_copy_zfs_opendir(vfs_handle_struct *handle,
					       const char *fname,
					       const char *mask, uint32 attr)
{
	/*
	  Work around strange issue with 2008/Vista and later.

	  When showing the previous versions tab the client lists the shadow
	  copies, then does a bunch of file-info calls for each previous
	  version (snapshot), and then does a find_first2/find on the shadow
	  copy folder itself (@GMT-...). If that last find returns anything
	  other than an error, the Open and Copy buttons are not enabled and
	  the Restore does nothing. Hence this hack here to detect this
	  request and return a not-found error.
	*/
	if (mask && strlen(mask) == GMT_NAME_LEN && strncmp(mask, "@GMT-", 5) == 0) {
		DEBUG(10,("shadow_copy_zfs_opendir: name='%s'\n", fname));
		errno = ENOENT;
		return NULL;
	}

	SHADOW2_NEXT(OPENDIR, (handle, name, mask, attr), SMB_STRUCT_DIR *, NULL);
}

static int shadow_copy_zfs_stat(vfs_handle_struct *handle,
				struct smb_filename *smb_fname)
{
	SHADOW2_NEXT_SMB_FNAME(STAT, (handle, smb_fname), int, -1);
}

static int shadow_copy_zfs_lstat(vfs_handle_struct *handle,
				 struct smb_filename *smb_fname)
{
	SHADOW2_NEXT_SMB_FNAME(LSTAT, (handle, smb_fname), int, -1);
}

static int shadow_copy_zfs_unlink(vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname_in)
{
	struct smb_filename *smb_fname = NULL;
	NTSTATUS status;

	status = copy_smb_filename(talloc_tos(), smb_fname_in, &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		return -1;
	}

	SHADOW2_NEXT_SMB_FNAME(UNLINK, (handle, smb_fname), int, -1);
}

static int shadow_copy_zfs_chmod(vfs_handle_struct *handle, const char *fname,
				 mode_t mode)
{
	SHADOW2_NEXT(CHMOD, (handle, name, mode), int, -1);
}

static int shadow_copy_zfs_chown(vfs_handle_struct *handle, const char *fname,
				 uid_t uid, gid_t gid)
{
	SHADOW2_NEXT(CHOWN, (handle, name, uid, gid), int, -1);
}

static int shadow_copy_zfs_chdir(vfs_handle_struct *handle, const char *fname)
{
	SHADOW2_NEXT(CHDIR, (handle, name), int, -1);
}

static int shadow_copy_zfs_ntimes(vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname_in,
				  struct smb_file_time *ft)
{
	struct smb_filename *smb_fname = NULL;
	NTSTATUS status;

	status = copy_smb_filename(talloc_tos(), smb_fname_in, &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		return -1;
	}

	SHADOW2_NEXT_SMB_FNAME(NTIMES, (handle, smb_fname, ft), int, -1);
}

static int shadow_copy_zfs_readlink(vfs_handle_struct *handle,
				    const char *fname, char *buf, size_t bufsiz)
{
	SHADOW2_NEXT(READLINK, (handle, name, buf, bufsiz), int, -1);
}

static int shadow_copy_zfs_mknod(vfs_handle_struct *handle, const char *fname,
				 mode_t mode, SMB_DEV_T dev)
{
	SHADOW2_NEXT(MKNOD, (handle, name, mode, dev), int, -1);
}

static char *shadow_copy_zfs_realpath(vfs_handle_struct *handle,
				      const char *fname)
{
	const char *gmt;

	if (shadow_copy_zfs_match_name(fname, &gmt)
	    && (gmt[GMT_NAME_LEN] == '\0')) {
		char *copy;

		copy = talloc_strdup(talloc_tos(), fname);
		if (copy == NULL) {
			errno = ENOMEM;
			return NULL;
		}

		copy[gmt - fname] = '.';
		copy[gmt - fname + 1] = '\0';

		DEBUG(10, ("calling NEXT_REALPATH with %s\n", copy));
		SHADOW2_NEXT(REALPATH, (handle, name), char *,
			     NULL);
	}
	SHADOW2_NEXT(REALPATH, (handle, name), char *, NULL);
}

static const char *shadow_copy_zfs_connectpath(struct vfs_handle_struct *handle,
					       const char *fname)
{
	const char *gmt_start;
	char *ret;

	DEBUG(10, ("shadow_copy_zfs_connectpath called with %s\n", fname));

	if (!shadow_copy_zfs_match_name(fname, &gmt_start)) {
		return SMB_VFS_NEXT_CONNECTPATH(handle, fname);
	}

	ret = convert_shadow_zfs_name(handle, fname, gmt_start, False);
	DEBUG(6,("shadow_copy_zfs_connectpath: '%s' -> '%s'\n", fname, ret));
	return ret;
}

static NTSTATUS shadow_copy_zfs_get_nt_acl(vfs_handle_struct *handle,
					   const char *fname,
					   uint32 security_info,
					   struct security_descriptor **ppdesc)
{
	SHADOW2_NTSTATUS_NEXT(GET_NT_ACL, (handle, name, security_info, ppdesc),
			      NT_STATUS_ACCESS_DENIED);
}

static int shadow_copy_zfs_mkdir(vfs_handle_struct *handle,
				 const char *fname, mode_t mode)
{
	SHADOW2_NEXT(MKDIR, (handle, name, mode), int, -1);
}

static int shadow_copy_zfs_rmdir(vfs_handle_struct *handle,  const char *fname)
{
	SHADOW2_NEXT(RMDIR, (handle, name), int, -1);
}

static int shadow_copy_zfs_chflags(vfs_handle_struct *handle, const char *fname,
				   unsigned int flags)
{
	SHADOW2_NEXT(CHFLAGS, (handle, name, flags), int, -1);
}

static ssize_t shadow_copy_zfs_add_readonly_attr(vfs_handle_struct *handle,
						 struct smb_filename *smb_fname,
						 const char *fname,
						 const char *aname, void *value,
						 size_t size, ssize_t ret)
{
	struct smb_filename smb_fname_buf;
	DATA_BLOB blob;
	struct xattr_DOSATTRIB dosattrib;
	enum ndr_err_code ndr_err;

	/* only handling the basic dos attributes */
	if (strcmp(aname, SAMBA_XATTR_DOS_ATTRIB) != 0) {
		return ret;
	}

	if (!fname) {
		fname = smb_fname->base_name;
	}

	if (ret > 0) {
		/* we have attributes from the lower layer, so decode them */
		ZERO_STRUCT(blob);
		blob.data = (uint8_t *) value;
		blob.length = size;

		ndr_err = ndr_pull_struct_blob(&blob, talloc_tos(), &dosattrib,
				(ndr_pull_flags_fn_t) ndr_pull_xattr_DOSATTRIB);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(1, ("shadow_copy_zfs_add_readonly_attr: bad ndr "
				  "decode from EA on file %s: Error = %s\n",
				  fname, ndr_errstr(ndr_err)));
			return -1;
		}

		if (dosattrib.version != 3) {
			DEBUG(1, ("shadow_copy_zfs_add_readonly_attr: expected "
				  "dosattrib version 3, got %d\n",
				  (int) dosattrib.version));
			return -1;
		}
		if (!(dosattrib.info.info3.valid_flags & XATTR_DOSINFO_ATTRIB)) {
			DEBUG(10, ("shadow_copy_zfs_add_readonly_attr: "
				   "XATTR_DOSINFO_ATTRIB not valid, ignoring"
				   "\n"));
			return ret;
		}
	} else {
		/* lower layer returned error, so create attrs from stat */
		if (smb_fname == NULL) {
			smb_fname = &smb_fname_buf;

			smb_fname->base_name = (char *) fname;
			smb_fname->stream_name = NULL;
			smb_fname->original_lcomp = NULL;
			ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
			if (ret < 0) {
				DEBUG(1, ("shadow_copy_zfs_add_readonly_attr: "
					  "error on stat on file %s: %s\n",
					  fname, strerror(errno)));
				return ret;
			}
		}

		ZERO_STRUCT(dosattrib);
		dosattrib.version = 3;
		dosattrib.info.info3.valid_flags = XATTR_DOSINFO_ATTRIB;
		dosattrib.info.info3.attrib = dos_mode_msdfs(handle->conn,
							     smb_fname);
	}

	/* add read-only attribute */
	dosattrib.info.info3.attrib |= FILE_ATTRIBUTE_READONLY;
	dosattrib.info.info3.attrib &= ~FILE_ATTRIBUTE_NORMAL;

	DEBUG(10,("shadow_copy_zfs_add_readonly_attr: new dosmode = 0x%x\n",
		  dosattrib.info.info3.attrib));

	/* (re)encode attributes */
	ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &dosattrib,
			(ndr_push_flags_fn_t) ndr_push_xattr_DOSATTRIB);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("shadow_copy_zfs_add_readonly_attr: bad ndr "
			  "encode on file %s: Error = %s\n",
			  fname, ndr_errstr(ndr_err)));
		return -1;
	}

	if (blob.length > size) {
		DEBUG(1, ("shadow_copy_zfs_add_readonly_attr: ndr "
			  "encode on file %s too big: len = %u, buf = %u\n",
			  fname, blob.length, size));
	}

	memcpy(value, blob.data, blob.length);
	talloc_free(blob.data);

	return blob.length;
}

static ssize_t shadow_copy_zfs_getxattr(vfs_handle_struct *handle,
					const char *fname, const char *aname,
					void *value, size_t size)
{
	SHADOW2_XATTR_NEXT(GETXATTR, (handle, name, aname, value, size),
			   ssize_t, -1,
			   ret = shadow_copy_zfs_add_readonly_attr(handle, NULL,
								   name2, aname,
								   value, size,
								   ret));
}

static ssize_t shadow_copy_zfs_lgetxattr(vfs_handle_struct *handle,
					 const char *fname, const char *aname,
					 void *value, size_t size)
{
	SHADOW2_XATTR_NEXT(LGETXATTR, (handle, name, aname, value, size),
			   ssize_t, -1,
			   ret = shadow_copy_zfs_add_readonly_attr(handle, NULL,
								   name2, aname,
								   value, size,
								   ret));
}

static ssize_t shadow_copy_zfs_fgetxattr(struct vfs_handle_struct *handle,
					 struct files_struct *fsp,
					 const char *aname, void *value,
					 size_t size)
{
	int ret = SMB_VFS_NEXT_FGETXATTR(handle, fsp, aname, value, size);
	if (shadow_copy_zfs_match_name(fsp->fsp_name->base_name, NULL)) {
		ret = shadow_copy_zfs_add_readonly_attr(handle, fsp->fsp_name,
							NULL, aname, value,
							size, ret);
	}
	return ret;
}

static ssize_t shadow_copy_zfs_listxattr(struct vfs_handle_struct *handle,
					 const char *fname, char *list,
					 size_t size)
{
	SHADOW2_NEXT(LISTXATTR, (handle, name, list, size), ssize_t, -1);
}

static int shadow_copy_zfs_removexattr(struct vfs_handle_struct *handle,
				       const char *fname, const char *aname)
{
	SHADOW2_NEXT(REMOVEXATTR, (handle, name, aname), int, -1);
}

static int shadow_copy_zfs_lremovexattr(struct vfs_handle_struct *handle,
					const char *fname, const char *aname)
{
	SHADOW2_NEXT(LREMOVEXATTR, (handle, name, aname), int, -1);
}

static int shadow_copy_zfs_setxattr(struct vfs_handle_struct *handle,
				    const char *fname, const char *aname,
				    const void *value, size_t size, int flags)
{
	SHADOW2_NEXT(SETXATTR, (handle, name, aname, value, size, flags), int, -1);
}

static int shadow_copy_zfs_lsetxattr(struct vfs_handle_struct *handle,
				     const char *fname, const char *aname,
				     const void *value, size_t size, int flags)
{
	SHADOW2_NEXT(LSETXATTR, (handle, name, aname, value, size, flags), int, -1);
}

static int shadow_copy_zfs_chmod_acl(vfs_handle_struct *handle,
				     const char *fname, mode_t mode)
{
	SHADOW2_NEXT(CHMOD_ACL, (handle, name, mode), int, -1);
}

static int shadow_copy_zfs_get_shadow_copy_zfs_data(vfs_handle_struct *handle,
						    files_struct *fsp,
						    struct shadow_copy_data
						    *shadow_copy_zfs_data,
						    bool labels)
{
	struct snapshot_list *snapshots;
	unsigned idx;

	/* Get the list of snapshots.

	   The client usually sends two requests for the shadow data, the first
	   one with labels == False in order to get the number of shadow copies
	   available, and the second with labels == True. Since we really just
	   want to serve the same list on the second request we only invalidate
	   the cache when labels == False.

	   But just to be safe, in case a client always requests labels, we
	   also limit the max time before we force a reload.
	 */
	snapshots = shadow_copy_zfs_list_snapshots(handle, !labels);
	if (snapshots == NULL) {
		return -1;
	}

	if (labels &&
	    difftime(time(NULL), snapshots->timestamp) > MAX_CACHE_TIME) {
		snapshots = shadow_copy_zfs_list_snapshots(handle, True);
		if (snapshots == NULL) {
			return -1;
		}
	}

	/* copy the info to the output data. Note: data is already sorted */
	shadow_copy_zfs_data->num_volumes = snapshots->num_entries;
	shadow_copy_zfs_data->labels = NULL;

	if (labels) {
		shadow_copy_zfs_data->labels =
			talloc_array(shadow_copy_zfs_data,
				     SHADOW_COPY_LABEL,
				     shadow_copy_zfs_data->num_volumes);

		if (shadow_copy_zfs_data->labels == NULL) {
			DEBUG(0,("shadow_copy_zfs: out of memory\n"));
			return -1;
		}

		for (idx = 0; idx < snapshots->num_entries; idx++) {
			strlcpy(shadow_copy_zfs_data->labels[idx],
				snapshots->entries[idx]->label,
				sizeof(shadow_copy_zfs_data->labels[0]));
		}
	}

	return 0;
}

static struct vfs_fn_pointers vfs_shadow_copy_zfs_fns = {
	.opendir = shadow_copy_zfs_opendir,
	.mkdir = shadow_copy_zfs_mkdir,
	.rmdir = shadow_copy_zfs_rmdir,
	.chflags = shadow_copy_zfs_chflags,
	.getxattr = shadow_copy_zfs_getxattr,
	.lgetxattr = shadow_copy_zfs_lgetxattr,
	.fgetxattr = shadow_copy_zfs_fgetxattr,
	.listxattr = shadow_copy_zfs_listxattr,
	.removexattr = shadow_copy_zfs_removexattr,
	.lremovexattr = shadow_copy_zfs_lremovexattr,
	.setxattr = shadow_copy_zfs_setxattr,
	.lsetxattr = shadow_copy_zfs_lsetxattr,
	.open_fn = shadow_copy_zfs_open,
	.rename = shadow_copy_zfs_rename,
	.stat = shadow_copy_zfs_stat,
	.lstat = shadow_copy_zfs_lstat,
	.unlink = shadow_copy_zfs_unlink,
	.chmod = shadow_copy_zfs_chmod,
	.chown = shadow_copy_zfs_chown,
	.chdir = shadow_copy_zfs_chdir,
	.ntimes = shadow_copy_zfs_ntimes,
	.symlink = shadow_copy_zfs_symlink,
	.vfs_readlink = shadow_copy_zfs_readlink,
	.link = shadow_copy_zfs_link,
	.mknod = shadow_copy_zfs_mknod,
	.realpath = shadow_copy_zfs_realpath,
	.connectpath = shadow_copy_zfs_connectpath,
	.get_nt_acl = shadow_copy_zfs_get_nt_acl,
	.chmod_acl = shadow_copy_zfs_chmod_acl,
	.get_shadow_copy_data = shadow_copy_zfs_get_shadow_copy_zfs_data,
};

NTSTATUS vfs_shadow_copy_zfs_init(void);
NTSTATUS vfs_shadow_copy_zfs_init(void)
{
	NTSTATUS ret;

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "shadow_copy_zfs",
			       &vfs_shadow_copy_zfs_fns);

	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_shadow_copy_zfs_debug_level = debug_add_class("shadow_copy_zfs");
	if (vfs_shadow_copy_zfs_debug_level == -1) {
		vfs_shadow_copy_zfs_debug_level = DBGC_VFS;
		DEBUG(0, ("%s: Couldn't register custom debugging class!\n",
			"vfs_shadow_copy_zfs_init"));
	} else {
		DEBUG(10, ("%s: Debug class number of '%s': %d\n",
			   "vfs_shadow_copy_zfs_init","shadow_copy_zfs",
			   vfs_shadow_copy_zfs_debug_level));
	}

	return ret;
}
