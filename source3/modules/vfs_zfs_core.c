/*
 *  Unix SMB/CIFS implementation.
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "includes.h"
#include "smbd/globals.h"
#include "smbd/smbd.h"
#include "libcli/security/security.h"
#include "auth.h"
#include "privileges.h"
#include "nfs4_acls.h"
#include "system/filesys.h"

#include "lib/util/tevent_ntstatus.h"
#include "modules/smb_libzfs.h"

static int vfs_zfs_core_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_zfs_core_debug_level

struct zfs_core_config_data {
	struct dataset_list *dl;
	bool zfs_space_enabled;
	bool zfs_quota_enabled;
	bool zfs_auto_create;
	const char *dataset_auto_quota;
	uint64_t base_user_quota;
};

static struct zfs_dataset *smbfname_to_ds(const struct connection_struct *conn,
					  struct dataset_list *dl,
					  const struct smb_filename *smb_fname)
{
	int ret;
	const SMB_STRUCT_STAT *psbuf = NULL;
	struct zfs_dataset *child = NULL;
	char *full_path = NULL;
	char *to_free = NULL;
	char path[PATH_MAX + 1];
	int len;

	if (VALID_STAT(smb_fname->st)) {
		psbuf = &smb_fname->st;
	}
	else {
		ret = vfs_stat_smb_basename(discard_const(conn), smb_fname,
					    discard_const(psbuf));
		if (ret != 0) {
			DBG_ERR("Failed to stat() %s: %s\n",
				smb_fname_str_dbg(smb_fname), strerror(errno));
			return NULL;
		}
	}

        if (psbuf->st_ex_dev == dl->root->devid) {
                return dl->root;
        }
        for (child=dl->children; child; child=child->next) {
                if (child->devid == psbuf->st_ex_dev) {
                        return child;
                }
        }

        /*
         * Our current cache of datasets does not contain the path in
         * question. Use libzfs to try to get it. Allocate under
         * memory context of our dataset list.
         */
	len = full_path_tos(discard_const(conn->cwd_fsp->fsp_name->base_name),
			    smb_fname->base_name,
			    path, sizeof(path),
			    &full_path, &to_free);
        if (len == -1) {
                DBG_ERR("Could not allocate memory in full_path_tos.\n");
                return NULL;
	}

        child = smb_zfs_path_get_dataset(dl->root->zhandle->lz,
					 dl, path, true, false);
	TALLOC_FREE(to_free);
        if (child != NULL) {
                DLIST_ADD(dl->children, child);
                return child;
        }

        DBG_ERR("No dataset found for %s with device id: %lu\n",
                path, psbuf->st_ex_dev);
        errno = ENOENT;
        return NULL;
}

static uint64_t zfs_core_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	uint64_t res;
	struct zfs_core_config_data *config = NULL;
	struct zfs_dataset *ds = NULL;
	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				return -1);

	if (!config->zfs_space_enabled) {
		return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);
	}

	ds = smbfname_to_ds(handle->conn, config->dl, smb_fname);
	if (ds == NULL) {
		DBG_ERR("Failed to retrive ZFS dataset handle on %s: %s\n",
			smb_fname_str_dbg(smb_fname), strerror(errno));
	}

	res = smb_zfs_disk_free(ds->zhandle, bsize, dfree, dsize);
	if (res == -1) {
		res = SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);
	}

	DBG_DEBUG("bsize = %lu, dfree: %lu, dsize: %lu \n",
		  bsize, dfree, dsize);

	return res;
}

static int zfs_core_get_quota(struct vfs_handle_struct *handle,
                                const struct smb_filename *smb_fname,
                                enum SMB_QUOTA_TYPE qtype,
                                unid_t id,
                                SMB_DISK_QUOTA *qt)

{
	int ret;
	struct zfs_core_config_data *config = NULL;
	struct zfs_dataset *ds = NULL;
	uint64_t hardlimit, usedspace;
	hardlimit = usedspace = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				return -1);

	if (!config->zfs_quota_enabled) {
		DBG_DEBUG("Quotas disabled in zfs_core configuration.\n");
		errno = ENOSYS;
		return -1;
	}

	ds = smbfname_to_ds(handle->conn, config->dl, smb_fname);
	if (ds == NULL) {
		DBG_ERR("Failed to retrive ZFS dataset handle on %s: %s\n",
			smb_fname_str_dbg(smb_fname), strerror(errno));
	}

	switch (qtype) {
	case SMB_USER_QUOTA_TYPE:
	case SMB_USER_FS_QUOTA_TYPE:
		//passing -1 to quotactl means that the current UID should be used. Do the same.
		if (id.uid == -1) {
			uid_t current_user = geteuid();
			become_root();
			ret = smb_zfs_get_userspace_quota(ds->zhandle,
							  current_user,
							  SMBZFS_USER,
							  &hardlimit,
							  &usedspace);
			unbecome_root();
		}
		else {
			become_root();
			ret = smb_zfs_get_userspace_quota(ds->zhandle,
							  id.uid,
							  SMBZFS_USER,
							  &hardlimit,
							  &usedspace);
			unbecome_root();
		}
		break;
	case SMB_GROUP_QUOTA_TYPE:
	case SMB_GROUP_FS_QUOTA_TYPE:
		become_root();
		ret = smb_zfs_get_userspace_quota(ds->zhandle,
						  id.gid,
						  SMBZFS_GROUP,
						  &hardlimit,
						  &usedspace);
		unbecome_root();
		break;
	default:
		DBG_ERR("Unrecognized quota type.\n");
		ret = -1;
		break;
	}

	ZERO_STRUCTP(qt);
	qt->bsize = 1024;
	qt->hardlimit = hardlimit;
	qt->softlimit = hardlimit;
	qt->curblocks = usedspace;
	qt->ihardlimit = hardlimit;
	qt->isoftlimit = hardlimit;
	qt->curinodes = usedspace;
	qt->qtype = qtype;
	qt->qflags = QUOTAS_DENY_DISK|QUOTAS_ENABLED;

        DBG_INFO("zfs_core_get_quota: hardlimit: (%lu), usedspace: (%lu)\n", qt->hardlimit, qt->curblocks);

        return ret;
}

static int zfs_core_set_quota(struct vfs_handle_struct *handle,
			enum SMB_QUOTA_TYPE qtype, unid_t id,
			SMB_DISK_QUOTA *qt)
{
	struct zfs_core_config_data *config = NULL;
	int ret;
	bool is_disk_op = false;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				return -1);

	if (!config->zfs_quota_enabled) {
		DBG_DEBUG("Quotas disabled in zfs_core configuration.\n");
		errno = ENOSYS;
		return -1;
	}

	is_disk_op = security_token_has_privilege(
			handle->conn->session_info->security_token,
			SEC_PRIV_DISK_OPERATOR);

	if (!is_disk_op) {
		errno = EPERM;
		return -1;
	}

	switch (qtype) {
	case SMB_USER_QUOTA_TYPE:
	case SMB_USER_FS_QUOTA_TYPE:
		DBG_INFO("zfs_core_set_quota: quota type: (%d), "
			 "id: (%d), h-limit: (%lu), s-limit: (%lu)\n",
			 qtype, id.uid, qt->hardlimit, qt->softlimit);
		become_root();
		ret = smb_zfs_set_userspace_quota(config->dl->root->zhandle,
						  id.uid, qtype, qt->hardlimit);
		unbecome_root();
		break;
	case SMB_GROUP_QUOTA_TYPE:
	case SMB_GROUP_FS_QUOTA_TYPE:
		DBG_INFO("zfs_core_set_quota: quota type: (%d), "
			 "id: (%d), h-limit: (%lu), s-limit: (%lu)\n",
			 qtype, id.gid, qt->hardlimit, qt->softlimit);
		become_root();
		ret = smb_zfs_set_userspace_quota(config->dl->root->zhandle,
						  id.gid, qtype, qt->hardlimit);
		unbecome_root();
		break;
	default:
		DBG_ERR("Received unknown quota type.\n");
		ret = -1;
		break;
	}

	return ret;
}

static int create_zfs_connectpath(vfs_handle_struct *handle,
				  struct zfs_core_config_data *config,
				  const char *user)
{
	bool do_chown;
	int rv;
	NTSTATUS status;
	char *parent = NULL;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	struct smblibzfshandle *libzp = NULL;
	struct dataset_list *ds_list = NULL;
	struct zfs_dataset *ds = NULL;

	if (access(handle->conn->connectpath, F_OK) == 0) {
		DBG_INFO("Connectpath for %s already exists. "
			 "skipping dataset creation\n",
			 handle->conn->connectpath);
		TALLOC_FREE(tmp_ctx);
		return 0;
	}

	rv = get_smblibzfs_handle(tmp_ctx, &libzp);
	if (rv != 0) {
		DBG_ERR("Failed to obtain libzfshandle on connectpath: %s\n",
			strerror(errno));
		return -1;
	}

	rv = smb_zfs_create_dataset(tmp_ctx, libzp, handle->conn->connectpath,
				    config->dataset_auto_quota, &ds_list, true);
	if (rv !=0) {
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	/*
	 * chdir() to root of newly-created datasets is required due to
	 * wide-link related access checks in open_internal_dirfsp().
	 */
	rv = chdir(ds_list->root->mountpoint);
	if (rv != 0) {
		DBG_ERR("failed to chdir into [%s]: %s\n",
			ds_list->root->mountpoint, strerror(errno));
		TALLOC_FREE(tmp_ctx);
		return rv;
	}
	for (ds = ds_list->children; ds; ds = ds->next) {
		struct smb_filename *child_smbfname = NULL;
		struct files_struct *fsp = NULL;

		child_smbfname = synthetic_smb_fname(talloc_tos(),
						     ds->mountpoint,
						     NULL,
						     NULL,
						     0,
						     0);

		status = open_internal_dirfsp(handle->conn,
					      child_smbfname,
					      O_RDONLY,
					      &fsp);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(tmp_ctx);
			DBG_ERR("Failed to open internal dirfsp for %s: %s\n",
				ds->mountpoint, strerror(errno));
			return -1;
		}
		status = inherit_new_acl(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			fsp_free(fsp);
			TALLOC_FREE(tmp_ctx);
			DBG_ERR("Failed to create inherited ACL for %s: %s\n",
				ds->mountpoint, strerror(errno));
			return -1;
		}
		fsp_free(fsp);
		TALLOC_FREE(child_smbfname);
	}
	rv = chdir(handle->conn->connectpath);
	if (rv != 0) {
		DBG_ERR("failed to chdir into [%s]: %s\n",
			ds_list->root->mountpoint, strerror(errno));
		TALLOC_FREE(tmp_ctx);
		return rv;
	}

	do_chown = lp_parm_bool(SNUM(handle->conn), "zfs_core",
			        "chown_homedir", true);
	if (do_chown) {
		struct passwd *current_user = Get_Pwnam_alloc(tmp_ctx, user);
		if ( !current_user ) {
			DBG_ERR("Get_Pwnam_alloc failed for (%s).\n", user);
			TALLOC_FREE(tmp_ctx);
			return -1;
		}
		rv = chown(handle->conn->connectpath,
			   current_user->pw_uid,
			   current_user->pw_gid);
		if (rv < 0) {
			DBG_ERR("Failed to chown (%s) to (%u:%u)\n",
				handle->conn->connectpath,
				current_user->pw_uid, getegid() );
		}
	}
	TALLOC_FREE(tmp_ctx);
	return rv;
}

/*
 * Fake the presence of a base quota. Check if user quota already exists.
 * If it exists, then we assume that the base quota has either already been set
 * or it has been modified by the admin. In either case, do nothing.
 */

static int set_base_user_quota(vfs_handle_struct *handle,
			       struct zfs_core_config_data *config,
			       const char *user)
{
	int ret;
	uint64_t existing_quota, usedspace, base_quota;
	existing_quota = usedspace = 0;
	uid_t current_user = nametouid(user);

	if (current_user == -1) {
		DBG_ERR("Failed to convert (%s) to uid.\n", user);
		return -1;
	}
	else if (current_user == 0) {
		DBG_INFO("Refusing to set user quota on uid 0.\n");
		return -1;
	}

	ret = smb_zfs_get_userspace_quota(config->dl->root->zhandle,
					  current_user,
					  SMBZFS_USER,
					  &existing_quota,
					  &usedspace);
	if (ret != 0) {
		DBG_ERR("Failed to get base quota uid: (%u), path (%s)\n",
			current_user, handle->conn->connectpath );
		return -1;
	}

	DBG_INFO("set_base_user_quote: uid (%u), quota (%lu)\n",
		 current_user, base_quota);

	if ( !existing_quota ) {
		ret = smb_zfs_set_userspace_quota(config->dl->root->zhandle,
						  current_user,
						  SMBZFS_USER,
						  config->base_user_quota);
		if (ret != 0) {
			DBG_ERR("Failed to set base quota uid: (%u), "
				"path (%s), value (%lu)\n", current_user,
				handle->conn->connectpath, base_quota );
		}
	}
	return ret;
}

static int zfs_core_connect(struct vfs_handle_struct *handle,
			    const char *service, const char *user)
{
	struct zfs_core_config_data *config = NULL;
	int ret;
	const char *dataset_auto_quota = NULL;
	const char *base_quota_str = NULL;
	struct smblibzfshandle *lz = NULL;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	config = talloc_zero(handle->conn, struct zfs_core_config_data);
	if (!config) {
		DEBUG(0, ("talloc_zero() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	/*
	 * Check if we need to automatically create a new ZFS dataset
	 * before falling through to SMB_VFS_NEXT_CONNECT.
	 */
	config->zfs_auto_create = lp_parm_bool(SNUM(handle->conn),
			"zfs_core", "zfs_auto_create", false);
	config->dataset_auto_quota = lp_parm_const_string(SNUM(handle->conn),
			"zfs_core", "dataset_auto_quota", NULL);

	if (config->zfs_auto_create) {
		ret = create_zfs_connectpath(handle, config, user);
		if (ret < 0) {
			return -1;
		}
	}

	ret = conn_zfs_init(handle->conn->sconn,
			    handle->conn->connectpath,
			    &lz,
			    &config->dl);
	if (ret != 0) {
		DBG_ERR("Failed to initialize ZFS data: %s\n",
			strerror(errno));
		return ret;
	}

	base_quota_str = lp_parm_const_string(SNUM(handle->conn),
			"zfs_core", "base_user_quota", NULL);

	if (base_quota_str != NULL) {
		config->base_user_quota = (conv_str_size(base_quota_str) / 1024);
		set_base_user_quota(handle, config, user);
        }

	if (config->dl->root->properties->casesens == SMBZFS_INSENSITIVE) {
		DBG_INFO("zfs_core: case insensitive dataset detected, "
			 "automatically adjusting case sensitivity settings.\n");
		lp_do_parameter(SNUM(handle->conn),
				"case sensitive", "yes");
		handle->conn->case_sensitive = True;
	}

	config->zfs_space_enabled = lp_parm_bool(SNUM(handle->conn),
			"zfs_core", "zfs_space_enabled", true);

	config->zfs_quota_enabled = lp_parm_bool(SNUM(handle->conn),
			"zfs_core", "zfs_quota_enabled", true);

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct zfs_core_config_data,
				return -1);

	return 0;
}

static struct vfs_fn_pointers zfs_core_fns = {
	.connect_fn = zfs_core_connect,
	.get_quota_fn = zfs_core_get_quota,
	.set_quota_fn = zfs_core_set_quota,
	.disk_free_fn = zfs_core_disk_free
};

NTSTATUS vfs_zfs_core_init(TALLOC_CTX *);
NTSTATUS vfs_zfs_core_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "zfs_core",
					&zfs_core_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	vfs_zfs_core_debug_level = debug_add_class("zfs_core");
	if (vfs_zfs_core_debug_level == -1) {
		vfs_zfs_core_debug_level = DBGC_VFS;
		DBG_ERR("%s: Couldn't register custom debugging class!\n",
			"vfs_zfs_core_init");
	} else {
		DBG_DEBUG("%s: Debug class number of '%s': %d\n",
		"vfs_zfs_core_init","zfs_core",vfs_zfs_core_debug_level);
	}
	return ret;
}
