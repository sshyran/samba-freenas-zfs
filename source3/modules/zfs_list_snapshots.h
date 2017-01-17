/*
 * shadow_copy_zfs: a shadow copy module (second implementation)
 *
 * Copyright (C) Andrew Tridgell   2007 (portions taken from shadow_copy_zfs)
 * Copyright (C) Ed Plese          2009
 * Copyright (C) Volker Lendecke   2011
 * Copyright (C) Christian Ambach  2011
 * Copyright (C) Michael Adam      2013
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


#ifndef __ZFS_LIST_SNAPSHOTS_H
#define __ZFS_LIST_SNAPSHOTS_H

struct iter_info
{
    struct snapshot_list *snapshots;
    const char **inclusions;
    const char **exclusions;
};

struct snapshot_entry
{
    char label[25];
    char name[1];
};

struct snapshot_list
{
    time_t timestamp;
    char *mountpoint;
    int (*cmpfunc)(const void *, const void *);
    size_t num_entries;
    struct snapshot_entry *entries[1];
};

struct snapshot_list *shadow_copy_zfs_list_snapshots(TALLOC_CTX *mem_ctx,
    const char *fs, const char **inclusions, const char **exclusions);


#endif	/* __ZFS_LIST_SNAPSHOTS_H */
