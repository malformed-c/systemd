/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "escape.h"
#include "mount-list.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"

const char* mount_entry_path(const MountEntry *p) {
        assert(p);

        /* Returns the path of this bind mount. If the malloc()-allocated ->path_buffer field is set we return that,
         * otherwise the stack/static ->path field is returned. */

        return p->path_malloc ?: p->path_const;
}

const char* mount_entry_unprefixed_path(const MountEntry *p) {
        assert(p);

        /* Returns the unprefixed path (ie: before prefix_where_needed() ran), if any */

        return p->unprefixed_path_malloc ?: p->unprefixed_path_const ?: mount_entry_path(p);
}

void mount_entry_consume_prefix(MountEntry *p, char *new_path) {
        assert(p);
        assert(p->path_malloc || p->path_const);
        assert(new_path);

        /* Saves current path in unprefixed_ variable, and takes over new_path */

        free_and_replace(p->unprefixed_path_malloc, p->path_malloc);
        /* If we didn't have a path on the heap, then it's a static one */
        if (!p->unprefixed_path_malloc)
                p->unprefixed_path_const = p->path_const;
        p->path_malloc = new_path;
        p->has_prefix = true;
}

bool mount_entry_read_only(const MountEntry *p) {
        assert(p);

        return p->read_only || IN_SET(p->mode, MOUNT_READ_ONLY, MOUNT_INACCESSIBLE);
}

bool mount_entry_noexec(const MountEntry *p) {
        assert(p);

        return p->noexec || IN_SET(p->mode, MOUNT_NOEXEC, MOUNT_INACCESSIBLE, MOUNT_PRIVATE_SYSFS, MOUNT_BIND_SYSFS, MOUNT_PROCFS, MOUNT_PRIVATE_CGROUP2FS);
}

bool mount_entry_exec(const MountEntry *p) {
        assert(p);

        return p->exec || p->mode == MOUNT_EXEC;
}

const char* mount_entry_source(const MountEntry *p) {
        assert(p);

        return p->source_malloc ?: p->source_const;
}

const char* mount_entry_options(const MountEntry *p) {
        assert(p);

        return p->options_malloc ?: p->options_const;
}

void mount_entry_done(MountEntry *p) {
        assert(p);

        p->path_malloc = mfree(p->path_malloc);
        p->unprefixed_path_malloc = mfree(p->unprefixed_path_malloc);
        p->source_malloc = mfree(p->source_malloc);
        p->options_malloc = mfree(p->options_malloc);
        p->overlay_layers = strv_free(p->overlay_layers);
        verity_settings_done(&p->verity);
}

void mount_list_done(MountList *ml) {
        assert(ml);

        FOREACH_ARRAY(m, ml->mounts, ml->n_mounts)
                mount_entry_done(m);

        ml->mounts = mfree(ml->mounts);
        ml->n_mounts = 0;
}

MountEntry* mount_list_extend(MountList *ml) {
        assert(ml);

        if (!GREEDY_REALLOC0(ml->mounts, ml->n_mounts+1))
                return NULL;

        return ml->mounts + ml->n_mounts++;
}

int mount_path_compare(const MountEntry *a, const MountEntry *b) {
        int d;

        /* ExtensionImages/Directories will be used by other mounts as a base, so sort them first
         * regardless of the prefix - they are set up in the propagate directory anyway */
        d = -CMP(a->mode == MOUNT_EXTENSION_IMAGE, b->mode == MOUNT_EXTENSION_IMAGE);
        if (d != 0)
                return d;
        d = -CMP(a->mode == MOUNT_EXTENSION_DIRECTORY, b->mode == MOUNT_EXTENSION_DIRECTORY);
        if (d != 0)
                return d;

        /* MOUNT_PRIVATE_TMPFS needs to be set up earlier, especially than MOUNT_BIND. */
        d = -CMP(a->mode == MOUNT_PRIVATE_TMPFS, b->mode == MOUNT_PRIVATE_TMPFS);
        if (d != 0)
                return d;

        /* If the paths are not equal, then order prefixes first */
        d = path_compare(mount_entry_path(a), mount_entry_path(b));
        if (d != 0)
                return d;

        /* If the paths are equal, check the mode */
        return CMP((int) a->mode, (int) b->mode);
}

int prefix_where_needed(MountList *ml, const char *root_directory) {
        /* Prefixes all paths in the bind mount table with the root directory if the entry needs that. */

        assert(ml);

        FOREACH_ARRAY(me, ml->mounts, ml->n_mounts) {
                char *s;

                if (me->has_prefix)
                        continue;

                s = path_join(root_directory, mount_entry_path(me));
                if (!s)
                        return -ENOMEM;

                mount_entry_consume_prefix(me, s);
        }

        return 0;
}

void mount_entry_path_debug_string(const char *root, MountEntry *m, char **ret_path) {
        assert(m);

        /* Create a string suitable for debugging logs, stripping for example the local working directory.
         * For example, with a BindPaths=/var/bar that does not exist on the host:
         *
         * Before:
         *  foo.service: Failed to set up mount namespacing: /run/systemd/unit-root/var/bar: No such file or directory
         * After:
         *  foo.service: Failed to set up mount namespacing: /var/bar: No such file or directory
         *
         * Note that this is an error path, so no OOM check is done on purpose. */

        if (!ret_path)
                return;

        if (!mount_entry_path(m)) {
                *ret_path = NULL;
                return;
        }

        if (root) {
                const char *e = startswith(mount_entry_path(m), root);
                if (e) {
                        *ret_path = strdup(e);
                        return;
                }
        }

        *ret_path = strdup(mount_entry_path(m));
        return;
}
