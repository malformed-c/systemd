/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "glyph-util.h"
#include "pidref.h"
#include "process-util.h"
#include "runtime-scope.h"

#include "alloc-util.h"
#include "chase.h"
#include "dev-setup.h"
#include "devnum-util.h"
#include "dissect-image.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "label-util.h"
#include "lock-util.h"
#include "log.h"
#include "loop-util.h"
#include "mkdir.h"
#include "mount-list.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "path-util.h"
#include "selinux-util.h"
#include "socket-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "user-util.h"

const ImageClassInfo image_class_info[_IMAGE_CLASS_MAX] = {
        [IMAGE_SYSEXT] = {
                .level_env = "SYSEXT_LEVEL",
                .level_env_print = " SYSEXT_LEVEL=",
        },
        [IMAGE_CONFEXT] = {
                .level_env = "CONFEXT_LEVEL",
                .level_env_print = " CONFEXT_LEVEL=",
        }
};

static const char * const mount_mode_table[_MOUNT_MODE_MAX] = {
        [MOUNT_INACCESSIBLE]          = "inaccessible",
        [MOUNT_OVERLAY]               = "overlay",
        [MOUNT_IMAGE]                 = "image",
        [MOUNT_BIND]                  = "bind",
        [MOUNT_BIND_RECURSIVE]        = "bind-recursive",
        [MOUNT_PRIVATE_TMP]           = "private-tmp",
        [MOUNT_PRIVATE_DEV]           = "private-dev",
        [MOUNT_BIND_DEV]              = "bind-dev",
        [MOUNT_EMPTY_DIR]             = "empty-dir",
        [MOUNT_PRIVATE_SYSFS]         = "private-sysfs",
        [MOUNT_BIND_SYSFS]            = "bind-sysfs",
        [MOUNT_PRIVATE_CGROUP2FS]     = "private-cgroup2fs",
        [MOUNT_PROCFS]                = "procfs",
        [MOUNT_READ_ONLY]             = "read-only",
        [MOUNT_READ_WRITE]            = "read-write",
        [MOUNT_NOEXEC]                = "noexec",
        [MOUNT_EXEC]                  = "exec",
        [MOUNT_TMPFS]                 = "tmpfs",
        [MOUNT_RUN]                   = "run",
        [MOUNT_PRIVATE_TMPFS]         = "private-tmpfs",
        [MOUNT_EXTENSION_DIRECTORY]   = "extension-directory",
        [MOUNT_EXTENSION_IMAGE]       = "extension-image",
        [MOUNT_MQUEUEFS]              = "mqueuefs",
        [MOUNT_READ_WRITE_IMPLICIT]   = "read-write-implicit",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(mount_mode, MountMode);

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

static bool verity_has_later_duplicates(MountList *ml, const MountEntry *needle) {

        assert(ml);
        assert(needle);
        assert(needle >= ml->mounts && needle < ml->mounts + ml->n_mounts);
        assert(needle->mode == MOUNT_EXTENSION_IMAGE);

        if (!iovec_is_set(&needle->verity.root_hash))
                return false;

        /* Overlayfs rejects supplying the same directory inode twice as determined by filesystem UUID and
         * file handle in lowerdir=, even if they are mounted on different paths, as it resolves each mount
         * to its source filesystem, so drop duplicates, and keep the last one. This only covers non-DDI
         * verity images. Note that the list is ordered, so we only check for the reminder of the list for
         * each item, rather than the full list from the beginning, as any earlier duplicates will have
         * already been pruned. */

        for (const MountEntry *m = needle + 1; m < ml->mounts + ml->n_mounts; m++) {
                if (m->mode != MOUNT_EXTENSION_IMAGE)
                        continue;
                if (iovec_equal(&m->verity.root_hash, &needle->verity.root_hash))
                        return true;
        }

        return false;
}

static void drop_duplicates(MountList *ml) {
        MountEntry *f, *t, *previous;

        assert(ml);

        /* Drops duplicate entries. Expects that the array is properly ordered already. */

        for (f = ml->mounts, t = ml->mounts, previous = NULL; f < ml->mounts + ml->n_mounts; f++) {

                /* The first one wins (which is the one with the more restrictive mode), see mount_path_compare()
                 * above. Note that we only drop duplicates that haven't been mounted yet. */
                if (previous &&
                    path_equal(mount_entry_path(f), mount_entry_path(previous)) &&
                    f->state == MOUNT_PENDING && previous->state == MOUNT_PENDING) {
                        log_debug("%s (%s) is duplicate.", mount_entry_path(f), mount_mode_to_string(f->mode));
                        /* Propagate the flags to the remaining entry */
                        previous->read_only = previous->read_only || mount_entry_read_only(f);
                        previous->noexec = previous->noexec || mount_entry_noexec(f);
                        previous->exec = previous->exec || mount_entry_exec(f);
                        mount_entry_done(f);
                        continue;
                }

                if (f->mode == MOUNT_EXTENSION_IMAGE && verity_has_later_duplicates(ml, f)) {
                        log_debug("Skipping duplicate extension image %s", mount_entry_source(f));
                        mount_entry_done(f);
                        continue;
                }

                *t = *f;
                previous = t;
                t++;
        }

        ml->n_mounts = t - ml->mounts;
}

static void drop_inaccessible(MountList *ml) {
        MountEntry *f, *t;
        const char *clear = NULL;

        assert(ml);

        /* Drops all entries obstructed by another entry further up the tree. Expects that the array is properly
         * ordered already. */

        for (f = ml->mounts, t = ml->mounts; f < ml->mounts + ml->n_mounts; f++) {

                /* If we found a path set for INACCESSIBLE earlier, and this entry has it as prefix we should drop
                 * it, as inaccessible paths really should drop the entire subtree. */
                if (clear && path_startswith(mount_entry_path(f), clear)) {
                        log_debug("%s is masked by %s.", mount_entry_path(f), clear);
                        mount_entry_done(f);
                        continue;
                }

                clear = f->mode == MOUNT_INACCESSIBLE ? mount_entry_path(f) : NULL;

                *t = *f;
                t++;
        }

        ml->n_mounts = t - ml->mounts;
}

static void drop_nop(MountList *ml) {
        MountEntry *f, *t;

        assert(ml);

        /* Drops all entries which have an immediate parent that has the same type, as they are redundant. Assumes the
         * list is ordered by prefixes. */

        for (f = ml->mounts, t = ml->mounts; f < ml->mounts + ml->n_mounts; f++) {

                /* Only suppress such subtrees for READ_ONLY, READ_WRITE and READ_WRITE_IMPLICIT entries */
                if (IN_SET(f->mode, MOUNT_READ_ONLY, MOUNT_READ_WRITE, MOUNT_READ_WRITE_IMPLICIT)) {
                        MountEntry *found = NULL;

                        /* Now let's find the first parent of the entry we are looking at. */
                        for (MountEntry *p = PTR_SUB1(t, ml->mounts); p; p = PTR_SUB1(p, ml->mounts))
                                if (path_startswith(mount_entry_path(f), mount_entry_path(p))) {
                                        found = p;
                                        break;
                                }

                        /* We found it, let's see if it's the same mode, if so, we can drop this entry */
                        if (found && found->mode == f->mode) {
                                log_debug("%s (%s) is made redundant by %s (%s)",
                                          mount_entry_path(f), mount_mode_to_string(f->mode),
                                          mount_entry_path(found), mount_mode_to_string(found->mode));
                                mount_entry_done(f);
                                continue;
                        }
                }

                *t = *f;
                t++;
        }

        ml->n_mounts = t - ml->mounts;
}

static void drop_outside_root(MountList *ml, const char *root_directory) {
        MountEntry *f, *t;

        assert(ml);

        /* Nothing to do */
        if (!root_directory)
                return;

        /* Drops all mounts that are outside of the root directory. */

        for (f = ml->mounts, t = ml->mounts; f < ml->mounts + ml->n_mounts; f++) {

                /* ExtensionImages/Directories bases are opened in /run/[user/xyz/]systemd/unit-extensions
                 * on the host, and a private (invisible to the guest) tmpfs instance is mounted on
                 * /run/[user/xyz/]systemd/unit-private-tmp as the storage backend of private /tmp and
                 * /var/tmp. */
                if (!IN_SET(f->mode, MOUNT_EXTENSION_IMAGE, MOUNT_EXTENSION_DIRECTORY, MOUNT_PRIVATE_TMPFS) &&
                    !path_startswith(mount_entry_path(f), root_directory)) {
                        log_debug("%s is outside of root directory.", mount_entry_path(f));
                        mount_entry_done(f);
                        continue;
                }

                *t = *f;
                t++;
        }

        ml->n_mounts = t - ml->mounts;
}

int clone_device_node(const char *node, const char *temporary_mount, bool *make_devnode) {
        _cleanup_free_ char *sl = NULL;
        const char *dn, *bn;
        struct stat st;
        int r;

        assert(node);
        assert(path_is_absolute(node));
        assert(temporary_mount);
        assert(make_devnode);

        if (stat(node, &st) < 0) {
                if (errno == ENOENT) {
                        log_debug_errno(errno, "Device node '%s' to clone does not exist.", node);
                        return -ENXIO;
                }

                return log_debug_errno(errno, "Failed to stat() device node '%s' to clone: %m", node);
        }

        r = stat_verify_device_node(&st);
        if (r < 0)
                return log_debug_errno(r, "Cannot clone device node '%s': %m", node);

        dn = strjoina(temporary_mount, node);

        /* First, try to create device node properly */
        if (*make_devnode) {
                mac_selinux_create_file_prepare(node, st.st_mode, /* label_context= */ NULL);
                r = mknod(dn, st.st_mode, st.st_rdev);
                mac_selinux_create_file_clear();
                if (r >= 0)
                        goto add_symlink;
                if (errno != EPERM)
                        return log_debug_errno(errno, "Failed to mknod '%s': %m", node);

                /* This didn't work, let's not try this again for the next iterations. */
                *make_devnode = false;
        }

        /* We're about to fall back to bind-mounting the device node. So create a dummy bind-mount target.
         * Do not prepare device-node SELinux label (see issue 13762) */
        r = mknod(dn, S_IFREG, 0);
        if (r < 0 && errno != EEXIST)
                return log_debug_errno(errno, "Failed to mknod dummy device node for '%s': %m", node);

        /* Fallback to bind-mounting: The assumption here is that all used device nodes carry standard
         * properties. Specifically, the devices nodes we bind-mount should either be owned by root:root or
         * root:tty (e.g. /dev/tty, /dev/ptmx) and should not carry ACLs. */
        r = mount_nofollow_verbose(LOG_DEBUG, node, dn, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

add_symlink:
        bn = path_startswith(node, "/dev/");
        if (!bn)
                return 0;

        /* Create symlinks like /dev/char/1:9 → ../urandom */
        if (asprintf(&sl, "%s/dev/%s/" DEVNUM_FORMAT_STR,
                     temporary_mount,
                     S_ISCHR(st.st_mode) ? "char" : "block",
                     DEVNUM_FORMAT_VAL(st.st_rdev)) < 0)
                return log_oom_debug();

        (void) mkdir_parents(sl, 0755);

        const char *t = strjoina("../", bn);
        if (symlink(t, sl) < 0)
                log_debug_errno(errno, "Failed to symlink '%s' to '%s', ignoring: %m", t, sl);

        return 0;
}

int bind_mount_device_dir(const char *temporary_mount, const char *dir) {
        const char *t;

        assert(temporary_mount);
        assert(dir);
        assert(path_is_absolute(dir));

        t = strjoina(temporary_mount, dir);

        (void) mkdir(t, 0755);
        return mount_nofollow_verbose(LOG_DEBUG, dir, t, NULL, MS_BIND, NULL);
}

char* settle_runtime_dir(RuntimeScope scope) {
        char *runtime_dir;

        if (scope != RUNTIME_SCOPE_USER)
                return strdup("/run/");

        if (asprintf(&runtime_dir, "/run/user/" UID_FMT, geteuid()) < 0)
                return NULL;

        return runtime_dir;
}

int create_temporary_mount_point(RuntimeScope scope, char **ret) {
        _cleanup_free_ char *runtime_dir = NULL, *temporary_mount = NULL;

        assert(ret);

        runtime_dir = settle_runtime_dir(scope);
        if (!runtime_dir)
                return log_oom_debug();

        temporary_mount = path_join(runtime_dir, "systemd/namespace-XXXXXX");
        if (!temporary_mount)
                return log_oom_debug();

        if (!mkdtemp(temporary_mount))
                return log_debug_errno(errno, "Failed to create temporary directory '%s': %m", temporary_mount);

        *ret = TAKE_PTR(temporary_mount);
        return 0;
}

int mount_bind_sysfs(const MountEntry *m) {
        int r;

        assert(m);

        (void) mkdir_p_label(mount_entry_path(m), 0755);

        r = path_is_mount_point(mount_entry_path(m));
        if (r < 0)
                return log_debug_errno(r, "Unable to determine whether /sys is already mounted: %m");
        if (r > 0) /* make this a NOP if /sys is already a mount point */
                return 0;

        /* Bind mount the host's version so that we get all child mounts of it, too. */
        r = mount_nofollow_verbose(LOG_DEBUG, "/sys", mount_entry_path(m), NULL, MS_BIND|MS_REC, NULL);
        if (r < 0)
                return r;

        return 1;
}

int mount_private_apivfs(
                const char *fstype,
                const char *entry_path,
                const char *bind_source,
                const char *opts,
                RuntimeScope scope) {

        _cleanup_(rmdir_and_freep) char *temporary_mount = NULL;
        int r;

        assert(fstype);
        assert(entry_path);
        assert(bind_source);

        bool noprivs = false;

        /* First, check if we have enough privileges to mount a new instance. */
        _cleanup_close_ int mount_fd = make_fsmount(
                        LOG_DEBUG,
                        /* what= */ fstype,
                        fstype,
                        MS_NOSUID|MS_NOEXEC|MS_NODEV,
                        opts,
                        /* userns_fd= */ -EBADF);
        if (ERRNO_IS_NEG_PRIVILEGE(mount_fd))
                noprivs = true;
        else if (ERRNO_IS_NEG_NOT_SUPPORTED(mount_fd)) {
                /* Fallback for kernels lacking mount_setattr() */

                // FIXME: This compatibility code path shall be removed once kernel 5.12
                //        becomes the new minimal baseline

                r = create_temporary_mount_point(scope, &temporary_mount);
                if (r < 0)
                        return r;

                r = mount_nofollow_verbose(
                                LOG_DEBUG,
                                fstype,
                                temporary_mount,
                                fstype,
                                MS_NOSUID|MS_NOEXEC|MS_NODEV,
                                opts);
                if (ERRNO_IS_NEG_PRIVILEGE(r))
                        noprivs = true;
                else if (r < 0)
                        return r;
        } else if (mount_fd < 0)
                return log_debug_errno(mount_fd, "Failed to make file system mount: %m");

        (void) mkdir_p_label(entry_path, 0755);

        if (noprivs) {
                /* When we do not have enough privileges to mount a new instance, fall back to use an
                 * existing mount. */

                r = path_is_mount_point(entry_path);
                if (r < 0)
                        return log_debug_errno(r, "Unable to determine whether '%s' is already mounted: %m", entry_path);
                if (r > 0)
                        return 0; /* Use the current mount as is. */

                /* We lack permissions to mount a new instance, and it is not already mounted. But we can
                 * access the host's, so as a final fallback bind-mount it to the destination, as most likely
                 * we are inside a user manager in an unprivileged user namespace. */
                r = mount_nofollow_verbose(LOG_DEBUG, bind_source, entry_path, /* fstype= */ NULL, MS_BIND|MS_REC, /* options= */ NULL);
                if (r < 0)
                        return r;

                return 1;
        }

        /* OK. We have a new mount instance. Let's clear an existing mount and its submounts. */
        r = umount_recursive(entry_path, /* flags= */ 0);
        if (r < 0)
                log_debug_errno(r, "Failed to unmount directories below '%s', ignoring: %m", entry_path);

        /* Then, move the new mount instance. */
        if (mount_fd >= 0) {
                r = RET_NERRNO(move_mount(mount_fd, "", -EBADF, entry_path, MOVE_MOUNT_F_EMPTY_PATH));
                if (r < 0)
                        return log_debug_errno(r, "Failed to attach '%s' to '%s': %m", fstype, entry_path);
        } else if (temporary_mount) {
                r = mount_nofollow_verbose(LOG_DEBUG, temporary_mount, entry_path, /* fstype= */ NULL, MS_MOVE, /* options= */ NULL);
                if (r < 0)
                        return r;
        } else
                assert_not_reached();

        /* We mounted a new instance now. Let's bind mount the children over now. This matters for nspawn
         * where a bunch of files are overmounted, in particular the boot id. */
        (void) bind_mount_submounts(bind_source, entry_path);
        return 1;
}

int mount_bind(
                const MountEntry *m,
                const char *what,
                bool recursive,
                bool make) {

        int r;

        assert(m);
        assert(what);

        r = mount_nofollow_verbose(
                        LOG_DEBUG,
                        what,
                        mount_entry_path(m),
                        NULL,
                        MS_BIND|(recursive ? MS_REC : 0),
                        NULL);
        if (r >= 0)
                return 0;
        if (r != -ENOENT || !make)
                return log_debug_errno(r, "Failed to mount %s to %s: %m", what, mount_entry_path(m));

        /* Either the source or the destination is missing. Create the destination and try again. */
        r = mkdir_parents(mount_entry_path(m), 0755);
        if (r < 0 && r != -EEXIST)
                return log_debug_errno(r,
                                       "Failed to create parent directories of destination mount point node '%s': %m",
                                       mount_entry_path(m));

        r = make_mount_point_inode_from_path(what, mount_entry_path(m), 0755);
        if (r < 0 && r != -EEXIST)
                return log_debug_errno(r, "Failed to create destination mount point node '%s': %m",
                                       mount_entry_path(m));

        r = mount_nofollow_verbose(
                        LOG_DEBUG,
                        what,
                        mount_entry_path(m),
                        NULL,
                        MS_BIND|(recursive ? MS_REC : 0),
                        NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to mount %s to %s: %m", what, mount_entry_path(m));

        return 0;
}

int mount_tmpfs(const MountEntry *m) {
        const char *entry_path, *inner_path;
        int r;

        assert(m);

        entry_path = mount_entry_path(m);
        inner_path = mount_entry_unprefixed_path(m);

        /* First, get rid of everything that is below if there is anything. Then, overmount with our new
         * tmpfs */

        (void) mkdir_p_label(entry_path, 0755);
        (void) umount_recursive(entry_path, 0);

        r = mount_nofollow_verbose(LOG_DEBUG, "tmpfs", entry_path, "tmpfs", m->flags, mount_entry_options(m));
        if (r < 0)
                return r;

        r = label_fix_full(AT_FDCWD, entry_path, inner_path, /* flags= */ 0, /* label_context= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to fix label of '%s' as '%s': %m", entry_path, inner_path);

        return 1;
}

int mount_run(const MountEntry *m) {
        int r;

        assert(m);

        r = path_is_mount_point(mount_entry_path(m));
        if (r < 0 && r != -ENOENT)
                return log_debug_errno(r, "Unable to determine whether /run is already mounted: %m");
        if (r > 0) /* make this a NOP if /run is already a mount point */
                return 0;

        return mount_tmpfs(m);
}

int mount_mqueuefs(const MountEntry *m) {
        int r;
        const char *entry_path;

        assert(m);

        entry_path = mount_entry_path(m);

        (void) mkdir_p_label(entry_path, 0755);
        (void) umount_recursive(entry_path, 0);

        r = mount_nofollow_verbose(LOG_DEBUG, "mqueue", entry_path, "mqueue", m->flags, mount_entry_options(m));
        if (r == -ENODEV) /* POSIX message queues may be disabled in the kernel. */
                return 0;
        if (r < 0)
                return r;

        return 1;
}

int mount_image(
                MountEntry *m,
                const char *root_directory,
                const ImagePolicy *image_policy,
                RuntimeScope runtime_scope) {

        _cleanup_(extension_release_data_done) ExtensionReleaseData rdata = {};
        ImageClass required_class = _IMAGE_CLASS_INVALID;
        int r;

        assert(m);

        if (m->mode == MOUNT_EXTENSION_IMAGE) {
                r = parse_os_release(
                                empty_to_root(root_directory),
                                "ID", &rdata.os_release_id,
                                "ID_LIKE", &rdata.os_release_id_like,
                                "VERSION_ID", &rdata.os_release_version_id,
                                image_class_info[IMAGE_SYSEXT].level_env, &rdata.os_release_sysext_level,
                                image_class_info[IMAGE_CONFEXT].level_env, &rdata.os_release_confext_level,
                                NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire 'os-release' data of OS tree '%s': %m", empty_to_root(root_directory));
                if (isempty(rdata.os_release_id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "'ID' field not found or empty in 'os-release' data of OS tree '%s'.", empty_to_root(root_directory));

                required_class = m->filter_class;
        }

        r = verity_dissect_and_mount(
                        /* src_fd= */ -EBADF,
                        mount_entry_source(m),
                        mount_entry_path(m),
                        m->image_options_const,
                        image_policy,
                        /* image_filter= */ NULL,
                        &rdata,
                        required_class,
                        &m->verity,
                        runtime_scope,
                        /* ret_image= */ NULL);
        if (r == -ENOENT && m->ignore)
                return 0;
        if (r == -ESTALE && rdata.os_release_id)
                return log_error_errno(r, // FIXME: this should not be logged ad LOG_ERR, as it will result in duplicate logging.
                                       "Failed to mount image %s, extension-release metadata does not match the lower layer's: ID=%s ID_LIKE='%s'%s%s%s%s%s%s",
                                       mount_entry_source(m),
                                       rdata.os_release_id,
                                       strempty(rdata.os_release_id_like),
                                       rdata.os_release_version_id ? " VERSION_ID=" : "",
                                       strempty(rdata.os_release_version_id),
                                       rdata.os_release_sysext_level ? image_class_info[IMAGE_SYSEXT].level_env_print : "",
                                       strempty(rdata.os_release_sysext_level),
                                       rdata.os_release_confext_level ? image_class_info[IMAGE_CONFEXT].level_env_print : "",
                                       strempty(rdata.os_release_confext_level));
        if (r == -ENOCSI) {
                log_debug("Image %s does not match the expected class, ignoring", mount_entry_source(m));
                return 0; /* Nothing to do, wrong class */
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to mount image %s on %s: %m", mount_entry_source(m), mount_entry_path(m));

        return 1;
}

int mount_overlay(const MountEntry *m) {
        _cleanup_free_ char *options = NULL, *layers = NULL;
        int r;

        assert(m);

        /* Extension hierarchies are optional (e.g.: confext might not have /opt) so check if they actually
         * exist in an image before attempting to create an overlay with them, otherwise the mount will
         * fail. We can't check before this, as the images will not be mounted until now. */

        /* Note that lowerdir= parameters are in 'reverse' order, so the top-most directory in the overlay
         * comes first in the list. */
        STRV_FOREACH_BACKWARDS(o, m->overlay_layers) {
                _cleanup_free_ char *escaped = NULL;

                r = is_dir(*o, /* follow= */ false);
                if (r <= 0) {
                        if (r != -ENOENT)
                                log_debug_errno(r,
                                                "Failed to check whether overlay layer source path '%s' exists, ignoring: %m",
                                                *o);
                        continue;
                }

                escaped = shell_escape(*o, ",:");
                if (!escaped)
                        return log_oom_debug();

                if (!strextend_with_separator(&layers, ":", escaped))
                        return log_oom_debug();
        }

        if (!layers) {
                log_debug("None of the overlays specified in '%s' exist at the source, skipping.",
                          mount_entry_options(m));
                return 0; /* Only the root is set? Then there's nothing to overlay */
        }

        options = strjoin("lowerdir=", layers, ":", mount_entry_path(m)); /* The root goes in last */
        if (!options)
                return log_oom_debug();

        (void) mkdir_p_label(mount_entry_path(m), 0755);

        r = mount_nofollow_verbose(LOG_DEBUG, "systemd-extensions", mount_entry_path(m), "overlay", MS_RDONLY, options);
        if (r == -ENOENT && m->ignore)
                return 0;
        if (r < 0)
                return r;

        return 1;
}

int mount_bpffs(const MountEntry *m, PidRef *pidref, int socket_fd, int errno_pipe) {
        int r;

        assert(m);
        assert(pidref_is_set(pidref));
        assert(socket_fd >= 0);
        assert(errno_pipe >= 0);

        _cleanup_close_ int fs_fd = fsopen("bpf", FSOPEN_CLOEXEC);
        if (fs_fd < 0)
                return log_debug_errno(errno, "Failed to fsopen: %m");

        r = send_one_fd(socket_fd, fs_fd, /* flags= */ 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to send bpffs fd to child: %m");

        r = pidref_wait_for_terminate_and_check("(sd-bpffs)", pidref, /* flags= */ 0);
        if (r < 0)
                return r;

        /* If something strange happened with the child, let's consider this fatal, too */
        if (r != EXIT_SUCCESS) {
                ssize_t ss = read(errno_pipe, &r, sizeof(r));
                if (ss < 0)
                        return log_debug_errno(errno, "Failed to read from the bpffs helper errno pipe: %m");
                if (ss != sizeof(r))
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Short read from the bpffs helper errno pipe.");
                return log_debug_errno(r, "bpffs helper exited with error: %m");
        }

        pidref_done(pidref);

        _cleanup_close_ int mnt_fd = fsmount(fs_fd, /* flags= */ 0, /* mount_attrs= */ 0);
        if (mnt_fd < 0)
                return log_debug_errno(errno, "Failed to fsmount bpffs: %m");

        r = move_mount(mnt_fd, "", AT_FDCWD, mount_entry_path(m), MOVE_MOUNT_F_EMPTY_PATH);
        if (r < 0)
                return log_debug_errno(errno, "Failed to move bpffs mount to %s: %m", mount_entry_path(m));

        return 1;
}

int follow_symlink(
                const char *root_directory,
                MountEntry *m) {

        _cleanup_free_ char *target = NULL;
        int r;

        assert(m);

        /* Let's chase symlinks, but only one step at a time. That's because depending where the symlink points we
         * might need to change the order in which we mount stuff. Hence: let's normalize piecemeal, and do one step at
         * a time by specifying CHASE_STEP. This function returns 0 if we resolved one step, and > 0 if we reached the
         * end and already have a fully normalized name. */

        r = chase(mount_entry_path(m), root_directory, CHASE_STEP|CHASE_NONEXISTENT|CHASE_TRIGGER_AUTOFS, &target, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to chase symlinks '%s': %m", mount_entry_path(m));
        if (r > 0) /* Reached the end, nothing more to resolve */
                return 1;

        if (m->n_followed >= CHASE_MAX) /* put a boundary on things */
                return log_debug_errno(SYNTHETIC_ERRNO(ELOOP),
                                       "Symlink loop on '%s'.",
                                       mount_entry_path(m));

        log_debug("Followed mount entry path symlink %s %s %s.",
                  mount_entry_path(m), glyph(GLYPH_ARROW_RIGHT), target);

        mount_entry_consume_prefix(m, TAKE_PTR(target));

        m->n_followed++;

        return 0;
}

static bool should_propagate_to_submounts(const MountEntry *m) {
        assert(m);
        return !IN_SET(m->mode, MOUNT_EMPTY_DIR, MOUNT_TMPFS, MOUNT_PRIVATE_TMPFS);
}

int make_read_only(const MountEntry *m, char **deny_list, FILE *proc_self_mountinfo) {
        unsigned long new_flags = 0, flags_mask = 0;
        bool submounts;
        int r;

        assert(m);
        assert(proc_self_mountinfo);

        if (m->state != MOUNT_APPLIED)
                return 0;

        if (mount_entry_read_only(m) || m->mode == MOUNT_PRIVATE_DEV) {
                new_flags |= MS_RDONLY;
                flags_mask |= MS_RDONLY;
        }

        if (m->nosuid) {
                new_flags |= MS_NOSUID;
                flags_mask |= MS_NOSUID;
        }

        if (flags_mask == 0) /* No Change? */
                return 0;

        /* We generally apply these changes recursively, except for /dev, and the cases we know there's
         * nothing further down.  Set /dev readonly, but not submounts like /dev/shm. Also, we only set the
         * per-mount read-only flag.  We can't set it on the superblock, if we are inside a user namespace
         * and running Linux <= 4.17. */
        submounts = mount_entry_read_only(m) && should_propagate_to_submounts(m);
        if (submounts)
                r = bind_remount_recursive_with_mountinfo(mount_entry_path(m), new_flags, flags_mask, deny_list, proc_self_mountinfo);
        else
                r = bind_remount_one_with_mountinfo(mount_entry_path(m), new_flags, flags_mask, proc_self_mountinfo);

        /* Note that we only turn on the MS_RDONLY flag here, we never turn it off. Something that was marked
         * read-only already stays this way. This improves compatibility with container managers, where we
         * won't attempt to undo read-only mounts already applied. */

        if (r == -ENOENT && m->ignore)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to re-mount '%s'%s: %m", mount_entry_path(m),
                                       submounts ? " and its submounts" : "");
        return 0;
}

int make_noexec(const MountEntry *m, char **deny_list, FILE *proc_self_mountinfo) {
        unsigned long new_flags = 0, flags_mask = 0;
        bool submounts;
        int r;

        assert(m);
        assert(proc_self_mountinfo);

        if (m->state != MOUNT_APPLIED)
                return 0;

        if (mount_entry_noexec(m)) {
                new_flags |= MS_NOEXEC;
                flags_mask |= MS_NOEXEC;
        } else if (mount_entry_exec(m)) {
                new_flags &= ~MS_NOEXEC;
                flags_mask |= MS_NOEXEC;
        }

        if (flags_mask == 0) /* No Change? */
                return 0;

        submounts = should_propagate_to_submounts(m);
        if (submounts)
                r = bind_remount_recursive_with_mountinfo(mount_entry_path(m), new_flags, flags_mask, deny_list, proc_self_mountinfo);
        else
                r = bind_remount_one_with_mountinfo(mount_entry_path(m), new_flags, flags_mask, proc_self_mountinfo);

        if (r == -ENOENT && m->ignore)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to re-mount '%s'%s: %m", mount_entry_path(m),
                                       submounts ? " and its submounts" : "");
        return 0;
}

int make_nosuid(const MountEntry *m, FILE *proc_self_mountinfo) {
        bool submounts;
        int r;

        assert(m);
        assert(proc_self_mountinfo);

        if (m->state != MOUNT_APPLIED)
                return 0;

        submounts = should_propagate_to_submounts(m);
        if (submounts)
                r = bind_remount_recursive_with_mountinfo(mount_entry_path(m), MS_NOSUID, MS_NOSUID, NULL, proc_self_mountinfo);
        else
                r = bind_remount_one_with_mountinfo(mount_entry_path(m), MS_NOSUID, MS_NOSUID, proc_self_mountinfo);
        if (r == -ENOENT && m->ignore)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to re-mount '%s'%s: %m", mount_entry_path(m),
                                       submounts ? " and its submounts" : "");
        return 0;
}

void sort_and_drop_unused_mounts(MountList *ml, const char *root_directory) {
        assert(ml);
        assert(root_directory);

        assert(ml->mounts || ml->n_mounts == 0);

        typesafe_qsort(ml->mounts, ml->n_mounts, mount_path_compare);

        drop_duplicates(ml);
        drop_outside_root(ml, root_directory);
        drop_inaccessible(ml);
        drop_nop(ml);
}
