/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "log.h"
#include "mkdir.h"
#include "nspawn-setuid.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

int change_uid_gid_raw(
                uid_t uid,
                gid_t gid,
                const gid_t *supplementary_gids,
                size_t n_supplementary_gids,
                bool chown_stdio) {

        int r;

        if (!uid_is_valid(uid))
                uid = 0;
        if (!gid_is_valid(gid))
                gid = 0;

        if (chown_stdio) {
                (void) fchown(STDIN_FILENO, uid, gid);
                (void) fchown(STDOUT_FILENO, uid, gid);
                (void) fchown(STDERR_FILENO, uid, gid);
        }

        r = fully_set_uid_gid(uid, gid, supplementary_gids, n_supplementary_gids);
        if (r < 0)
                return log_error_errno(r, "Changing privileges failed: %m");

        return 0;
}

int change_uid_gid(const char *user, bool chown_stdio, char **ret_home) {
        _cleanup_free_ gid_t *gids = NULL;
        _cleanup_free_ char *username = NULL, *home = NULL;
        int n_gids;
        uid_t uid;
        gid_t gid;
        int r;

        assert(ret_home);

        if (!user || STR_IN_SET(user, "root", "0")) {
                /* Reset everything fully to 0, just in case */

                r = reset_uid_gid();
                if (r < 0)
                        return log_error_errno(r, "Failed to become root: %m");

                *ret_home = NULL;
                return 0;
        }

        /* Resolve the user directly against the database visible to us right now, i.e. in-process via
         * NSS (getpwnam_r()/getpwuid_r()), rather than by shelling out to the external "getent" binary
         * (as this used to work): by the time we get here we have already pivoted into the target root,
         * so a plain NSS lookup already correctly resolves against the container's own /etc/passwd (and
         * whatever nsswitch.conf it ships) without requiring any extra binary to be present in it. Unlike
         * a full OS tree, a minimal/OCI-style application rootfs (e.g. one assembled via --mstack=) is not
         * guaranteed to ship a "getent" binary at all, so shelling out made resolution fail outright for
         * any such non-root --user=/--uid=. */
        r = get_user_creds(user, /* flags= */ 0, &username, &uid, &gid, &home, /* ret_shell= */ NULL);
        if (r == -ESRCH)
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH),
                                       "Failed to resolve user %s.", user);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve user %s: %m", user);

        /* Second, get group memberships */
        n_gids = getgrouplist_malloc(username, gid, &gids);
        if (n_gids < 0)
                return log_error_errno(n_gids, "Failed to resolve group memberships of user %s: %m", user);

        r = mkdir_parents(home, 0775);
        if (r < 0)
                return log_error_errno(r, "Failed to make home root directory: %m");

        r = mkdir_safe(home, 0755, uid, gid, 0);
        if (r < 0 && !IN_SET(r, -EEXIST, -ENOTDIR))
                return log_error_errno(r, "Failed to make home directory: %m");

        r = change_uid_gid_raw(uid, gid, gids, n_gids, chown_stdio);
        if (r < 0)
                return r;

        if (ret_home)
                *ret_home = TAKE_PTR(home);

        return 0;
}
