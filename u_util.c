#include "u_util.h"
#include <stdlib.h>
#include <unistd.h>
#include <grp.h>
#include <stdio.h>

int validate_user(void) {
    const char* error_prefix = "error in validate_user: ";

    struct group* gr = getgrnam(TAHINI_SIDECAR_OWNERS_GROUP);
    if (!gr) {
        fprintf(stderr, "%s user group %s not found\n", error_prefix, TAHINI_SIDECAR_OWNERS_GROUP);
        return 0;
    }

    gid_t want = gr->gr_gid;

    // getegid() is the effective group ID of the current process
    if (getegid() == want) return 1;

    // check if the process has any supplementary group IDs
    int n = getgroups(0, NULL);

    if (n <= 0) {
        fprintf(stderr, "%s failed to get groups\n", error_prefix);
        return 0;
    }

    gid_t* list = malloc((size_t)n * sizeof(gid_t));
    if (!list) {
        fprintf(stderr, "%s failed to allocate memory for groups list\n", error_prefix);
        return 0;
    }

    n = getgroups(n, list);
    if (n <= 0) {
        fprintf(stderr, "%s failed to get groups\n", error_prefix);
        free(list);
        return 0;
    }

    int found = 0;
    for (int i = 0; i < n; i++) {
        // check if the process is in any of the supplementary group IDs
        if (list[i] == want) {
            found = 1;
            break;
        }
    }

    free(list);
    return found;
}
