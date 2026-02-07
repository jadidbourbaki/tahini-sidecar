#ifndef TAHINI_U_UTIL_H
#define TAHINI_U_UTIL_H

#define TAHINI_SIDECAR_OWNERS_GROUP "sidecar-owners"

// Returns 1 if the current process is in the TAHINI_SIDECAR_OWNERS_GROUP, 0 otherwise.
int validate_user(void);

#endif /* TAHINI_U_UTIL_H */
