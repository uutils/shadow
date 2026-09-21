/* A PAM module for the deployment suite, and nothing else.
 *
 * It writes the environment of the process the PAM stack runs in to
 * /tmp/pam-envprobe.out and reports PAM_IGNORE, so it changes no outcome.
 * pam_exec cannot do this job: it hands its child the PAM environment and the
 * PAM items, never the calling process's environment, so a probe run through
 * it sees nothing whether or not the tool cleaned up after the caller. This
 * module runs inside the tool, and `environ` is the tool's.
 */
#include <security/pam_modules.h>
#include <stdio.h>

extern char **environ;

static int dump(void) {
    FILE *f = fopen("/tmp/pam-envprobe.out", "w");
    if (f == NULL) {
        return PAM_IGNORE;
    }
    for (char **e = environ; *e != NULL; e++) {
        fprintf(f, "%s\n", *e);
    }
    fclose(f);
    return PAM_IGNORE;
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return dump();
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return dump();
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
