/*
 * auth-script OpenVPN plugin (Optimized)
 * 
 * Runs an external script to decide whether to authenticate a user or not.
 * Useful for checking 2FA on VPN auth attempts as it doesn't block the main
 * openvpn process, unlike passing the script to --auth-user-pass-verify.
 * 
 * Functions required to be a valid OpenVPN plugin:
 * - openvpn_plugin_min_version_required_v1
 * - openvpn_plugin_open_v3
 * - openvpn_plugin_func_v3
 * - openvpn_plugin_close_v1
 */

#define __EXTENSIONS__

#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <openvpn-plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define PLUGIN_NAME "auth-script"
#define OPENVPN_PLUGIN_VERSION_MIN 3

/* Plugin state structure */
struct plugin_context 
{
    plugin_log_t plugin_log;
    int argc;           /* Number of arguments (including script path) */
    char **argv;        /* NULL-terminated argument array */
};

/* 
 * Handle an authentication request using double-fork pattern.
 * 
 * Fork structure:
 *   Parent (OpenVPN plugin thread) 
 *     └─> Child (intermediate process)
 *           └─> Grandchild (daemonized script executor)
 *
 * The child exits immediately with DEFERRED status, allowing the parent
 * to return quickly. The grandchild runs the actual auth script and
 * writes the result to the auth_control_file.
 */
static int deferred_handler(struct plugin_context *context, 
                            const char *envp[])
{
    plugin_log_t log = context->plugin_log;
    pid_t pid;

    log(PLOG_DEBUG, PLUGIN_NAME, 
        "Deferred handler using script_path=%s", 
        context->argv[0]);

    pid = fork();

    if (pid < 0) {
        log(PLOG_ERR, PLUGIN_NAME, 
            "fork() failed: %s (errno=%d)", strerror(errno), errno);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* Parent process: wait for intermediate child */
    if (pid > 0) {
        int wstatus;
        pid_t wait_rc;

        log(PLOG_DEBUG, PLUGIN_NAME, "Forked child pid=%d", pid);
        
        /* Block until the intermediate child exits */
        do {
            wait_rc = waitpid(pid, &wstatus, 0);
        } while (wait_rc < 0 && errno == EINTR);

        if (wait_rc < 0) {
            log(PLOG_ERR, PLUGIN_NAME,
                "waitpid() failed for pid=%d: %s (errno=%d)",
                pid, strerror(errno), errno);
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        if (WIFEXITED(wstatus)) {
            int exit_status = WEXITSTATUS(wstatus);
            log(PLOG_DEBUG, PLUGIN_NAME, 
                "Child pid=%d exited with status=%d", pid, exit_status);
            return exit_status;
        }

        if (WIFSIGNALED(wstatus)) {
            log(PLOG_ERR, PLUGIN_NAME,
                "Child pid=%d killed by signal %d",
                pid, WTERMSIG(wstatus));
        } else {
            log(PLOG_ERR, PLUGIN_NAME,
                "Child pid=%d terminated abnormally", pid);
        }
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* 
     * Intermediate child process: fork again to create daemon,
     * then exit immediately to prevent zombie processes.
     */
    pid = fork();

    if (pid < 0) {
        _exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }
    
    if (pid > 0) {
        /* Intermediate child exits, grandchild continues */
        _exit(OPENVPN_PLUGIN_FUNC_DEFERRED);
    }

    /* 
     * Grandchild (daemon) process: execute the auth script.
     * This process is orphaned and adopted by init.
     */
    
    /* Create new session and detach from controlling terminal */
    if (setsid() < 0) {
        _exit(EXIT_FAILURE);
    }

    /* Set file creation mask */
    umask(0);

    /* Change to root directory to avoid holding mount points */
    if (chdir("/") < 0) {
        /* Non-fatal, continue anyway */
    }

    /* Close standard file descriptors - must do this BEFORE any logging
     * since logging won't work after this point */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Redirect stdin/stdout/stderr to /dev/null */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) {
            close(devnull);
        }
    }

    /* Execute the authentication script */
    execve(context->argv[0], context->argv, (char *const *)envp);
    
    /* execve only returns on error - exit with failure */
    _exit(EXIT_FAILURE);
}

/* Specify minimum OpenVPN plugin API version */
OPENVPN_EXPORT int openvpn_plugin_min_version_required_v1(void)
{
    return OPENVPN_PLUGIN_VERSION_MIN;
}

/*
 * Deep copy an argv array.
 * Returns a newly allocated NULL-terminated array of newly allocated strings.
 * Caller must free with free_argv().
 */
static char **copy_argv(const char *argv[], int *out_argc)
{
    int argc = 0;
    char **new_argv = NULL;
    
    /* Count arguments */
    while (argv[argc] != NULL) {
        argc++;
    }
    
    if (argc == 0) {
        *out_argc = 0;
        return NULL;
    }
    
    /* Allocate pointer array (argc + 1 for NULL terminator) */
    new_argv = calloc(argc + 1, sizeof(char *));
    if (new_argv == NULL) {
        *out_argc = 0;
        return NULL;
    }
    
    /* Duplicate each string */
    for (int i = 0; i < argc; i++) {
        new_argv[i] = strdup(argv[i]);
        if (new_argv[i] == NULL) {
            /* Cleanup on failure */
            for (int j = 0; j < i; j++) {
                free(new_argv[j]);
            }
            free(new_argv);
            *out_argc = 0;
            return NULL;
        }
    }
    
    new_argv[argc] = NULL;  /* NULL-terminate */
    *out_argc = argc;
    return new_argv;
}

/* Free an argv array created by copy_argv() */
static void free_argv(char **argv, int argc)
{
    if (argv == NULL) return;
    
    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
}

/* 
 * Handle plugin initialization.
 *   arguments->argv[0] = path to shared library
 *   arguments->argv[1] = path to authentication script
 *   arguments->argv[2..n] = optional script arguments
 */
OPENVPN_EXPORT int openvpn_plugin_open_v3(
    const int struct_version,
    struct openvpn_plugin_args_open_in const *arguments,
    struct openvpn_plugin_args_open_return *retptr)
{
    plugin_log_t log = arguments->callbacks->plugin_log;
    struct plugin_context *context = NULL;

    log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_open_v3");

    /* Verify struct version compatibility */
    if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
        log(PLOG_ERR, PLUGIN_NAME, 
            "Incompatible struct version: got %d, need >= %d",
            struct_version, OPENVPN_PLUGINv3_STRUCTVER);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* Verify script path was provided */
    if (arguments->argv[1] == NULL) {
        log(PLOG_ERR, PLUGIN_NAME, 
            "No script path specified. Usage: plugin <lib_path> <script_path> [args...]");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* Verify script exists and is executable */
    if (access(arguments->argv[1], X_OK) != 0) {
        log(PLOG_ERR, PLUGIN_NAME, 
            "Script not found or not executable: %s (%s)",
            arguments->argv[1], strerror(errno));
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* Allocate plugin context */
    context = calloc(1, sizeof(struct plugin_context));
    if (context == NULL) {
        log(PLOG_ERR, PLUGIN_NAME, "Failed to allocate plugin context");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    context->plugin_log = log;

    /* Copy script path and arguments (skip argv[0] which is the plugin library path) */
    context->argv = copy_argv(&arguments->argv[1], &context->argc);
    if (context->argv == NULL) {
        log(PLOG_ERR, PLUGIN_NAME, "Failed to copy script arguments");
        free(context);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    log(PLOG_DEBUG, PLUGIN_NAME, 
        "Configured with script=%s, argc=%d", 
        context->argv[0], context->argc);

    /* Register for auth verification callbacks */
    retptr->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
    retptr->handle = (openvpn_plugin_handle_t)context;

    log(PLOG_DEBUG, PLUGIN_NAME, "Plugin initialized successfully");

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/* Handle plugin function calls */
OPENVPN_EXPORT int openvpn_plugin_func_v3(
    const int struct_version,
    struct openvpn_plugin_args_func_in const *arguments,
    struct openvpn_plugin_args_func_return *retptr)
{
    (void)retptr;  /* Unused */
    
    struct plugin_context *context = 
        (struct plugin_context *)arguments->handle;
    plugin_log_t log = context->plugin_log;

    log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_func_v3");

    /* Verify struct version compatibility */
    if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
        log(PLOG_ERR, PLUGIN_NAME, 
            "Incompatible struct version: got %d, need >= %d",
            struct_version, OPENVPN_PLUGINv3_STRUCTVER);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* Handle auth verification request */
    if (arguments->type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
        log(PLOG_DEBUG, PLUGIN_NAME, "Handling AUTH_USER_PASS_VERIFY");
        return deferred_handler(context, arguments->envp);
    }

    /* Unexpected call type */
    log(PLOG_DEBUG, PLUGIN_NAME, 
        "Ignoring unexpected call type=%d", arguments->type);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/* Clean up plugin resources */
OPENVPN_EXPORT void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *)handle;
    
    if (context != NULL) {
        free_argv(context->argv, context->argc);
        free(context);
    }
}
