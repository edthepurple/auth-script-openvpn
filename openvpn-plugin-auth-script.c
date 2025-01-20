/*
 * auth-script OpenVPN plugin
 * Optimized for efficiency and performance.
 */

#define __EXTENSIONS__

#include <stddef.h>
#include <errno.h>
#include <openvpn-plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define PLUGIN_NAME "auth-script"
#define OPENVPN_PLUGIN_VERSION_MIN 3
#define SCRIPT_NAME_IDX 0

struct plugin_context {
    plugin_log_t plugin_log;
    const char *argv[];
};

static int deferred_handler(struct plugin_context *context, const char *envp[]) {
    plugin_log_t log = context->plugin_log;
    pid_t pid = fork();

    if (pid < 0) {
        log(PLOG_ERR, PLUGIN_NAME, "Fork failed with pid %d", pid);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    if (pid > 0) {
        int status;
        pid_t wait_rc = waitpid(pid, &status, 0);

        if (wait_rc < 0) {
            log(PLOG_ERR, PLUGIN_NAME, "waitpid failed for pid %d", pid);
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }

        log(PLOG_ERR, PLUGIN_NAME, "Child process %d terminated abnormally", pid);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    if (fork() < 0) {
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    if (setsid() < 0 || chdir("/") < 0) {
        log(PLOG_ERR, PLUGIN_NAME, "Daemonization failed");
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    execve(context->argv[SCRIPT_NAME_IDX], (char *const *)context->argv, (char *const *)envp);

    log(PLOG_ERR, PLUGIN_NAME, "Exec failed with errno: %d", errno);
    exit(EXIT_FAILURE);
}

OPENVPN_EXPORT int openvpn_plugin_min_version_required_v1() {
    return OPENVPN_PLUGIN_VERSION_MIN;
}

OPENVPN_EXPORT int openvpn_plugin_open_v3(const int struct_version,
                                          struct openvpn_plugin_args_open_in const *args,
                                          struct openvpn_plugin_args_open_return *retptr) {
    plugin_log_t log = args->callbacks->plugin_log;
    log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_open_v3");

    if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
        log(PLOG_ERR, PLUGIN_NAME, "Struct version too old");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    size_t argv_size = 0;
    for (int i = 1; args->argv[i]; i++) {
        argv_size += sizeof(char *) + strlen(args->argv[i]) + 1;
    }

    if (argv_size == 0) {
        log(PLOG_ERR, PLUGIN_NAME, "No script_path specified");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    struct plugin_context *context = malloc(sizeof(struct plugin_context) + argv_size);
    if (!context) {
        log(PLOG_ERR, PLUGIN_NAME, "Memory allocation failed");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    memset(context, 0, sizeof(struct plugin_context) + argv_size);
    context->plugin_log = log;
    memcpy(context->argv, &args->argv[1], argv_size);

    retptr->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
    retptr->handle = (openvpn_plugin_handle_t)context;

    log(PLOG_DEBUG, PLUGIN_NAME, "Plugin initialized successfully");
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int openvpn_plugin_func_v3(const int struct_version,
                                          struct openvpn_plugin_args_func_in const *args,
                                          struct openvpn_plugin_args_func_return *retptr) {
    (void)retptr;

    if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    struct plugin_context *context = (struct plugin_context *)args->handle;

    if (args->type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
        return deferred_handler(context, args->envp);
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle) {
    free((struct plugin_context *)handle);
}
