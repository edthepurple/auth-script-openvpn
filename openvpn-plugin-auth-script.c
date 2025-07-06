/*
 * auth-script OpenVPN plugin
 * 
 * Runs an external script to decide whether to authenticate a user or not.
 * Useful for checking 2FA on VPN auth attempts as it doesn't block the main
 * openvpn process, unlike passing the script to --auth-user-pass-verify.
 * 
 * Functions required to be a valid OpenVPN plugin:
 * openvpn_plugin_open_v3
 * openvpn_plugin_func_v3
 * openvpn_plugin_close_v1
 */

/* Required to use strdup */
#define __EXTENSIONS__

/********** Includes */
#include <stddef.h>
#include <errno.h>
#include <openvpn-plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

/********** Constants */
/* For consistency in log messages */
#define PLUGIN_NAME "auth-script"
#define OPENVPN_PLUGIN_VERSION_MIN 3
#define SCRIPT_NAME_IDX 0

/* Where we store our own settings/state */
struct plugin_context 
{
        plugin_log_t plugin_log;
        const char *argv[];
};

/* Handle an authentication request */
static int deferred_handler(struct plugin_context *context, 
                const char *envp[])
{
        plugin_log_t log = context->plugin_log;
        pid_t pid;

        log(PLOG_DEBUG, PLUGIN_NAME, 
                        "Deferred handler using script_path=%s", 
                        context->argv[SCRIPT_NAME_IDX]);

        pid = fork();

        /* Parent - child failed to fork */
        if (pid < 0) {
                log(PLOG_ERR, PLUGIN_NAME, 
                                "pid failed < 0 check, got %d", pid);
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        /* Parent - child forked successfully 
         *
         * Here we wait until that child completes before notifying OpenVPN of
         * our status.
         */
        if (pid > 0) {
                int wstatus;

                log(PLOG_DEBUG, PLUGIN_NAME, "child pid is %d", pid);
                
                /* Block until the child returns */
                if (waitpid(pid, &wstatus, 0) < 0) {
                        log(PLOG_ERR, PLUGIN_NAME,
                                        "wait failed for pid %d", pid);
                        return OPENVPN_PLUGIN_FUNC_ERROR;
                }

                /* WIFEXITED will be true if the child exited normally, any
                 * other return indicates an abnormal termination.
                 */
                if (WIFEXITED(wstatus)) {
                        log(PLOG_DEBUG, PLUGIN_NAME, 
                                        "child pid %d exited with status %d", 
                                        pid, WEXITSTATUS(wstatus));
                        return WEXITSTATUS(wstatus);
                }

                log(PLOG_ERR, PLUGIN_NAME,
                                "child pid %d terminated abnormally",
                                pid);
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        /* Child Control - Spin off our successor */
        pid = fork();

        /* Notify our parent that our child failed to fork */
        if (pid < 0) 
                _exit(OPENVPN_PLUGIN_FUNC_ERROR);
        
        /* Let our parent know that our child is working appropriately */
        if (pid > 0)
                _exit(OPENVPN_PLUGIN_FUNC_DEFERRED);

        /* Child Spawn - This process actually spawns the script */
        
        /* Daemonize - minimal overhead version */
        setsid();

        /* Close only standard file descriptors */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        /* Execute the script directly */
        execve(context->argv[0], 
                (char *const*)context->argv, 
                (char *const*)envp);
        
        /* If we get here, execve failed - just exit */
        _exit(EXIT_FAILURE);
}

/* We require OpenVPN Plugin API v3 */
OPENVPN_EXPORT int openvpn_plugin_min_version_required_v1()
{
        return OPENVPN_PLUGIN_VERSION_MIN;
}

/* 
 * Handle plugin initialization
 *        arguments->argv[0] is path to shared lib
 *        arguments->argv[1] is expected to be path to script
 */
OPENVPN_EXPORT int openvpn_plugin_open_v3(const int struct_version,
                struct openvpn_plugin_args_open_in const *arguments,
                struct openvpn_plugin_args_open_return *retptr)
{
        plugin_log_t log = arguments->callbacks->plugin_log;
        log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_open_v3");

        struct plugin_context *context = NULL;

        /* Safeguard on openvpn versions */
        if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
                log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: struct version was older than required");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        /* Tell OpenVPN we want to handle these calls */
        retptr->type_mask = OPENVPN_PLUGIN_MASK(
                        OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

        /* Check we've been handed a script path to call */
        if (!arguments->argv[1]) {
                log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: no script_path specified in config file");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        /*
         * Count arguments and calculate total size needed
         */
        int argc = 0;
        size_t total_size = 0;
        for (int i = 1; arguments->argv[i]; i++) {
                total_size += strlen(arguments->argv[i]) + 1;
                argc++;
        }

        /* 
         * Allocate context with space for argv pointers and string data
         */
        size_t context_size = sizeof(struct plugin_context) + 
                             (argc + 1) * sizeof(char*) + total_size;
        context = (struct plugin_context *) malloc(context_size);
        if (!context) {
                log(PLOG_ERR, PLUGIN_NAME, "ERROR: malloc failed");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        context->plugin_log = log;

        /* Set up argv array and copy strings */
        char **argv_ptr = (char**)&context->argv[0];
        char *str_data = (char*)context + sizeof(struct plugin_context) + 
                        (argc + 1) * sizeof(char*);
        
        for (int i = 0; i < argc; i++) {
                size_t len = strlen(arguments->argv[i + 1]);
                memcpy(str_data, arguments->argv[i + 1], len + 1);
                argv_ptr[i] = str_data;
                str_data += len + 1;
        }
        argv_ptr[argc] = NULL;

        log(PLOG_DEBUG, PLUGIN_NAME, 
                        "script_path=%s", 
                        context->argv[SCRIPT_NAME_IDX]);

        /* Pass state back to OpenVPN so we get handed it back later */
        retptr->handle = (openvpn_plugin_handle_t) context;

        log(PLOG_DEBUG, PLUGIN_NAME, "plugin initialized successfully");

        return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/* Called when we need to handle OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY calls */
OPENVPN_EXPORT int openvpn_plugin_func_v3(const int struct_version,
                struct openvpn_plugin_args_func_in const *arguments,
                struct openvpn_plugin_args_func_return *retptr)
{
        (void)retptr; /* Squish -Wunused-parameter warning */
        struct plugin_context *context = 
                (struct plugin_context *) arguments->handle;

        /* Safeguard on openvpn versions */
        if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
                context->plugin_log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: struct version was older than required");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        if(arguments->type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
                context->plugin_log(PLOG_DEBUG, PLUGIN_NAME,
                                "Handling auth with deferred script");
                return deferred_handler(context, arguments->envp);
        }
        
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
        struct plugin_context *context = (struct plugin_context *) handle;
        free(context);
}
