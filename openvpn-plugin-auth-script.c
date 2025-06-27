/*
 * auth-script OpenVPN plugin - High Concurrency Version
 * 
 * Runs an external script to decide whether to authenticate a user or not.
 * Optimized for maximum concurrent authentication requests without blocking.
 */

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
#include <limits.h>
#include <signal.h>
#include <pthread.h>
#include <sys/resource.h>

/********** Constants */
#define PLUGIN_NAME "auth-script"
#define OPENVPN_PLUGIN_VERSION_MIN 3
#define MAX_SCRIPT_ARGS 64
#define MAX_ARG_LENGTH 4096
#define MAX_CONCURRENT_AUTHS 1000
#define CLEANUP_INTERVAL 30  /* seconds */

/* Return codes for better readability */
#define AUTH_SUCCESS 0
#define AUTH_FAILURE 1
#define AUTH_DEFERRED 2
#define AUTH_ERROR 3

/* Process tracking structure */
struct auth_process {
    pid_t pid;
    time_t start_time;
    int active;
    struct auth_process *next;
};

/* Thread-safe process list */
struct process_list {
    struct auth_process *head;
    pthread_mutex_t mutex;
    int count;
};

/* Plugin context structure */
struct plugin_context {
    plugin_log_t plugin_log;
    char *script_path;
    char **script_args;
    int arg_count;
    struct process_list *processes;
    pthread_t cleanup_thread;
    int cleanup_running;
    int max_concurrent;
};

/* Global signal handler setup */
static void setup_signal_handlers(void) {
    /* Ignore SIGCHLD to prevent zombie processes */
    signal(SIGCHLD, SIG_IGN);
    
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
}

/* Get system limits for maximum processes */
static int get_max_processes(plugin_log_t log) {
    struct rlimit rlim;
    int max_proc = MAX_CONCURRENT_AUTHS;
    
    if (getrlimit(RLIMIT_NPROC, &rlim) == 0) {
        /* Use 80% of available processes to leave headroom */
        int system_max = (int)(rlim.rlim_cur * 0.8);
        if (system_max > 0 && system_max < max_proc) {
            max_proc = system_max;
        }
    }
    
    log(PLOG_NOTE, PLUGIN_NAME, "Maximum concurrent authentications: %d", max_proc);
    return max_proc;
}

/* Initialize process tracking */
static struct process_list* init_process_list(plugin_log_t log) {
    struct process_list *list = calloc(1, sizeof(struct process_list));
    if (!list) {
        log(PLOG_ERR, PLUGIN_NAME, "Failed to allocate process list");
        return NULL;
    }
    
    if (pthread_mutex_init(&list->mutex, NULL) != 0) {
        log(PLOG_ERR, PLUGIN_NAME, "Failed to initialize mutex");
        free(list);
        return NULL;
    }
    
    list->head = NULL;
    list->count = 0;
    return list;
}

/* Add process to tracking list */
static int add_process(struct process_list *list, pid_t pid, plugin_log_t log) {
    struct auth_process *proc = calloc(1, sizeof(struct auth_process));
    if (!proc) {
        log(PLOG_ERR, PLUGIN_NAME, "Failed to allocate process structure");
        return 0;
    }
    
    proc->pid = pid;
    proc->start_time = time(NULL);
    proc->active = 1;
    
    pthread_mutex_lock(&list->mutex);
    proc->next = list->head;
    list->head = proc;
    list->count++;
    pthread_mutex_unlock(&list->mutex);
    
    return 1;
}

/* Remove finished processes from tracking list */
static void cleanup_processes(struct process_list *list, plugin_log_t log) {
    struct auth_process *current, *prev, *to_free;
    int cleaned = 0;
    
    pthread_mutex_lock(&list->mutex);
    
    prev = NULL;
    current = list->head;
    
    while (current) {
        /* Check if process is still running */
        if (current->active && kill(current->pid, 0) != 0) {
            /* Process is dead, mark for cleanup */
            current->active = 0;
        }
        
        /* Remove inactive processes */
        if (!current->active) {
            to_free = current;
            if (prev) {
                prev->next = current->next;
                current = current->next;
            } else {
                list->head = current->next;
                current = current->next;
            }
            free(to_free);
            list->count--;
            cleaned++;
        } else {
            prev = current;
            current = current->next;
        }
    }
    
    pthread_mutex_unlock(&list->mutex);
    
    if (cleaned > 0) {
        log(PLOG_DEBUG, PLUGIN_NAME, "Cleaned up %d finished processes", cleaned);
    }
}

/* Background cleanup thread */
static void* cleanup_thread_func(void *arg) {
    struct plugin_context *context = (struct plugin_context*)arg;
    plugin_log_t log = context->plugin_log;
    
    log(PLOG_DEBUG, PLUGIN_NAME, "Cleanup thread started");
    
    while (context->cleanup_running) {
        sleep(CLEANUP_INTERVAL);
        if (context->cleanup_running) {
            cleanup_processes(context->processes, log);
        }
    }
    
    log(PLOG_DEBUG, PLUGIN_NAME, "Cleanup thread stopped");
    return NULL;
}

/* Get current process count */
static int get_process_count(struct process_list *list) {
    int count;
    pthread_mutex_lock(&list->mutex);
    count = list->count;
    pthread_mutex_unlock(&list->mutex);
    return count;
}

/* Utility function to validate script path */
static int validate_script_path(const char *path, plugin_log_t log) {
    struct stat st;
    
    if (!path || strlen(path) == 0) {
        log(PLOG_ERR, PLUGIN_NAME, "Empty script path provided");
        return 0;
    }
    
    if (strlen(path) >= PATH_MAX) {
        log(PLOG_ERR, PLUGIN_NAME, "Script path too long: %zu chars", strlen(path));
        return 0;
    }
    
    if (stat(path, &st) != 0) {
        log(PLOG_ERR, PLUGIN_NAME, "Script not found: %s", path);
        return 0;
    }
    
    if (!S_ISREG(st.st_mode)) {
        log(PLOG_ERR, PLUGIN_NAME, "Script path is not a regular file: %s", path);
        return 0;
    }
    
    if (!(st.st_mode & S_IXUSR)) {
        log(PLOG_ERR, PLUGIN_NAME, "Script is not executable: %s", path);
        return 0;
    }
    
    return 1;
}

/* Safely copy arguments with bounds checking */
static int copy_script_args(struct plugin_context *context, 
                           const char * const *argv, 
                           plugin_log_t log) {
    int i;
    
    /* Count arguments (skip argv[0] which is the plugin path) */
    for (i = 1; argv[i] && i < MAX_SCRIPT_ARGS; i++) {
        if (strlen(argv[i]) >= MAX_ARG_LENGTH) {
            log(PLOG_ERR, PLUGIN_NAME, "Argument %d too long", i);
            return 0;
        }
    }
    
    if (i >= MAX_SCRIPT_ARGS) {
        log(PLOG_ERR, PLUGIN_NAME, "Too many arguments provided");
        return 0;
    }
    
    context->arg_count = i - 1;  /* Don't count plugin path */
    
    /* Allocate array for argument pointers plus NULL terminator */
    context->script_args = calloc(context->arg_count + 1, sizeof(char*));
    if (!context->script_args) {
        log(PLOG_ERR, PLUGIN_NAME, "Failed to allocate memory for arguments");
        return 0;
    }
    
    /* Copy each argument */
    for (i = 0; i < context->arg_count; i++) {
        context->script_args[i] = strdup(argv[i + 1]);
        if (!context->script_args[i]) {
            log(PLOG_ERR, PLUGIN_NAME, "Failed to copy argument %d", i);
            return 0;
        }
    }
    
    context->script_path = context->script_args[0];
    return 1;
}

/* Clean up allocated resources */
static void cleanup_context(struct plugin_context *context) {
    if (context) {
        /* Stop cleanup thread */
        if (context->cleanup_running) {
            context->cleanup_running = 0;
            pthread_join(context->cleanup_thread, NULL);
        }
        
        /* Clean up process list */
        if (context->processes) {
            cleanup_processes(context->processes, context->plugin_log);
            pthread_mutex_destroy(&context->processes->mutex);
            free(context->processes);
        }
        
        /* Clean up script args */
        if (context->script_args) {
            for (int i = 0; i < context->arg_count; i++) {
                free(context->script_args[i]);
            }
            free(context->script_args);
        }
        
        free(context);
    }
}

/* High-performance asynchronous authentication handler */
static int deferred_handler(struct plugin_context *context, const char *envp[]) {
    plugin_log_t log = context->plugin_log;
    pid_t pid;
    int current_count;
    
    /* Check if we're at capacity */
    current_count = get_process_count(context->processes);
    if (current_count >= context->max_concurrent) {
        /* Try cleanup first */
        cleanup_processes(context->processes, log);
        current_count = get_process_count(context->processes);
        
        if (current_count >= context->max_concurrent) {
            log(PLOG_ERR, PLUGIN_NAME, 
                "Maximum concurrent authentications reached: %d", current_count);
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    }
    
    log(PLOG_DEBUG, PLUGIN_NAME, 
        "Starting auth %d/%d: %s", current_count + 1, context->max_concurrent, 
        context->script_path);
    
    /* Fork for asynchronous execution */
    pid = fork();
    if (pid < 0) {
        log(PLOG_ERR, PLUGIN_NAME, "Fork failed: %s", strerror(errno));
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    if (pid > 0) {
        /* Parent - track the process and return immediately */
        if (!add_process(context->processes, pid, log)) {
            log(PLOG_ERR, PLUGIN_NAME, "Failed to track process %d", pid);
            /* Kill the child since we can't track it */
            kill(pid, SIGKILL);
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
        
        log(PLOG_DEBUG, PLUGIN_NAME, "Started auth process %d", pid);
        return OPENVPN_PLUGIN_FUNC_DEFERRED;
    }
    
    /* Child process - execute script and exit */
    
    /* Detach from parent process group */
    setsid();
    
    /* Close unnecessary file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    /* Change to root directory */
    if (chdir("/") < 0) {
        /* Continue anyway */
    }
    
    /* Execute the authentication script */
    execve(context->script_path, context->script_args, (char * const *)envp);
    
    /* If execve fails, exit with error */
    _exit(AUTH_ERROR);
}

/* API Functions */

OPENVPN_EXPORT int openvpn_plugin_min_version_required_v1() {
    return OPENVPN_PLUGIN_VERSION_MIN;
}

OPENVPN_EXPORT int openvpn_plugin_open_v3(const int struct_version,
                struct openvpn_plugin_args_open_in const *arguments,
                struct openvpn_plugin_args_open_return *retptr) {
    
    plugin_log_t log = arguments->callbacks->plugin_log;
    struct plugin_context *context = NULL;
    
    log(PLOG_DEBUG, PLUGIN_NAME, "Initializing high-concurrency plugin");
    
    /* Setup signal handlers */
    setup_signal_handlers();
    
    /* Version check */
    if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
        log(PLOG_ERR, PLUGIN_NAME, "Incompatible plugin API version");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    /* Check if script path is provided */
    if (!arguments->argv[1]) {
        log(PLOG_ERR, PLUGIN_NAME, "No script path specified in configuration");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    /* Validate script path */
    if (!validate_script_path(arguments->argv[1], log)) {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    /* Allocate context */
    context = calloc(1, sizeof(struct plugin_context));
    if (!context) {
        log(PLOG_ERR, PLUGIN_NAME, "Failed to allocate plugin context");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    context->plugin_log = log;
    context->max_concurrent = get_max_processes(log);
    
    /* Initialize process tracking */
    context->processes = init_process_list(log);
    if (!context->processes) {
        cleanup_context(context);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    /* Copy script arguments */
    if (!copy_script_args(context, arguments->argv, log)) {
        cleanup_context(context);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    /* Start cleanup thread */
    context->cleanup_running = 1;
    if (pthread_create(&context->cleanup_thread, NULL, cleanup_thread_func, context) != 0) {
        log(PLOG_ERR, PLUGIN_NAME, "Failed to create cleanup thread");
        context->cleanup_running = 0;
        cleanup_context(context);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    /* Configure plugin to handle authentication */
    retptr->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
    retptr->handle = (openvpn_plugin_handle_t) context;
    
    log(PLOG_NOTE, PLUGIN_NAME, 
        "High-concurrency plugin initialized: script=%s, max_concurrent=%d", 
        context->script_path, context->max_concurrent);
    
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int openvpn_plugin_func_v3(const int struct_version,
                struct openvpn_plugin_args_func_in const *arguments,
                struct openvpn_plugin_args_func_return *retptr) {
    
    (void)retptr; /* Suppress unused parameter warning */
    
    struct plugin_context *context = (struct plugin_context *) arguments->handle;
    plugin_log_t log = context->plugin_log;
    
    /* Version check */
    if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
        log(PLOG_ERR, PLUGIN_NAME, "Incompatible plugin API version");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    /* Handle authentication request */
    if (arguments->type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
        return deferred_handler(context, arguments->envp);
    }
    
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle) {
    struct plugin_context *context = (struct plugin_context *) handle;
    if (context) {
        context->plugin_log(PLOG_DEBUG, PLUGIN_NAME, "Closing high-concurrency plugin");
        cleanup_context(context);
    }
}
