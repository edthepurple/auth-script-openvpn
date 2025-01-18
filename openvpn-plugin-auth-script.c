/* 
 * Multi-threaded auth-script OpenVPN plugin
 * Runs authentication scripts in a thread pool for better performance
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
#include <pthread.h>
#include <semaphore.h>

#define PLUGIN_NAME "auth-script"
#define OPENVPN_PLUGIN_VERSION_MIN 3
#define SCRIPT_NAME_IDX 0
#define MAX_THREADS 10
#define MAX_QUEUE_SIZE 100

/* Structure for queued authentication requests */
struct auth_request {
    const char **envp;
    struct plugin_context *context;
    int result;
    sem_t completion_sem;
    struct auth_request *next;
};

/* Thread pool and queue structures */
struct thread_pool {
    pthread_t threads[MAX_THREADS];
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_not_empty;
    pthread_cond_t queue_not_full;
    struct auth_request *queue_head;
    struct auth_request *queue_tail;
    int queue_size;
    int shutdown;
};

/* Plugin context with thread pool */
struct plugin_context {
    plugin_log_t plugin_log;
    struct thread_pool *pool;
    const char *argv[];
};

/* Forward declarations */
static void *worker_thread(void *arg);
static int process_auth_request(struct auth_request *request);

/* Initialize thread pool */
static struct thread_pool *create_thread_pool(plugin_log_t log) {
    struct thread_pool *pool = malloc(sizeof(struct thread_pool));
    if (!pool) return NULL;

    pool->queue_head = NULL;
    pool->queue_tail = NULL;
    pool->queue_size = 0;
    pool->shutdown = 0;

    pthread_mutex_init(&pool->queue_mutex, NULL);
    pthread_cond_init(&pool->queue_not_empty, NULL);
    pthread_cond_init(&pool->queue_not_full, NULL);

    for (int i = 0; i < MAX_THREADS; i++) {
        if (pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
            log(PLOG_ERR, PLUGIN_NAME, "Failed to create worker thread");
            // Cleanup and return NULL on failure
            for (int j = 0; j < i; j++) {
                pthread_cancel(pool->threads[j]);
            }
            pthread_mutex_destroy(&pool->queue_mutex);
            pthread_cond_destroy(&pool->queue_not_empty);
            pthread_cond_destroy(&pool->queue_not_full);
            free(pool);
            return NULL;
        }
    }

    return pool;
}

/* Worker thread function */
static void *worker_thread(void *arg) {
    struct thread_pool *pool = (struct thread_pool *)arg;
    struct auth_request *request;

    while (1) {
        pthread_mutex_lock(&pool->queue_mutex);

        while (pool->queue_size == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->queue_not_empty, &pool->queue_mutex);
        }

        if (pool->shutdown && pool->queue_size == 0) {
            pthread_mutex_unlock(&pool->queue_mutex);
            pthread_exit(NULL);
        }

        request = pool->queue_head;
        if (request) {
            pool->queue_head = request->next;
            if (pool->queue_head == NULL) {
                pool->queue_tail = NULL;
            }
            pool->queue_size--;
        }

        pthread_cond_signal(&pool->queue_not_full);
        pthread_mutex_unlock(&pool->queue_mutex);

        if (request) {
            request->result = process_auth_request(request);
            sem_post(&request->completion_sem);
        }
    }

    return NULL;
}

/* Process individual authentication request */
static int process_auth_request(struct auth_request *request) {
    plugin_log_t log = request->context->plugin_log;
    pid_t pid;

    pid = fork();

    if (pid < 0) {
        log(PLOG_ERR, PLUGIN_NAME, "Fork failed with error %d", errno);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    if (pid > 0) {
        pid_t wait_rc;
        int wstatus;

        wait_rc = waitpid(pid, &wstatus, 0);

        if (wait_rc < 0) {
            log(PLOG_ERR, PLUGIN_NAME, "Wait failed for pid %d", pid);
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        if (WIFEXITED(wstatus)) {
            return WEXITSTATUS(wstatus);
        }

        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* Child process */
    pid = fork();

    if (pid < 0) {
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    if (pid > 0) {
        exit(OPENVPN_PLUGIN_FUNC_DEFERRED);
    }

    /* Grandchild process */
    umask(0);
    setsid();
    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    execve(request->context->argv[0],
           (char *const*)request->context->argv,
           (char *const*)request->envp);

    /* If execve fails, log the error */
    log(PLOG_ERR, PLUGIN_NAME, "Execve failed with errno %d", errno);
    exit(EXIT_FAILURE);
}

/* Queue a new authentication request */
static int queue_auth_request(struct plugin_context *context, const char *envp[]) {
    struct auth_request *request = malloc(sizeof(struct auth_request));
    if (!request) return OPENVPN_PLUGIN_FUNC_ERROR;

    request->context = context;
    request->envp = envp;
    request->next = NULL;
    sem_init(&request->completion_sem, 0, 0);

    pthread_mutex_lock(&context->pool->queue_mutex);

    while (context->pool->queue_size >= MAX_QUEUE_SIZE) {
        pthread_cond_wait(&context->pool->queue_not_full, &context->pool->queue_mutex);
    }

    if (context->pool->queue_tail) {
        context->pool->queue_tail->next = request;
    } else {
        context->pool->queue_head = request;
    }
    context->pool->queue_tail = request;
    context->pool->queue_size++;

    pthread_cond_signal(&context->pool->queue_not_empty);
    pthread_mutex_unlock(&context->pool->queue_mutex);

    /* Wait for completion */
    sem_wait(&request->completion_sem);
    int result = request->result;

    /* Cleanup */
    sem_destroy(&request->completion_sem);
    free(request);

    return result;
}

/* Plugin API implementation */
OPENVPN_EXPORT int openvpn_plugin_min_version_required_v1() {
    return OPENVPN_PLUGIN_VERSION_MIN;
}

OPENVPN_EXPORT int openvpn_plugin_open_v3(const int struct_version,
        struct openvpn_plugin_args_open_in const *arguments,
        struct openvpn_plugin_args_open_return *retptr) {
    plugin_log_t log = arguments->callbacks->plugin_log;

    if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
        log(PLOG_ERR, PLUGIN_NAME, "Plugin version too old");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    retptr->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

    size_t arg_size = 0;
    for (int arg_idx = 1; arguments->argv[arg_idx]; arg_idx++) {
        arg_size += strlen(arguments->argv[arg_idx]) + 1;
    }

    struct plugin_context *context = malloc(sizeof(struct plugin_context) + arg_size);
    if (!context) {
        log(PLOG_ERR, PLUGIN_NAME, "Failed to allocate context");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    memset(context, 0, sizeof(struct plugin_context) + arg_size);
    context->plugin_log = log;

    if (arg_size == 0) {
        log(PLOG_ERR, PLUGIN_NAME, "No script path specified");
        free(context);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    memcpy(&context->argv, &arguments->argv[1], arg_size);

    /* Initialize thread pool */
    context->pool = create_thread_pool(log);
    if (!context->pool) {
        log(PLOG_ERR, PLUGIN_NAME, "Failed to create thread pool");
        free(context);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    retptr->handle = (openvpn_plugin_handle_t)context;
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int openvpn_plugin_func_v3(const int struct_version,
        struct openvpn_plugin_args_func_in const *arguments,
        struct openvpn_plugin_args_func_return *retptr) {
    (void)retptr;
    struct plugin_context *context = (struct plugin_context *)arguments->handle;

    if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    if (arguments->type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
        return queue_auth_request(context, arguments->envp);
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle) {
    struct plugin_context *context = (struct plugin_context *)handle;
    
    if (context->pool) {
        /* Signal shutdown to all threads */
        pthread_mutex_lock(&context->pool->queue_mutex);
        context->pool->shutdown = 1;
        pthread_cond_broadcast(&context->pool->queue_not_empty);
        pthread_mutex_unlock(&context->pool->queue_mutex);

        /* Wait for all threads to finish */
        for (int i = 0; i < MAX_THREADS; i++) {
            pthread_join(context->pool->threads[i], NULL);
        }

        /* Clean up remaining requests */
        struct auth_request *request = context->pool->queue_head;
        while (request) {
            struct auth_request *next = request->next;
            sem_destroy(&request->completion_sem);
            free(request);
            request = next;
        }

        /* Cleanup thread pool resources */
        pthread_mutex_destroy(&context->pool->queue_mutex);
        pthread_cond_destroy(&context->pool->queue_not_empty);
        pthread_cond_destroy(&context->pool->queue_not_full);
        free(context->pool);
    }

    free(context);
}
