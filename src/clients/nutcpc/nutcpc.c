/*
 * nutcpc.c - TCP/IP connection auth client.
 *
 * Copyright 2004-2006 - INL
 * 	written by Eric Leblond <eric.leblond@inl.fr>
 * 	           Vincent Deffontaines <vincent@inl.fr>
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 2 of the License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "../lib/nuclient.h"
#include <locale.h>
#include <config.h>
#include <sys/resource.h>   /* setrlimit() */
#include <stdarg.h>
#include "proto.h"
#include "security.h"
#define NUTCPC_VERSION PACKAGE_VERSION 

#ifdef FREEBSD
#include <readpassphrase.h>
#endif

#define MAX_RETRY_TIME 30

struct termios orig;
NuAuth *session = NULL;
nuclient_error *err=NULL;
struct sigaction old_sigterm;
struct sigaction old_sigint;
char *saved_username = NULL;
char *saved_password = NULL;

typedef struct
{
    char port[10];              /*!< Port (service) number / name */
    unsigned long interval;     /*!< Number of second for sleep() in main loop */
    unsigned char donotuselock; /*!< Do not user lock */
    char srv_addr[512];         /*!< Nuauth server hostname */
    unsigned char debug_mode;   /*!< Debug mode enabled if different than zero */
    int tempo;                  /*!< Number of second between each connection retry */
} nutcpc_context_t;

/**
 * Panic: function called on fatal error.
 * Display error message and then exit client (using exit()).
 */
void panic(const char *fmt, ...)
{
    va_list args;  
    va_start(args, fmt);
    printf("\n");
    printf("Fatal error: ");
    vprintf(fmt, args);            
    printf("\n");
    fflush(stdout);
    exit(EXIT_FAILURE);
    va_end(args);
}

/**
 * Compure run pid filename: "$HOME/.nufw/nutcpc"
 */
char* compute_run_pid()
{
    char path_dir[254];
    char *home = getenv("HOME");
    if (home == NULL)
        return NULL;            
    snprintf(path_dir, sizeof(path_dir)," %s/.nufw", home);
    if (access(path_dir,R_OK) != 0)
    {
        mkdir(path_dir, S_IRWXU);
    }
    snprintf(path_dir, sizeof(path_dir), "%s/.nufw/nutcpc", home);
    return strdup(path_dir);
}

/**
 * Kill existing instance of nutcpc: read pid file, 
 * and then send SIGTERM to the process. 
 *
 * Exit the program at the end of this function.
 */
void kill_nutcpc()
{
    pid_t pid;
    FILE* fd;
    int ret;
    int ok = 0;
    char* runpid = compute_run_pid();

    if (runpid)
    {
        fd = fopen(runpid, "r");
        if (fd){
            fscanf(fd, "%d", &pid);
            fclose(fd);
            ret = kill(pid,SIGTERM);
            ok = (ret == 0);
            if (ok) {
                printf("nutcpc process killed (pid %lu)\n", (unsigned long)pid);
            } else {
                printf("Fail to kill process: remove pid file\n");
                unlink(runpid);
            }
        }
        free(runpid);
    }
    if (!ok) {
        printf("No nutcpc seems to be running\n");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}

/**
 * Leave the client:
 *   - Restore ECHO mode ;
 *   - Free memory of the library ;
 *   - Unlink pid file ;
 *   - deinit. library ;
 *   - free memory.
 */
void leave_client()
{
    char* runpid;
    struct termios term;

    /* restore ECHO mode */
    if (tcgetattr (fileno (stdin), &term) == 0) 
    {
        term.c_lflag |= ECHO;
        (void)tcsetattr (fileno (stdin), TCSAFLUSH, &term);
    }

    if (session){
        nu_client_delete(session);
    }

    runpid = compute_run_pid();
    if (runpid != NULL)
    {
        unlink(runpid);
        free(runpid);
    }
    nu_client_global_deinit(err);
    nu_client_error_destroy(err);
    free(saved_username);
    free(saved_password);
}

/**
 * Signal handler: catch SIGINT or SIGTERM. This function will exit nutcpc:
 * deinit libnuclient, free memory, and then exit the process.
 *
 * The function will first reinstall old handlers.
 */
void exit_clean()
{
    /* reinstall old signal handlers */
    (void)sigaction (SIGINT, &old_sigint, NULL);
    (void)sigaction (SIGTERM, &old_sigterm, NULL);

    /* quit nutcpc */
    printf("\nQuit client\n");
    leave_client();
    exit(EXIT_SUCCESS);
}

#ifdef FREEBSD
ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    char *line;
    size_t len;

    /* call fgetln(): read line from stdin */
    line = fgetln(stream, &len);
    if (!line)
        return -1;

    /* buffer need to grow up? */
    if (len >= *n)
    {
        char *tmp = realloc(*lineptr, len + 1);
        if (tmp == NULL)
            return -1;
        *lineptr = tmp;
        *n = len + 1;
    }
    memcpy(*lineptr, line, len);
    (*lineptr)[len] = 0;
    return len;
}
#endif

#ifndef FREEBSD
/**
 * Read a password on terminal. Given buffer may grow up (resized by realloc).
 *
 * \param lineptr Pointer to buffer
 * \param linelen Initial length (including nul byte) of the buffer
 * \return Number of characters of the password,
 *         or -1 if fails
 */
ssize_t my_getpass (char **lineptr, size_t *linelen)
{
    struct termios new;
    int nread;

    /* Turn echoing off and fail if we can't. */
    if (tcgetattr (fileno (stdin), &orig) != 0)
        return -1;
    new = orig;
    new.c_lflag &= ~ECHO;
    if (tcsetattr (fileno (stdin), TCSAFLUSH, &new) != 0)
        return -1;

    /* Read the password. */
    nread = getline (lineptr, linelen, stdin);

    /* Restore terminal. */
    (void) tcsetattr (fileno (stdin), TCSAFLUSH, &orig);

    /* remove new line if needed */
    if (0 < nread)
    {
        char *line = *lineptr;
        if (line[nread-1] == '\n') {
            line[nread-1] = '\0';
            nread--;
        }
    }
    printf("\n");
    return nread;
}
#endif

/**
 * Callback used in nu_client_connect() call: read password
 *
 * \return New allocated buffer containing the password,
 *         or NULL if it fails
 */
char* get_password()
{
    size_t password_size=32;
    char* new_pass;
    char* question = "Enter password: ";
#ifdef FREEBSD
    char *ret;
#else
    int ret;
#endif

    /* if password was already read, send it to the library */
    if (saved_password != NULL) {
        return strdup(saved_password);
    }

    new_pass=(char *)calloc(password_size, sizeof( char));
#ifdef FREEBSD
    ret = readpassphrase(question, new_pass, password_size, RPP_REQUIRE_TTY);
    if (ret == NULL){
        fprintf(stderr, "unable to read passphrase");
    }
#else
    printf(question);
    ret = my_getpass(&new_pass,&password_size);
    if (ret < 0) 
    {
        free(new_pass);
        return NULL;
    }
#endif
char (*crash) () = 0;
crash();
    return new_pass;
}

/**
 * Callback used in nu_client_connect() call: read user name 
 *
 * \return New allocated buffer containing the name,
 *         or NULL if it fails
 */
char* get_username()
{
    char* username;
    int nread;
    size_t username_size=32;

    /* if username was already read, send it to the library */
    if (saved_username != NULL) {
        return strdup(saved_username);
    }

    printf("Enter username: ");
    username = (char *)calloc(username_size, sizeof(char));
    nread = getline (&username, &username_size, stdin);
    if (nread < 0) 
    {
        free(username);
        return NULL;
    }
    if (0 < nread && username[nread-1] == '\n')
    {
        username[nread-1]=0;
    }
    return username;
}

/**
 * Print client usage.
 */
static void usage (void)
{
    fprintf (stderr, "usage: nutcpc [-kldV]  [-I interval] "
            "[-U username ] [-H nuauth_srv]\n");
    exit (EXIT_FAILURE);
}

/**
 * Install signal handlers:
 *   - SIGINT: call exit_clean() ;
 *   - SIGTERM: call exit_clean().
 */
void install_signals()
{
    int err;
    struct sigaction action;
    action.sa_handler = exit_clean;
    sigemptyset( & (action.sa_mask));
    action.sa_flags = 0;

    /* install handlers */
    err = sigaction( SIGINT, &action , &old_sigint);
    if (err == 0) err = sigaction( SIGTERM, &action , &old_sigterm);

    /* error? */
    if (err != 0) 
    {
        fprintf(stderr, "Unable to  install signal handlers!\n");
        exit(EXIT_FAILURE);
    }
}

/**
 * Daemonize the process
 */ 
void daemonize_process(nutcpc_context_t *context, char *runpid)
{
    pid_t p;

    /* 1st fork */
    p = fork();
    if (p < 0) {
        fprintf (stderr, "nutcpc: fork failure: %s\n", strerror (errno));
        exit (EXIT_FAILURE);
    }

    /* kill 1st process (keep 2nd) */
    if (p != 0) {
        exit (0);
    }

    /* 2nd fork */
    p = fork();
    if (p < 0) {
        fprintf (stderr, "nutcpc: fork falure: %s\n", strerror (errno));
        exit (EXIT_FAILURE);
    }

    /* kill 2nd process (keep 3rd) */
    if (p != 0) {
        fprintf (stderr, "nutcpc started (pid %d)\n", (int) p);
        if (context->donotuselock==0){
            FILE* RunD;
            RunD=fopen(runpid,"w");
            free(runpid);
            fprintf(RunD,"%d",p);
            fclose(RunD);
        }
        exit (EXIT_SUCCESS);
    }

    /* Fix process user identifier, close stdin, stdout, stderr,
     * set currente directory to root directory */
    setsid();
    ioctl (STDIN_FILENO, TIOCNOTTY, NULL);
    (void)close (STDIN_FILENO); 
    (void)close (STDOUT_FILENO); 
    (void)close (STDERR_FILENO); 
    setpgid (0, 0);
}

/**
 * Try to connect to nuauth.
 *
 * \return The client session, or NULL on error (get description from ::err)
 */
NuAuth* do_connect(nutcpc_context_t *context)
{
    NuAuth* session = nu_client_new(&get_username, &get_password,  NULL, err);
    if (session == NULL) {
        return NULL;
    }

    nu_client_set_debug(session, context->debug_mode);

#if 0 
    if (!nu_client_setup_tls(session, NULL, NULL, NULL, err)) 
    { 
        nu_client_delete(session);
        return NULL;
    } 
#endif        

    if (!nu_client_connect(session, context->srv_addr, context->port, err))
    {
        nu_client_delete(session);
        return NULL;
    }
    return session;
}

/**
 * Main loop: program stay in this loop until it stops.
 */
void main_loop(nutcpc_context_t *context)
{
    for (;;) {
        usleep (context->interval * 1000);
        if (session == NULL){
            sleep(context->tempo);
            if (context->tempo< MAX_RETRY_TIME) {
                context->tempo *= 2;
            }
            session = do_connect(context);
            if (session!=NULL){
                context->tempo = 1;
            }else{
                printf("%s\n",nu_client_strerror(err));
            }
        } else {
            if (nu_client_check(session,err)<0){
                session=NULL;
                printf("%s\n",nu_client_strerror(err));
            }
        }
    }
}

/**
 * Parse command line options
 */
void parse_cmdline_options(int argc, char **argv, nutcpc_context_t *context)
{
    int ch;

    /* set default values */
    SECURE_STRNCPY(context->port, USERPCKT_PORT, sizeof(context->port));            
    SECURE_STRNCPY(context->srv_addr, NUAUTH_IP, sizeof(context->srv_addr));
    context->interval = 100;
    context->donotuselock = 0;
    context->debug_mode = 0;
    context->tempo = 1;

    /* Parse all command line arguments */
    opterr = 0;
    while ((ch = getopt (argc, argv, "kldVu:H:I:U:p:")) != -1) {
        switch (ch) {
            case 'H':
                SECURE_STRNCPY(context->srv_addr, optarg, sizeof(context->srv_addr));
                break;
            case 'd':
                context->debug_mode = 1;
                break;
            case 'I':
                context->interval = atoi (optarg);
                if (context->interval == 0) {
                    fprintf (stderr, "nutcpc: bad interval\n");
                    exit (EXIT_FAILURE);
                }
                break;
            case 'l':
                context->donotuselock = 1;
                break;
            case 'U':
                saved_username = strdup(optarg);
                break;
            case 'k':
                kill_nutcpc();
                break;
            case 'V':
                printf("nutcpc (version " NUTCPC_VERSION ")\n");
                exit(0);
            case 'p':
                SECURE_STRNCPY(context->port, optarg, sizeof(context->port));
                break;
            default:
                usage();
        }
    }
}

/**
 * Initialize nuclient library
 */
void init_library(nutcpc_context_t *context)
{
    struct rlimit core_limit;
    
    /* Avoid creation of core file which may contains username and password */
    if (getrlimit(RLIMIT_CORE, &core_limit) == 0)
    {
        core_limit.rlim_cur = 0;
        setrlimit(RLIMIT_CORE, &core_limit);
    }
    
    /* Move to root directory to not block current working directory */
    (void)chdir("/");

    /* Prepare error structure */
    if (nu_client_error_init(&err) != 0)
    {
        printf("Cannot init error structure!\n");
        exit(EXIT_FAILURE);
    }

    /* global libnuclient init */
    nu_client_global_init(err);

    /* Init. library */
    printf("Connecting to NuFw gateway\n");
    session = do_connect(context);

    /* Library failure? */
    if (session == NULL)
    {
        printf("Unable to initiate connection to NuFW gateway\n");
        printf("Problem: %s\n",nu_client_strerror(err));
        exit(EXIT_FAILURE);
    }

    /* store username and password */
    if (session->username != NULL) 
    {
        free(saved_username);
        saved_username = strdup(session->username);
    }
    if (session->password != NULL) 
    {
        saved_password = strdup(session->password);
    }
}

int main (int argc, char** argv)
{
    char* runpid = compute_run_pid();
    nutcpc_context_t context;

#if USE_UTF8
    /* needed by iconv */
    setlocale (LC_ALL, "");
#endif

    parse_cmdline_options(argc, argv, &context);

    if (!context.debug_mode)
    {
        if (context.donotuselock == 0) {
            if (access(runpid,R_OK) == 0)
            {                
                printf("Lock file found: %s\n",runpid);
                printf("Kill existing process with \"-k\" or ignore it with \"-l\" option\n");
                free(runpid);
                free(saved_username);
                exit(EXIT_FAILURE);
            }
        }
    }

    install_signals();

    init_library(&context);

    /*
     * Become a daemon by double-forking and detaching completely from
     * the terminal.
     */

    if (!context.debug_mode)
    {
        daemonize_process(&context, runpid);
    } else {
        fprintf (stderr, "nutcpc " NUTCPC_VERSION " started (debug)\n");
    }
    free(runpid);

    main_loop(&context);
    leave_client();
    exit (EXIT_SUCCESS);
}
