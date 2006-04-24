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
#include <stdarg.h>
#include "security.h"
#define NUTCPC_VERSION "2.0-beta1"

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

char * computerunpid(){
    char path_dir[254];
    char *home = getenv("HOME");
    if (home == NULL)
        return NULL;            
	snprintf(path_dir,sizeof(path_dir),"%s/.nufw", home);
	if (access(path_dir,R_OK)){
		mkdir(path_dir,S_IRWXU);
	}
	snprintf(path_dir, sizeof(path_dir), "%s/.nufw/.nutcpc", home);
	return strdup(path_dir);
}

/**
 * Kill existing instance of nutcpc: read pid file, 
 * and then send SIGTERM to the process. 
 *
 * Exit the program at the end of this function.
 */
void kill_nutcpc(){
	pid_t pid;
	FILE* FD;
        int ok, ret;
	char* runpid;
        
        ok = 0;
        runpid=computerunpid();
	if (runpid){
		FD = fopen(runpid,"r");
		if (FD){
			fscanf(FD,"%d",&pid);
			fclose(FD);
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
        } else {
            exit(EXIT_SUCCESS);
        }
}

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
        nu_client_free(session,err);
    }


    runpid=computerunpid();
    if (runpid != NULL)
    {
        unlink(runpid);
        free(runpid);
    }
    nu_client_global_deinit(err);
    nuclient_error_destroy(err);
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

	line = fgetln(stream, &len);
	if (!line)
		return -1;
	if (len >= *n) {
		char *tmp;

		/* XXX some realloc() implementations don't set errno */
		tmp = realloc(*lineptr, len + 1);
		if (!tmp)
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
 * Callback used in nu_client_init2() call: read password
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
    return new_pass;
}

/**
 * Callback used in nu_client_init2() call: read user name 
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

static void usage (void)
{
	fprintf (stderr, "usage: nutcpc [-kldV]  [-I interval] "
			"[-U username ] [-H nuauth_srv]\n");
	exit (EXIT_FAILURE);
}

int firstrule = 1;


int main (int argc, char *argv[])
{
	unsigned long interval = 100;
	char srv_addr[512]=NUAUTH_IP;
	int ch;
	int debug = 0;
	struct sigaction action;
	unsigned int port=4130;
	int tempo=1;
	unsigned char donotuselock=0;
	char* runpid=computerunpid();

#if USE_UTF8
	/* needed by iconv */
	setlocale (LC_ALL, "");
#endif
	/*
	 * Parse our arguments.
	 */
	opterr = 0;
	while ((ch = getopt (argc, argv, "kldVu:H:I:U:p:")) != -1) {
		switch (ch) {
			case 'H':
				SECURE_STRNCPY(srv_addr, optarg, sizeof(srv_addr));
				break;
			case 'd':
				debug = 1;
				break;
			case 'I':
				interval = atoi (optarg);
				if (interval == 0) {
					fprintf (stderr, "nutcpc: bad interval\n");
					exit (EXIT_FAILURE);
				}
				break;
			case 'l':
				donotuselock=1;
				break;
			case 'U':
				saved_username=strdup(optarg);
				break;
			case 'k':
				kill_nutcpc();
				break;
			case 'V':
				printf("nutcpc (version " NUTCPC_VERSION ")\n");
				exit(0);
			case 'p':
				sscanf(optarg,"%u",&port);
                                break;
			default:
				usage();
		}
	}

	if (debug == 0){
		if (donotuselock == 0) {
			if (! access(runpid,R_OK)){
				printf("Lock file found: %s\n",runpid);
                                printf("Kill existing process with \"-k\" or ignore it with \"-l\" option\n");
				free(runpid);
                                free(saved_username);
				exit(EXIT_FAILURE);
			}
		}
	}


	/* signal management */
	action.sa_handler = exit_clean;
	sigemptyset( & (action.sa_mask));
	action.sa_flags = 0;
	if ( sigaction( SIGINT, & action , &old_sigint) != 0) {
		printf("Error\n");
		exit(1);
	}
	if ( sigaction( SIGTERM, & action , &old_sigterm) != 0) {
		printf("Error\n");
		exit(1);
	}

        if (nuclient_error_init(&err) != 0)
        {
            printf("Cannot init error structure!\n");
            exit(-1);
        }

        /* global libnuclient init */
        nu_client_global_init(err);
        
        printf("Connecting to NuFw gateway\n");
	session = nu_client_init2(
			srv_addr,
			port,
			NULL,
			NULL,
			&get_username,
			&get_password,
			NULL,
                        err
			);

	if (!session){
		printf("\nCan not initiate connection to NuFW gateway\n");
                printf("Problem: %s\n",nuclient_strerror(err));
		exit(EXIT_FAILURE);
	}

        /* store username and password */
        if (session->username) {
            free(saved_username);
            saved_username=strdup(session->username);
        }
        if (session->password) {
            saved_password=strdup(session->password);
        }

	/*
	 * Become a daemon by double-forking and detaching completely from
	 * the terminal.
	 */

	if (debug == 0) {
		pid_t p;

		/* 1st fork */
		p = fork();
		if (p < 0) {
			fprintf (stderr, "nutcpc: fork: %s\n",
					strerror (errno));
			exit (EXIT_FAILURE);
		} else if (p != 0)
			exit (0);
		/* 2nd fork */
		p = fork();
		if (p < 0) {
			fprintf (stderr, "nutcpc: fork: %s\n",
					strerror (errno));
			exit (EXIT_FAILURE);
		} else if (p != 0) {
			fprintf (stderr, "nutcpc started (pid %d)\n", 
					(int) p);
			if (donotuselock==0){
				FILE* RunD;
				RunD=fopen(runpid,"w");
				free(runpid);
				fprintf(RunD,"%d",p);
				fclose(RunD);
			}
			exit (EXIT_SUCCESS);
		}
                setsid();
		ioctl (STDIN_FILENO, TIOCNOTTY, NULL);
		close (STDIN_FILENO); 
		close (STDOUT_FILENO); 
		close (STDERR_FILENO); 
		setpgid (0, 0);
		chdir ("/");
	} else {
		fprintf (stderr, "nutcpc " NUTCPC_VERSION " started (debug)\n");
	}
        free(runpid);


	for (;;) {
		usleep (interval * 1000);
		if (session == NULL){
			sleep(tempo);
			if (tempo< MAX_RETRY_TIME) {
				tempo=tempo*2;
			}
			session = nu_client_init2(
					srv_addr,
					port,
					NULL,
					NULL,
					&get_username,
					&get_password,
					NULL,
                                        err
					);
			if (session!=NULL){
				tempo=1;
			}else{
                            printf("%s\n",nuclient_strerror(err));
                        }
		} else {
			if (nu_client_check(session,err)<0){
				session=NULL;
                                printf("%s\n",nuclient_strerror(err));
			}
		}
	}
        leave_client();
	exit (EXIT_SUCCESS);
}
