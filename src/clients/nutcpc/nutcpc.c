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
#define NUTCPC_VERSION "1.1"

#ifdef FREEBSD
#include <readpassphrase.h>
#endif

#define MAX_RETRY_TIME 30

struct termios orig;

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

void exit_nutcpc(){
	pid_t pid;
	FILE* FD;
	char* runpid=computerunpid();
	if (runpid){
		FD = fopen(runpid,"r");
		if (FD){
			fscanf(FD,"%d",&pid);
			fclose(FD);
			kill(pid,SIGTERM);
		} else {
			printf("No nutcpc seems to be running (no lock file found)\n");
		}

	}
        exit(0);
}

void exit_clean()
{
	char* runpid=computerunpid();
	struct termios term;

        /* restore ECHO mode */
        printf("\n");
	if (tcgetattr (fileno (stdin), &term) == 0) 
        {
            term.c_lflag |= ECHO;
            (void)tcsetattr (fileno (stdin), TCSAFLUSH, &term);
        }

        nuclient_error *err=NULL;
        nuclient_error_init(&err);
	unlink(runpid);
	free(runpid);
        nu_client_global_deinit(err);
        nuclient_error_destroy(err);
	exit(EXIT_SUCCESS);
}

#ifdef FREEBSD
ssize_t
getline(char **lineptr, size_t *n, FILE *stream)
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



	ssize_t
my_getpass (char **lineptr, size_t *n)
{
	struct termios  new;
	int nread;

	/* Turn echoing off and fail if we can't. */
	if (tcgetattr (fileno (stdin), &orig) != 0)
		return -1;
	new = orig;
	new.c_lflag &= ~ECHO;
	if (tcsetattr (fileno (stdin), TCSAFLUSH, &new) != 0)
		return -1;

	/* Read the password. */
#ifdef LINUX
	nread = getline (lineptr, n, stdin);
#endif

	/* Restore terminal. */
	(void) tcsetattr (fileno (stdin), TCSAFLUSH, &orig);

	return nread;
}

char* password;

char* get_password()
{
	char* passwd;
	size_t password_size=32;
	if (password == NULL){
		passwd=(char *)calloc(32,sizeof( char));
#ifdef LINUX
		printf("Enter password: ");
		my_getpass(&passwd,&password_size);

		if (strlen(passwd)<password_size) {
			passwd[strlen(passwd)-1]=0;
		}
#else 
 if (readpassphrase("Enter password: ", passwd, password_size,
               RPP_REQUIRE_TTY) == NULL){
                  fprintf(stderr, "unable to read passphrase");
}
#endif

	} else {
		passwd=strdup(password);
	}
	return passwd;
}

char * username;
char * get_username()
{
	char* user;
	int nread;
	size_t username_size=64;

	if (username == NULL){
		printf("Enter username: ");
		user=(char *)calloc(64,sizeof( char));
		nread = getline (&user, &username_size, stdin);
		user[64]=0;
	} else {
		user = strdup(username);
	}
	return user;
}

static void usage (void)
{
	fprintf (stderr, "usage: nutcpc [-kldV]  [-I interval] "
			"[-U userid ] [-H nuauth_srv]\n");
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
	NuAuth *session;
	int userid;
	int tempo=1;
	unsigned char donotuselock=0;
	char* runpid=computerunpid();
        nuclient_error *err=NULL;

#if USE_UTF8
	/* needed by iconv */
	setlocale (LC_ALL, "");
#endif
	/*
	 * Parse our arguments.
	 */
	username=NULL;
	opterr = 0;
	while ((ch = getopt (argc, argv, "kldVu:H:I:U:p:")) != -1) {
		switch (ch) {
			case 'H':
				strncpy(srv_addr,optarg,512);
				srv_addr[511]=0;
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
				sscanf(optarg,"%u",&userid);
				username=strdup(optarg);
				break;
			case 'k':
				exit_nutcpc();
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
				printf("lock file found, not starting, please check %s\n",runpid);
				free(runpid);
				exit(EXIT_FAILURE);
			}
		}
	}


	/* signal management */
	action.sa_handler = exit_clean;
	sigemptyset( & (action.sa_mask));
	action.sa_flags = 0;
	if ( sigaction( SIGINT, & action , NULL ) != 0) {
		printf("Error\n");
		exit(1);
	}
	if ( sigaction( SIGTERM, & action , NULL ) != 0) {
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
        
	password=NULL;
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
		int nerror=errno;
		printf("\nCan not initiate connection to NuFW gateway\n");
		/*printf("Problem: %s\n",strerror(nerror));*/
                printf("Problem: %s\n",nuclient_strerror(err));
		exit(EXIT_FAILURE);
	} else {
		/* store username and password */
		if (session->username){
			username=strdup(session->username);
		} else 
			username=NULL;
		if (session->password){
			password=strdup(session->password);
		} else 
			password=NULL;
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
		ioctl (STDIN_FILENO, TIOCNOTTY, NULL);
		close (STDIN_FILENO); 
		close (STDOUT_FILENO); 
		close (STDERR_FILENO); 
		setpgid (0, 0);
		chdir ("/");
	} else {
		fprintf (stderr, "nutcpc " NUTCPC_VERSION " started (debug)\n");
	}


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

	if (session){
		nu_client_free(session,err);
	}
        nu_client_global_deinit(err);
        nuclient_error_destroy(err);

	return EXIT_SUCCESS;
}
