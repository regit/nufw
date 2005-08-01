/*
 * nutcpc.c - TCP/IP connection auth client.
 *
 * Copyright 2004,2005 - INL
 * 	written by Eric Leblond <eric.leblond@inl.fr>
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
#define NUTCPC_VERSION "0.6"

#define MAX_RETRY_TIME 30

struct termios orig;

void panic(const char *fmt, ...){
	printf("error\n");
	exit(-1);
}

char * computerunpid(){
	char path_dir[254];
	snprintf(path_dir,254,"%s/.nufw",getenv("HOME"));
	if (access(path_dir,R_OK)){
		mkdir(path_dir,S_IRWXU);
	}
	snprintf(path_dir,254,"%s/.nufw/.nutcpc",getenv("HOME"));
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

		/*
		 * */
	}	exit(0);
}

void exit_clean(){
	char* runpid=computerunpid();
	unlink(runpid);
	free(runpid);
	/* Restore terminal (can be superflu). */
	(void) tcsetattr (fileno (stdin), TCSAFLUSH, &orig);
	exit(0);
}

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
	nread = getline (lineptr, n, stdin);

	/* Restore terminal. */
	(void) tcsetattr (fileno (stdin), TCSAFLUSH, &orig);

	return nread;
}

char* password;

char* get_password()
{
	char* passwd;
	int password_size=32;
	if (password == NULL){
		passwd=(char *)calloc(32,sizeof( char));
		printf("Enter password : ");
		my_getpass(&passwd,&password_size);
		if (strlen(passwd)<password_size) {
			passwd[strlen(passwd)-1]=0;
		}
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
	int username_size=32;

	if (username == NULL){
		printf("Enter username : ");
		user=(char *)calloc(32,sizeof( char));
		nread = getline (&user, &username_size, stdin);
		user[32]=0;
	} else {
		user = strdup(username);
	}
	return user;
}

static void usage (void)
{
	fprintf (stderr, "usage: nutcpc [-kdV]  [-I interval] "
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

	/*
	 * Parse our arguments.
	 */
	username=NULL;
	opterr = 0;
	while ((ch = getopt (argc, argv, "kldVu:H:I:U:p:")) != -1) {
		switch (ch) {
			case 'H':
				strncpy(srv_addr,optarg,512);
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

	password=NULL;
	session = nu_client_init2(
			srv_addr,
			port,
			NULL,
			NULL,
			&get_username,
			&get_password,
			NULL
			);

	if (!session){
		int nerror=errno;
		printf("\nCan not initiate connection to NuFW gateway\n");
		printf("Problem : %s\n",strerror(nerror));
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
			FILE* RunD;
			fprintf (stderr, "nutcpc started (pid %d)\n", 
					(int) p);
			if (donotuselock==0){
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
	} else
		fprintf (stderr, "nutcpc " NUTCPC_VERSION " started (debug)\n");


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
					NULL
					);
			if (session!=NULL){
				tempo=1;
			}
		} else {
			if (nu_client_check(session)<0){
				session=NULL;
			}
		}
	}

	nu_client_free(session);

	return EXIT_SUCCESS;
}
