/* pam_nufw module */

/*
 * pam_nufw.c PAM module auth client
 * 
 * Written by Jean Gillaux <jean@inl.fr>
 * Based on pam_permit by Andrew Morgan <morgan@parc.power.net> 1996/3/11
 *
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


/*#define _GNU_SOURCE*/
#include "../lib/nuclient.h"
#include <sys/resource.h>   /* setrlimit() */
#include <stdio.h>
#include <locale.h>
#include <langinfo.h>
#include <syslog.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include "security.h"

/*
 * here, we make definitions for the externally accessible functions
 * in this file (these definitions are required for static modules
 * but strongly encouraged generally) they are used to instruct the
 * modules include file to define their prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/_pam_macros.h>


#define NUAUTH_SRV "192.168.12.1"
#define NUAUTH_PORT "4130"
#define FILE_LOCK ".pam_nufw"

#define MAX_RETRY_TIME 30

#define MAX_NOAUTH_USERS 10

const char *DEFAULT_USER = "nobody";

/*int noauth_cpt = 0;*/
char ** no_auth_users = NULL;
struct pam_nufw_s pn_s;
NuAuth* session = NULL;
char* locale_charset = NULL;

/* internal data */
struct pam_nufw_s {
    char nuauth_srv[BUFSIZ]; /* auth server to connect to */
    char nuauth_port[20];  /* port to use on auth server */
    char file_lock[BUFSIZ]; /* file lock used to store pid */
    char** no_auth_users;
    int no_auth_cpt;
    nuclient_error* err;
};

/* init pam_nufw info struct. returns error message, or NULL if no error occurs */
static char* _init_pam_nufw_s(struct pam_nufw_s *pn_s){
    struct rlimit core_limit;
    
    /* Avoid creation of core file which may contains username and password */
    if (getrlimit(RLIMIT_CORE, &core_limit) == 0)
    {
        core_limit.rlim_cur = 0;
        setrlimit(RLIMIT_CORE, &core_limit);
    }
    
    /* Setup locale */
    setlocale (LC_ALL, "");

    /* get local charset */
    locale_charset = nl_langinfo(CODESET);
    if (locale_charset == NULL) {
        return "Can't get locale charset!";
    }

    /* Move to root directory to not block current working directory */
    (void)chdir("/");

    memset(pn_s, 0, sizeof(pn_s));
    SECURE_STRNCPY(pn_s->nuauth_srv,NUAUTH_SRV, sizeof(pn_s->nuauth_srv));
    SECURE_STRNCPY(pn_s->nuauth_port, NUAUTH_PORT, sizeof(pn_s->nuauth_port));
    SECURE_STRNCPY(pn_s->file_lock,FILE_LOCK, sizeof(pn_s->file_lock));
    pn_s->no_auth_users = NULL;
    pn_s->no_auth_cpt = 0;
    return NULL;
}

/*  function to parse arguments */
static int _pam_parse(int argc, const char** argv, struct pam_nufw_s *pn){
    int ctrl = 0;
    char *noauth;
    char *user;
    char *search = ",";
    int noauth_cpt = 0;
    char ** no_auth_users = malloc(sizeof(char *) * MAX_NOAUTH_USERS);
    for(ctrl=0; argc-- > 0; ++argv){
        if(!strncmp(*argv,"server=",7)) {
            SECURE_STRNCPY(pn->nuauth_srv,*argv + 7, sizeof(pn->nuauth_srv));
        }else if(!strncmp(*argv, "port=",5)){
            SECURE_STRNCPY(pn->nuauth_port, *argv + 5, sizeof(pn->nuauth_port));
        }else if(!strncmp(*argv, "lock=", 5)){
            SECURE_STRNCPY(pn->file_lock,*argv + 5, sizeof(pn->file_lock));
        }else if(!strncmp(*argv, "noauth=",7)){
            noauth = strdup(*argv + 7);
            user = strtok(noauth, search);
            if (user){
                no_auth_users[noauth_cpt] = x_strdup(user);
                noauth_cpt ++; 
            }
            while ( (user=strtok(NULL, search)) != NULL){
                no_auth_users[noauth_cpt] = x_strdup(user);
                noauth_cpt ++; 
            }
        }
    }
    pn->no_auth_cpt = noauth_cpt;
    pn->no_auth_users = no_auth_users;
    return ctrl;
}

char * _get_runpid(struct pam_nufw_s *pn_s, char *home){
    char path_dir[1024];
    if (home == NULL) {
        home = getenv("HOME");
    }
    if (home == NULL) {
        return NULL;  
    }

    /* create directory path */
    snprintf(path_dir,sizeof(path_dir),"%s/.nufw", home);
    path_dir[sizeof(path_dir)-1] = 0;

    /* if the directory doesn't exist, create it */
    if (access(path_dir,R_OK)){
        mkdir(path_dir,S_IRWXU);
    }

    /* create pid file full path */
    snprintf(path_dir, sizeof(path_dir), "%s/.nufw/%s", home, pn_s->file_lock);
    path_dir[sizeof(path_dir)-1] = 0;
    return (char*)strdup(path_dir);
}

static int _kill_nuclient(char *runpid){
    pid_t pid;
    FILE* FD;
    int ok, ret;

    if (runpid){
        FD = fopen(runpid,"r");
        if (FD){
            fscanf(FD,"%d",&pid);
            fclose(FD);
            ret = kill(pid,SIGTERM);
            ok = (ret == 0);
            if (ok) {
                syslog(LOG_INFO,"(pam_nufw) process killed (pid %lu)\n", (unsigned long)pid);
                return 0;
            } else {
                syslog(LOG_ERR,"(pam_nufw) fail to kill process: remove pid file\n");
                unlink(runpid);
                return 1;
            }
        }
        free(runpid);
    }
    return 0;
}

/* function used to 
 * kill client 
 * free nuauth session and nuerror
 */
void exit_client(){
    char* runpid;
    if(session){
        nu_client_delete(session);
    }
    runpid = _get_runpid(&pn_s, NULL);
    if(runpid != NULL){
        unlink(runpid);
        free(runpid);
    }
    nu_client_global_deinit();
    nu_client_error_destroy(pn_s.err);
    exit(EXIT_SUCCESS);
}

/* test if username is on the list of users that  don't have to be authenticated */
int do_auth_on_user(const char *username){
    int i;
    for (i=0; i< pn_s.no_auth_cpt; i++){
        if (strcmp(pn_s.no_auth_users[i], username) == 0){
            return 1;
        }   
    }
    return 0;
}


/* --- authentication management functions --- */

/**
 * Try to connect to nuauth.
 *
 * \return The client session, or NULL on error (get description from ::err)
 */
NuAuth* do_connect(char *username, char *password, nuclient_error *err)
{
    NuAuth* session = nu_client_new(username, password,  err);
    if (session == NULL) {
        return NULL;
    }

#if 0        
    nu_client_set_debug(session, context->debug_mode);

    if (!nu_client_setup_tls(session, NULL, NULL, NULL, NULL, err)) 
    { 
        nu_client_delete(session);
        return NULL;
    } 
#endif        

    if (!nu_client_connect(session, pn_s.nuauth_srv, pn_s.nuauth_port, err))
    {
        nu_client_delete(session);
        return NULL;
    }
    return session;
}

static void main_loop(struct pam_nufw_s *pn_s)
{
  int connected = 1;
  int tempo = 1;
  unsigned long interval = 100;

  for (;;) {
      usleep (interval * 1000);
      if (!connected){
          sleep(tempo);
          if (tempo< MAX_RETRY_TIME) {
              tempo=tempo*2;
          }

          if (nu_client_connect(session, pn_s->nuauth_srv, pn_s->nuauth_port, pn_s->err) != 0) {
              tempo = 1;
              connected = 1;
          } else {
              nu_client_reset(session);
              /* quit if password is wrong. to not lock user account */
              syslog(LOG_ERR,"(pam_nufw) unable to reconnect to server: %s",
                      nu_client_strerror(pn_s->err));
              if (pn_s->err->error == BAD_CREDENTIALS_ERR){
                  syslog(LOG_ERR,"(pam_nufw) bad credentials: leaving");
                  exit_client();
              }
          }
      } else {
          if (nu_client_check(session,pn_s->err)<0){
              nu_client_reset(session);
              connected = 0;
              syslog(LOG_ERR,"(pam_nufw) libnuclient error: %s",nu_client_strerror(pn_s->err));
          }
      }
  }
}

struct user_info_s
{
  const char *username;
  const char *password;
  uid_t uid;
  gid_t gid;
  char *home_dir;
};

static void clear_user_info(struct user_info_s *user_info)
{
    memset(user_info, 0, sizeof(*user_info));
}

static int nufw_client_func(struct pam_nufw_s *pn_s, struct user_info_s *user_info)
{
  int mypid;
  FILE* RunD;
  struct sigaction no_action;
  int res_err;

  /* set user and group identifier, and home directory */
  if (setuid(user_info->uid) != 0) {
      syslog(LOG_ERR, "(pam_nufw) Fail to set sigaction");
      return PAM_AUTH_ERR;
  }
  setgid(user_info->gid);
  setenv("HOME", user_info->home_dir, 1);

  /* catch SIGINT and SIGTERM signals, install handler: exit_client() */
  no_action.sa_handler = exit_client;
  sigemptyset( & (no_action.sa_mask));
  no_action.sa_flags = 0;
  if ( sigaction( SIGINT, & no_action , NULL ) != 0
    || sigaction( SIGTERM, & no_action , NULL ) != 0) 
  {
      syslog(LOG_ERR, "(pam_nufw) Fail to set sigaction");
      return PAM_AUTH_ERR;
  }

  /* init nuclient_error */
  res_err = nu_client_error_init(&pn_s->err);
  if (res_err != 0 ){
      syslog(LOG_ERR,"(pam_nufw) Cannot init error structure! %i",res_err);
      return PAM_AUTH_ERR;
  }

  /* libnuclient init function */
  nu_client_global_init(pn_s->err);

  /* create libnuclient session (connection to nuauth) */
  session = do_connect(
          nu_client_to_utf8(user_info->username, locale_charset), 
          nu_client_to_utf8(user_info->password, locale_charset), 
          pn_s->err);
  clear_user_info(user_info);

  /* fails to connect to nuauth? */
  if(session == NULL){
      int errno_copy = errno;
      syslog(LOG_ERR,"(pam_nufw) Cannot connect to NuAuth Server");
      syslog(LOG_ERR,"(pam_nufw) Problem: %s\n", strerror(errno_copy));
      return PAM_SUCCESS; /* PAM_AUTH_ERR */
  }

  /* session opened to nuauth: write pid in lockfile */
  mypid = getpid();
  RunD = fopen(_get_runpid(pn_s, user_info->home_dir), "w");
  if (RunD != NULL) {
      fprintf(RunD,"%d",mypid);
      fclose(RunD);
      syslog(LOG_INFO,"(pam_nufw) session to NuAuth server opened, username=%s, server=%s (pid=%lu)",
              session->username, pn_s->nuauth_srv, (unsigned long)mypid);
  }

  /* and then stay in main loop ... */
  main_loop(pn_s);
  return PAM_SUCCESS;
}

static int read_user_info(struct user_info_s *user_info, 
        pam_handle_t *pamh,
        int argc, const char **argv, 
        int *pam_result)
{
  struct passwd *pw;
  int ctrl;

  /* init. pam with pam arguments */
  ctrl = _pam_parse(argc, argv, &pn_s);

  /* read user name */
  *pam_result = pam_get_user(pamh, &user_info->username, NULL);
  if (*pam_result != PAM_SUCCESS) {
      syslog(LOG_ERR,"get user returned error: %s", pam_strerror(pamh, *pam_result));
      *pam_result = PAM_AUTH_ERR;
      return 0;
  }

  /* if not username is specified, use default username */
  if (user_info->username == NULL || user_info->username[0] == '\0') {
      user_info->username = DEFAULT_USER;
      pam_set_item(pamh, PAM_USER, DEFAULT_USER);
  }

  /* Test if we have to make a connection on nuauth for this user */
  if(do_auth_on_user(user_info->username) !=0){
      syslog(LOG_INFO, "(pam_nufw) no auth for user %s", user_info->username);
      *pam_result = PAM_SUCCESS;
      return 0;
  }

  /* read user password */
  if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&user_info->password) == PAM_SUCCESS) {
      if (user_info->password == NULL)
          syslog(LOG_ERR, "(pam_nufw) password is NULL!");
  }else{
      syslog(LOG_ERR, "pam_nufw failed to get password");
      *pam_result = PAM_AUTH_ERR;
      return 0;
  }
  
  /* read password, user and group identifier */
  pw = (struct passwd *)getpwnam(user_info->username);
  user_info->uid = pw->pw_uid;
  user_info->gid = pw->pw_gid;
  user_info->home_dir = pw->pw_dir;
  *pam_result = PAM_SUCCESS;
  return 1;
}

/*
 * used to open the connection to the nuauth server
 */
PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
        int argc, const char **argv)
{
  int retval;
  struct user_info_s user_info;
  char *errmsg;
  pid_t child_pid;

  syslog(LOG_ERR,"(pam_nufw) do authenticate");

  /* init. our structure */
  errmsg = _init_pam_nufw_s(&pn_s);
  if (errmsg != NULL) {
      syslog(LOG_ERR, "(pam nufw) init failure: %s", errmsg);
      clear_user_info(&user_info);
      return PAM_AUTH_ERR;
  }

  /* read user informations */
  if (!read_user_info(&user_info, pamh, argc, argv, &retval)) {
      clear_user_info(&user_info);
      return retval;
  }

  /* do fork */
  child_pid = fork();
  if (child_pid < 0){
      syslog(LOG_ERR, "(pam_nufw) fork failed");
      clear_user_info(&user_info);
      return PAM_AUTH_ERR;
  }

  if (child_pid != 0){
      /* in fork parent */
      retval = PAM_SUCCESS;
  } else {
      /* in fork child */
      retval = nufw_client_func(&pn_s, &user_info);
  }
  clear_user_info(&user_info);
  return retval;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  /*D(("pam_nufw sm_setcred"));*/
  return PAM_SUCCESS;
}

/* --- account management functions --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  D(("pam_nufw sm_acct_mgmt"));
  return PAM_SUCCESS;
}

/* --- password management --- */

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  D(("pam_nufw sm_chauthok"));
  return PAM_SUCCESS;
}

/* --- session management --- */

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  /*const char *password = NULL; */
  /*D(("pam_nufw sm_open_session"));*/
  /*pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    syslog(LOG_INFO, "(pam_nufw) passwd: %s",password);*/
  syslog(LOG_INFO,"(pam_nufw) session opened");
  return PAM_SUCCESS;
}

/* 
 * On session closing, we want to close the connection
 * -> get pid file, and kill process
 */
PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  /*D(("pam_nufw sm_close_session"));*/
  int ctrl;
  struct passwd *pw;
  const char* user = NULL;
  char *errmsg;
  int retval;

  /* get parameters */
  errmsg = _init_pam_nufw_s(&pn_s);
  if (errmsg != NULL) {
      syslog(LOG_ERR, "(pam nufw) init failure: %s", errmsg);
      return PAM_AUTH_ERR;
  }

  /*syslog(LOG_INFO, "(pam_nufw) file_lock: %s",pn_s.file_lock);*/
  ctrl = _pam_parse(argc, argv, &pn_s);

  /* get username */
  retval = pam_get_user(pamh, &user, NULL);
  if(do_auth_on_user(user) !=0){
      return PAM_SUCCESS;
  }
  pw = (struct passwd *)getpwnam(user);
  setenv("HOME",pw->pw_dir,1);
  /*syslog(LOG_INFO, "(pam_nufw) file_lock: %s",_get_runpid(&pn_s));*/

  /* kill client */
  _kill_nuclient(_get_runpid(&pn_s, pw->pw_dir));

  syslog(LOG_INFO, "(pam_nufw) session closed");
  return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_permit_modstruct = {
    "pam_nufw",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif

