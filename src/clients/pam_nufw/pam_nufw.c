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

#define DEFAULT_USER "nobody"
#define MAX_RETRY_TIME 30

#define MAX_NOAUTH_USERS 10

char* glob_pass; 
char* glob_user;
/*int noauth_cpt = 0;*/
char ** no_auth_users = NULL;
struct pam_nufw_s pn_s;
NuAuth* session = NULL;
nuclient_error* nuerr = NULL;

/* internal data */
struct pam_nufw_s {
    char nuauth_srv[BUFSIZ]; /* auth server to connect to */
    char nuauth_port[20];  /* port to use on auth server */
    char file_lock[BUFSIZ]; /* file lock used to store pid */
    char** no_auth_users;
    int no_auth_cpt;
};

/* init pam_nufw info struct */
static void _init_pam_nufw_s(struct pam_nufw_s *pn_s){
    struct rlimit core_limit;
    
    /* Avoid creation of core file which may contains username and password */
    if (getrlimit(RLIMIT_CORE, &core_limit) == 0)
    {
        core_limit.rlim_cur = 0;
        setrlimit(RLIMIT_CORE, &core_limit);
    }
    
    /* Move to root directory to not block current working directory */
    (void)chdir("/");

    memset(pn_s, 0, sizeof(pn_s));
    SECURE_STRNCPY(pn_s->nuauth_srv,NUAUTH_SRV, sizeof(pn_s->nuauth_srv)-1);
    SECURE_STRNCPY(pn_s->nuauth_port, NUAUTH_PORT, sizeof(pn_s->nuauth_port));
    SECURE_STRNCPY(pn_s->file_lock,FILE_LOCK, sizeof(pn_s->file_lock)-1);
    pn_s->no_auth_users = NULL;
    pn_s->no_auth_cpt = 0;
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
            SECURE_STRNCPY(pn->nuauth_srv,*argv + 7, sizeof(pn->nuauth_srv)-1);
        }else if(!strncmp(*argv, "port=",5)){
            SECURE_STRNCPY(pn->nuauth_port, *argv + 5, sizeof(pn->nuauth_port));
        }else if(!strncmp(*argv, "lock=", 5)){
            SECURE_STRNCPY(pn->file_lock,*argv + 5, sizeof(pn->file_lock)-1);
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

char * _get_runpid(struct pam_nufw_s *pn_s){
    char path_dir[254];
    char *home = getenv("HOME");
    if (home == NULL)
        return NULL;            
    snprintf(path_dir,sizeof(path_dir),"%s/.nufw", home);
    if (access(path_dir,R_OK)){
        mkdir(path_dir,S_IRWXU);
    }
    snprintf(path_dir, sizeof(path_dir), "%s/.nufw/%s", home, pn_s->file_lock);
    return (char*) (strdup(path_dir));
    /*return strdup(path_dir);*/
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
                /*printf("nutcpc process killed (pid %lu)\n", (unsigned long)pid);*/
                return 0;
            } else {
                printf("Fail to kill process: remove pid file\n");
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
    runpid = _get_runpid(&pn_s);
    if(runpid != NULL){
        unlink(runpid);
        free(runpid);
    }
    nu_client_global_deinit(nuerr);
    nu_client_error_destroy(nuerr);
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
NuAuth* do_connect(nuclient_error *err)
{
    NuAuth* session = nu_client_new(glob_user, glob_pass,  err);
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

/*
 * used to open the connection to the nuauth server
 */
PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc
        ,const char **argv)
{
  int retval = PAM_AUTH_ERR;
  int p;
  struct sigaction no_action;
  const char *user = NULL;
  const char *password = NULL;
  const void *password2 = NULL;
  int uid,gid=0;
  struct passwd *pw;
  unsigned long interval = 100;
  int tempo = 1;
  int pdesc[2];
  int ctrl;
  nuclient_error* err=NULL;
  int res_err;

  _init_pam_nufw_s(&pn_s);

  /*D(("(pam_nufw) sm_authenticate"));*/
  syslog(LOG_ERR,"pam_nufw authenticate");
  ctrl = _pam_parse(argc, argv, &pn_s);
  /*
   * authentication requires we know who the user wants to be
   */
  retval = pam_get_user(pamh, &user, NULL);
  if (retval != PAM_SUCCESS) {
      syslog(LOG_ERR,"get user returned error: %s", pam_strerror(pamh,retval));
      return retval;
  }
  if (user == NULL || *user == '\0') {
      pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
  }

  /* Test if we have to make a connection on nuauth for this user */
  if(do_auth_on_user(user) !=0){
      syslog(LOG_INFO, "(pam_nufw) no auth for user %s",user);
      user = NULL;
      return PAM_SUCCESS;
  }

  if (pam_get_item(pamh, PAM_AUTHTOK, &password2) == PAM_SUCCESS){
#ifdef DEBUG
      /*syslog(LOG_INFO, "(pam_nufw) got password %s.",password);*/
#endif
      password = (char *) password2;
      if (password == NULL)
          syslog(LOG_ERR, "(pam_nufw) password is NULL!");
  }else{
      syslog(LOG_ERR, "pam_nufw failed to get password");
  }

  /*syslog(LOG_INFO,"(pam_nufw) connect nuauth: srv=%s, port=%i",srv_addr,port);*/
  pw = (struct passwd *)getpwnam(user);
  uid = (uid_t)(pw->pw_uid);
  gid = getgid();
  /*syslog(LOG_INFO,"(pam_nufw) uid=%i, gid=%i",uid,gid);*/
  setenv("HOME",pw->pw_dir,1);
  glob_pass = (char*)password;
  glob_user = (char*)user;

  if (pipe(pdesc) == -1){
      syslog(LOG_ERR,"pipe failed %s",strerror(errno));
  }
  p = fork();
  if (p < 0){
      syslog(LOG_ERR, "(pam_nufw) fork failed");
      return PAM_AUTH_ERR;
  }
  if (p == 0){/* in child */
      /*syslog(LOG_INFO,"(pam_nufw) in child");*/
      setuid(uid);
      /*syslog(LOG_INFO,"(pam_nufw) child uid %i",getuid());*/
      /* signal management */
      no_action.sa_handler = exit_client;
      sigemptyset( & (no_action.sa_mask));
      no_action.sa_flags = 0;
      if ( sigaction( SIGINT, & no_action , NULL ) != 0) {
          syslog(LOG_ERR, "Erro setting sigaction");
          return PAM_AUTH_ERR;
      }
      if ( sigaction( SIGTERM, & no_action , NULL ) != 0) {
          syslog(LOG_ERR, "Erro setting sigaction");
          return PAM_AUTH_ERR;
      }

      /* init nuclient_error */
      res_err = nu_client_error_init(&err);
      if (res_err != 0 ){
            syslog(LOG_ERR,"(pam_nufw) Cannot init error structure! %i",res_err);
            exit(-1);
      }
      /* libnuclient init function */
      nu_client_global_init(err);
      session = do_connect(err);

      /*syslog(LOG_INFO,"(pam_nufw) after nu_client_init2");*/
      if(session == NULL){
          syslog(LOG_ERR,"(pam_nufw) Cannot connect to NuAuth Server");
          int nerror = errno;
          syslog(LOG_ERR,"(pam_nufw) Problem : %s\n",strerror(nerror));
          /*return PAM_AUTH_ERR;*/
          return PAM_SUCCESS;
      }else{
          /* session opened to nuauth */
          syslog(LOG_INFO,"(pam_nufw) session to NuAuth server opened, username=%s, server=%s",session->username,pn_s.nuauth_srv);
          /* write pid in lockfile */
          int mypid;
          FILE* RunD;
          mypid = getpid();
          RunD=fopen(_get_runpid(&pn_s),"w");
          fprintf(RunD,"%d",mypid);
          fclose(RunD);
          for (;;) {
              usleep (interval * 1000);
              if (session == NULL){
                  sleep(tempo);
                  if (tempo< MAX_RETRY_TIME) {
                      tempo=tempo*2;
                  }
                  session = do_connect(err);
                  if (session==NULL){/* quit if password is wrong. to not lock user account */
                      syslog(LOG_ERR,"(pam_nufw) unable to reconnect to server: %s",nu_client_strerror(err));
                      if (err->error == BAD_CREDENTIALS_ERR){
                          syslog(LOG_ERR,"(pam_nufw) bad credentials: leaving");
                          exit_client();
                      }
                  }else{
                      tempo = 1;
                  }
              } else {
                  if (nu_client_check(session,err)<0){
                      session=NULL;
                      syslog(LOG_ERR,"(pam_nufw) libnuclient error: %s",nu_client_strerror(err));
                  }
              }
          }



      }
  }else{ /* in parent */
      /* nothing to do */
      /*syslog(LOG_INFO,"(pam_nufw) in parent");*/
  }
  user = NULL;                                            /* clean up */
  /*syslog(LOG_INFO,"(pam_nufw) exiting...");*/
  return PAM_SUCCESS;
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
  int retval;

  /* get parameters */
  _init_pam_nufw_s(&pn_s);
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
  _kill_nuclient(_get_runpid(&pn_s));

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
