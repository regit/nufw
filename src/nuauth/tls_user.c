/*
 ** Copyright(C) 2004,2005,2006 INL
 ** written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <gryzor@inl.fr>
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
 **
 */

#include "auth_srv.h"

/**
 * \ingroup TLS
 * \defgroup TLSUser TLS User server
 * @{
 */

/** \file tls_user.c
 *  \brief Manage clients connections and messages.
 *   
 * The thread tls_user_authsrv() wait for clients in tls_user_main_loop().
 */

extern int nuauth_tls_auth_by_cert;

/**
 * List of new clients which are in authentification state. This list is
 * feeded by tls_user_accept(), and read by pre_client_check() and
 * remove_socket_from_pre_client_list().
 *
 * Lock ::pre_client_list_mutex when you access to this list.
 */
GSList* pre_client_list;

/**
 * Mutex used to access ::pre_client_list.
 */
GStaticMutex pre_client_list_mutex;

struct tls_user_context_t {
    int mx;
    int sck_inet;
    fd_set tls_rx_set; /* read set */
    unsigned int nuauth_tls_max_clients;
    int nuauth_number_authcheckers;
    int nuauth_auth_nego_timeout;
};

struct pre_client_elt {
    int socket;
    time_t validity;
};

/**
 * Drop a client from the ::pre_client_list.
 */
gboolean remove_socket_from_pre_client_list(int socket) 
{
    GSList * client_runner=NULL;
    g_static_mutex_lock (&pre_client_list_mutex);
    for(client_runner=pre_client_list;client_runner;client_runner=client_runner->next){
        /* if entry older than delay then close socket */
        if (client_runner->data){
            if ( ((struct pre_client_elt*)(client_runner->data))->socket == socket){
                g_free(client_runner->data);
                client_runner->data=NULL;
                pre_client_list=g_slist_remove_all(pre_client_list,NULL);
                g_static_mutex_unlock (&pre_client_list_mutex);
                return TRUE;
            } 
        }
    }
    g_static_mutex_unlock (&pre_client_list_mutex);
    return FALSE;
}

/**
 * Check pre client list to disconnect connection
 * that are open since too long
 */
void pre_client_check()
{
    GSList * client_runner=NULL;
    time_t current_timestamp;
    for(;;){
        current_timestamp=time(NULL);

        /* lock client list */
        g_static_mutex_lock (&pre_client_list_mutex);
        /* iter on pre_client_list */
        for(client_runner=pre_client_list;client_runner;client_runner=client_runner->next){
            /* if entry older than delay then close socket */
            if (client_runner->data){
                if ( ((struct pre_client_elt*)(client_runner->data))->validity < current_timestamp){

#ifdef DEBUG_ENABLE
                    log_message(VERBOSE_DEBUG, AREA_USER, "closing socket %d due to timeout",((struct pre_client_elt*)(client_runner->data))->socket);
#endif
                    shutdown(((struct pre_client_elt*)(client_runner->data))->socket,SHUT_RDWR);
                    close(((struct pre_client_elt*)(client_runner->data))->socket);
                    g_free(client_runner->data);
                    client_runner->data=NULL;
                } 
            }
        }
        pre_client_list=g_slist_remove_all(pre_client_list,NULL);
        /* unlock client list */
        g_static_mutex_unlock (&pre_client_list_mutex);
        /* sleep */
        sleep(1);
    }
}

/**
 * get RX paquet from a TLS client connection and send it to user 
 * authentication threads.
 *
 * \param c_session SSL RX packet
 * \return 1 if read done, EOF if read complete, -1 on error
 */
static int treat_user_request (user_session_t * c_session)
{
    struct tls_buffer_read *datas;
    int header_length;
    struct nuv2_header* header;

    if (c_session == NULL) return 1;

    datas=g_new0(struct tls_buffer_read, 1);
    if (datas==NULL)
        return -1;
    datas->socket=0;
    datas->tls=c_session->tls;
    datas->ip_addr=c_session->addr;
#ifdef DEBUG_ENABLE
    if (!c_session->multiusers) {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
            g_message("(*) New packet from user %s",
                    c_session->user_name);
    }
#endif
    
    /* copy packet datas */
    datas->buffer = g_new0(char, CLASSIC_NUFW_PACKET_SIZE);
    if (datas->buffer == NULL){
        g_free(datas);
        return -1;
    }
    g_mutex_lock(c_session->tls_lock);
    datas->buffer_len = gnutls_record_recv(*(c_session->tls), datas->buffer, CLASSIC_NUFW_PACKET_SIZE);
    g_mutex_unlock(c_session->tls_lock);
    if ( datas->buffer_len < (int)sizeof(struct nuv2_header)) {
#ifdef DEBUG_ENABLE
        if (datas->buffer_len <0) 
            log_message(DEBUG, AREA_USER, "Received error from user %s", c_session->user_name);
#endif
        free_buffer_read(datas);
        return EOF;
    }

    /* get header to check if we need to get more datas */
    header = (struct nuv2_header* )datas->buffer;
    header_length=ntohs(header->length);

    /* is it an "USER HELLO" message ? */
    if (header->proto==PROTO_VERSION && header->msg_type == USER_HELLO){
        debug_log_message (VERBOSE_DEBUG, AREA_USER,
            "tls user: HELLO from %s", c_session->user_name);
        free_buffer_read(datas);
        return 1;
    }

    /* if message content is bigger than CLASSIC_NUFW_PACKET_SIZE, */
    /* continue to read the content */
    if (header->proto==PROTO_VERSION && header_length> datas->buffer_len && header_length<MAX_NUFW_PACKET_SIZE  ){
        int tmp_len;
        
        /* we realloc and get what we miss */
        datas->buffer=g_realloc(datas->buffer, header_length);
        header = (struct nuv2_header* )datas->buffer;
        
        g_mutex_lock(c_session->tls_lock);
        tmp_len = gnutls_record_recv( *(c_session->tls), datas->buffer+CLASSIC_NUFW_PACKET_SIZE,
                header_length - datas->buffer_len);
        g_mutex_unlock(c_session->tls_lock);
        if (tmp_len<0){
            free_buffer_read(datas);
            return -1;
        }
        datas->buffer_len += tmp_len;
    }
    
    /* check message type because USER_HELLO has to be ignored */
    if ( header->msg_type == USER_HELLO){
        return 1;
    }

    /* check authorization if we're facing a multi user packet */ 
    if ( (header->option == 0x0) || ((header->option == 0x1) && c_session->multiusers)) {
        /* this is an authorized packet we fill the buffer_read structure */
        if (c_session->multiusers) {
            datas->user_name=NULL;
            datas->user_id=0;
            datas->groups=NULL;
        } else {
            datas->user_name = g_strdup(c_session->user_name);
            datas->user_id = c_session->user_id;
            datas->groups = g_slist_copy(c_session->groups);
        }
        if (c_session->sysname){
            datas->os_sysname=g_strdup(c_session->sysname);
            if (datas->os_sysname == NULL){
                free_buffer_read(datas);
                return -1;
            }
        }
        if (c_session->release){
            datas->os_release=g_strdup(c_session->release);
            if (datas->os_release == NULL){
                free_buffer_read(datas);
                return -1;
            }
        }
        if (c_session->version){
            datas->os_version=g_strdup(c_session->version);
            if (datas->os_version == NULL){
                free_buffer_read(datas);
                return -1;
            }
        }

        debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "Pushing packet to user_checker");
        g_thread_pool_push (nuauthdatas->user_checkers,
                datas,	
                NULL
                );
    } else {
        log_message(INFO, AREA_USER, "Bad packet, option of header is not set or unauthorized option from user %s.", c_session->user_name);
        free_buffer_read(datas);
        return EOF;
    }
    return 1;
}

/**
 * Function called on new client connection:
 *    - Call accept()
 *    - Drop client if there are to much clients or if NuAuth is in reload
 *    - Create a client_connection structure
 *    - Add client to ::pre_client_list
 *    - Add client to ::tls_sasl_worker queue (see sasl_worker())
 * 
 * \return If an error occurs returns 1, else returns 0.
 */
int tls_user_accept(struct tls_user_context_t *context) 
{
    struct sockaddr_storage sockaddr;
    struct sockaddr_in *sockaddr4 = (struct sockaddr_in *)&sockaddr;
    struct sockaddr_in6 *sockaddr6 = (struct sockaddr_in6 *)&sockaddr;
    struct in6_addr addr;
    unsigned int len_inet = sizeof sockaddr;
    struct client_connection* current_client_conn;
    struct pre_client_elt* new_pre_client;
    int socket;
    gint option_value;

    /* Wait for a connect */
    socket = accept (context->sck_inet,
            (struct sockaddr *)&sockaddr,
            &len_inet);
    if (socket == -1){
        log_message(WARNING, AREA_MAIN, "accept");
    }

    if ( get_number_of_clients() >= context->nuauth_tls_max_clients ) {
        log_message(WARNING, AREA_MAIN, "too many clients (%d configured)\n",context->nuauth_tls_max_clients);
        shutdown(socket, SHUT_RDWR); 
        close(socket);
        return 1;
    }

    /* if system is in reload: drop new client */
    if (nuauthdatas->need_reload)
    {
        shutdown(socket,SHUT_RDWR);
        close(socket);
        return 0;
    }
   
    /* Extract client address (convert it to IPv6 if it's IPv4) */
    if (sockaddr6->sin6_family == AF_INET) {
        addr.s6_addr32[0] = 0;
        addr.s6_addr32[1] = 0;
        addr.s6_addr32[2] = 0xffff0000;
        addr.s6_addr32[3] = ntohl(sockaddr4->sin_addr.s_addr);
    } else {
        addr = sockaddr6->sin6_addr;
    }

    current_client_conn=g_new0(struct client_connection,1);
    current_client_conn->socket=socket;
    current_client_conn->addr = addr;

    /* Update mx number if needed */
    if ( socket+1 > context->mx )
        context->mx = socket + 1;
    
    /* Set KEEP ALIVE on connection */
    option_value=1;
    setsockopt (socket,
            SOL_SOCKET, SO_KEEPALIVE,
            &option_value,  sizeof(option_value));
    
    /* give the connection to a separate thread */
    /*  add element to pre_client 
        create pre_client_elt */
    new_pre_client = g_new0(struct pre_client_elt,1);
    new_pre_client->socket = socket;
    new_pre_client->validity = time(NULL) + context->nuauth_auth_nego_timeout;

    g_static_mutex_lock (&pre_client_list_mutex);
    pre_client_list=g_slist_prepend(pre_client_list,new_pre_client);
    g_static_mutex_unlock (&pre_client_list_mutex);

    g_thread_pool_push (nuauthdatas->tls_sasl_worker,
            current_client_conn, NULL);
    return 0;
}    

/**
 * Process client events:
 *    - Delete client if its session expired: delete_client_by_socket()
 *    - Call treat_user_request(). If it gets EOF, delete the client:
 *      send #FREE_MESSAGE to tls_push_queue (see push_worker()) if using
 *      PUSH mode (::nuauthconf->push), or call delete_client_by_socket().
 */
void tls_user_check_activity(struct tls_user_context_t *context, int socket)
{
    user_session_t * c_session;
    int u_request;
    debug_log_message(VERBOSE_DEBUG, AREA_USER, "user activity on socket %d",socket);

    /* we lock here but can do other thing on hash as it is not destructive 
     * in push mode modification of hash are done in push_worker */
    c_session = get_client_datas_by_socket(socket);

    if (nuauthconf->session_duration && c_session->expire < time(NULL)){
        FD_CLR(socket,&context->tls_rx_set);
        delete_client_by_socket(socket);
        return;
    }

    u_request = treat_user_request( c_session );
    if (u_request == EOF) {
        log_user_session(c_session,SESSION_CLOSE);
        debug_log_message(VERBOSE_DEBUG, AREA_USER, "client disconnect on socket %d",socket);
        FD_CLR(socket,&context->tls_rx_set);
        /* clean client structure */
        if (nuauthconf->push){
            struct internal_message* message=g_new0(struct internal_message,1);
            message->type = FREE_MESSAGE;
            message->datas = GINT_TO_POINTER(socket);
            g_async_queue_push(nuauthdatas->tls_push_queue,message);
        } else {
            delete_client_by_socket(socket);
        }
    }else if (u_request < 0) {
#ifdef DEBUG_ENABLE
        log_message(VERBOSE_DEBUG, AREA_USER, "treat_user_request() failure");
#endif
    }
}

/**
 * Wait for new client connection or client event using ::mx_queue
 * and select().
 *
 * It calls tls_user_accept() on new client connection, and 
 * tls_user_check_activity() on user event.
 */
void tls_user_main_loop(struct tls_user_context_t *context, GMutex *mutex)
{    
    gpointer c_pop;
    int i, nb_active_clients;
    fd_set wk_set; /* working set */
    struct timeval tv;

    log_message(INFO, AREA_MAIN, "[+] NuAuth is waiting for client connections.");
    while (g_mutex_trylock(mutex)) 
    {
        g_mutex_unlock(mutex);

        /* 
         * Try to get new file descriptor to update set. Messages come from 
         * tls_sasl_connect_ok() and are send when a new user is connected.
         */
        c_pop = g_async_queue_try_pop (mx_queue);
        while (c_pop != NULL)
        {
            int socket = GPOINTER_TO_INT(c_pop);

            debug_log_message(VERBOSE_DEBUG, AREA_USER, "checking mx against %d",socket);
            if ( socket+1 > context->mx )
                context->mx = socket + 1;
            /*
             * change FD_SET
             */
            FD_SET(socket,&context->tls_rx_set);
            c_pop=g_async_queue_try_pop (mx_queue);
        }


        /* wait new events during 1 second */
        FD_ZERO(&wk_set);
        for (i=0;i<context->mx;++i){
            if (FD_ISSET(i,&context->tls_rx_set))
                FD_SET(i,&wk_set);
        }
        tv.tv_sec=1;
        tv.tv_usec=0;
        nb_active_clients = select(context->mx,&wk_set,NULL,NULL,&tv);

        /* catch select() error */
        if (nb_active_clients == -1) {
            /* Signal was catched: just ignore it */
            if (errno == EINTR)
            {
                log_message(CRITICAL, AREA_MAIN,
                        "Warning: tls user select() failed: signal was catched.");
                continue;
            }

            switch(errno){
                case EBADF:
                    g_message("Bad file descriptor");
                    break;
                case EINVAL:
                    g_message("Negative value for socket");
                    break;
                case ENOMEM:
                    g_message("Not enough memory");
                    break;
            }
            log_message(FATAL, AREA_MAIN, 
                    "select() failed, exiting at %s:%d in %s (errno %i)",
                    __FILE__,__LINE__,__func__, errno);
            nuauth_ask_exit();
            break;
        }
        if (nb_active_clients == 0) {
            /* timeout, just continue */
            continue;
        }

        /*
         * Check if a connect has occured
         */
        if (FD_ISSET(context->sck_inet,&wk_set) ){
            if (tls_user_accept(context) != 0)
                continue;
        }

        /*
         * check for client activity
         */
        for ( i=0; i<context->mx; ++i) {
            if ( i == context->sck_inet )
                continue;
            if ( FD_ISSET(i, &wk_set) )
                tls_user_check_activity(context, i);
        }

        for ( i = context->mx - 1;
                i >= 0 && !FD_ISSET(i,&context->tls_rx_set);
                i = context->mx -1 ){
            debug_log_message(VERBOSE_DEBUG, AREA_USER, "setting mx to %d",i);
            context->mx = i;
        }
    }

    close(context->sck_inet);
}

int tls_user_bind(char **errmsg)
{
    struct addrinfo *res;
    struct addrinfo hints;
    int ecode;
    int sck_inet;
    gint option_value;
    int result;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = PF_UNSPEC;
    ecode = getaddrinfo(NULL, nuauthconf->userpckt_port, &hints, &res);
    if (ecode != 0)
    {
        *errmsg = g_strdup_printf("Fail to init. user server address: %s", 
                gai_strerror(ecode));
        return -1;
    }

    /* open the socket */
    if (res->ai_family == PF_INET)
        log_message(DEBUG,AREA_MAIN,"Create user server IPv4 socket\n");
    else if (res->ai_family == PF_INET6)
        log_message(DEBUG,AREA_MAIN,"Create user server IPv6 socket\n");
    else
        log_message(DEBUG,AREA_MAIN,"Create user server (any) socket\n");
    sck_inet = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sck_inet == -1)
    {
        *errmsg = g_strdup("Socket creation failed.");
        return -1;
    }

    /* set socket reuse and keep alive option */
    option_value=1;
    setsockopt (
            sck_inet,
            SOL_SOCKET,
            SO_REUSEADDR,
            &option_value,
            sizeof(option_value));
    setsockopt (
            sck_inet,
            SOL_SOCKET,
            SO_KEEPALIVE,
            &option_value,
            sizeof(option_value));

    /* bind */
    result = bind (sck_inet, res->ai_addr, res->ai_addrlen);
    if (result < 0)
    {
        *errmsg = g_strdup_printf("Unable to bind port %s.",
                nuauthconf->userpckt_port);
        close(sck_inet); 
        return -1;
    }
    freeaddrinfo(res);
    return sck_inet;
}

int tls_user_init(struct tls_user_context_t *context)
{
    confparams nuauth_tls_vars[] = {
        { "nuauth_tls_max_clients" , G_TOKEN_INT ,NUAUTH_TLS_MAX_CLIENTS, NULL },
        { "nuauth_number_authcheckers" , G_TOKEN_INT ,NB_AUTHCHECK, NULL },
        { "nuauth_auth_nego_timeout" , G_TOKEN_INT ,AUTH_NEGO_TIMEOUT, NULL }
    };
    GThread *pre_client_thread;
    char *errmsg;
    int result;

    context->sck_inet = tls_user_bind(&errmsg);
    if (context->sck_inet < 0)
    {
        log_message(FATAL, AREA_MAIN, 
            "FATAL ERROR: User bind error: %s",
            errmsg);
        log_message(FATAL, AREA_MAIN, 
            "Check that nuauth is not running twice. Exit nuauth!");
        return 0;
    }
    
    /* get config file setup */
    /* parse conf file */
    parse_conffile(DEFAULT_CONF_FILE, sizeof(nuauth_tls_vars)/sizeof(confparams),nuauth_tls_vars);
    
#define READ_CONF(KEY) \
	get_confvar_value(nuauth_tls_vars, sizeof(nuauth_tls_vars)/sizeof(confparams), KEY)

    context->nuauth_tls_max_clients = *(unsigned int*)READ_CONF("nuauth_tls_max_clients");
    context->nuauth_number_authcheckers = *(int*)READ_CONF("nuauth_number_authcheckers");
    context->nuauth_auth_nego_timeout = *(int*)READ_CONF("nuauth_auth_nego_timeout");
#undef READ_CONF    

    /* free config struct */
    free_confparams(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams));

    /* init sasl stuff */	
    my_sasl_init();

    init_client_struct();

#if 0
    /* intercept SIGTERM */
    action.sa_handler = tls_nuauth_cleanup;
    sigemptyset( & (action.sa_mask));
    action.sa_flags = 0;
    if ( sigaction( SIGTERM, & action , NULL ) != 0) {
        printf("Error\n");
        exit(EXIT_FAILURE);
    }
#endif

    /* pre client list */
    pre_client_list=NULL;
    pre_client_thread = g_thread_create ( (GThreadFunc) pre_client_check,
            NULL,
            FALSE,
            NULL);
    if (! pre_client_thread ) {
        return 0;
    }

    /* create tls sasl worker thread pool */
    nuauthdatas->tls_sasl_worker = g_thread_pool_new  ((GFunc) tls_sasl_connect,
            NULL,
            context->nuauth_number_authcheckers,
            TRUE,
            NULL);

    /* listen */
    result = listen(context->sck_inet,20);
    if (result == -1)
    {
        g_error("user listen() failed, exiting");
        return 0;
    }

    /* init fd_set */
    FD_ZERO(&context->tls_rx_set);
    FD_SET(context->sck_inet,&context->tls_rx_set);
    context->mx=context->sck_inet+1;
    mx_queue=g_async_queue_new ();
    return 1;
}

/**
 * TLS user packet server. 
 * Thread function serving user connection.
 * 
 * \return NULL
 */
void* tls_user_authsrv(GMutex *mutex)
{
    struct tls_user_context_t context;
    int ok = tls_user_init(&context);
    if (ok) {
        tls_user_main_loop(&context, mutex);
    } else {
        nuauth_ask_exit();
    }
    return NULL;
}

/**
 * @}
 */
