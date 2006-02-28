/*
 ** Copyright(C) 2004,2005 INL
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

extern int nuauth_tls_auth_by_cert;

GSList* pre_client_list;
GStaticMutex pre_client_list_mutex;

struct tls_user_context_t {
    int mx;
    int sck_inet;
    fd_set tls_rx_set; /* read set */
    int nuauth_tls_max_clients;
    int nuauth_number_authcheckers;
    int nuauth_auth_nego_timeout;
    gint option_value;
    GThreadPool* tls_sasl_worker;
};

struct pre_client_elt {
    int socket;
    time_t validity;
};

gboolean remove_socket_from_pre_client_list(int c) {
    GSList * client_runner=NULL;
    g_static_mutex_lock (&pre_client_list_mutex);
    for(client_runner=pre_client_list;client_runner;client_runner=client_runner->next){
        /* if entry older than delay then close socket */
        if (client_runner->data){
            if ( ((struct pre_client_elt*)(client_runner->data))->socket == c){
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
void  pre_client_check() {
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
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
                        g_message("closing socket %d due to timeout\n",((struct pre_client_elt*)(client_runner->data))->socket);
                    }
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
 * get RX paquet from a TLS client connection and send it to user authentication threads.
 *
 * - Argument : SSL RX packet
 * - Return : 1 if read done, EOF if read complete, -1 on error
 */
static int treat_user_request (user_session * c_session)
{
    struct tls_buffer_read *datas;
    int read_size;
    int pbuf_length;

    if (c_session == NULL) return 1;

    datas=g_new0(struct tls_buffer_read, 1);
    if (datas==NULL)
        return -1;
    datas->socket=0;
    datas->buffer=NULL;
    datas->tls=c_session->tls;
    datas->ipv4_addr=c_session->addr;
#ifdef DEBUG_ENABLE
    if (!c_session->multiusers) {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
            g_message("Packet from user %s\n",c_session->userid);
    }
#endif
    
    /* copy packet datas */
    datas->buffer=g_new0(char,MAX_NUFW_PACKET_SIZE);
    if (datas->buffer == NULL){
        g_free(datas);
        return -1;
    }
    read_size = gnutls_record_recv(*(c_session->tls), datas->buffer, MAX_NUFW_PACKET_SIZE);
    if ( read_size <= 0) {
#ifdef DEBUG_ENABLE
        if (read_size <0) 
            if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
                g_message("Received error from user %s\n",datas->user_name);
#endif
        free_buffer_read(datas);
        return EOF;
    }

    /* check buffer underflow */
    if (read_size < sizeof(struct nuv2_header))
    {
        free_buffer_read(datas);
        return -1;
    }

    /* get header to check if we need to get more datas */
    struct nuv2_header* pbuf = (struct nuv2_header* )datas->buffer;
    pbuf_length=ntohs(pbuf->length);
#ifdef DEBUG_ENABLE
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
        g_message("(%s:%d) Packet size is %d\n",__FILE__,__LINE__,pbuf_length );
    }
#endif

    if (pbuf->proto==PROTO_VERSION && pbuf->msg_type == USER_HELLO){
#ifdef DEBUG_ENABLE
        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
            g_message("(%s:%d) user HELLO",__FILE__,__LINE__);
        }
#endif
        free_buffer_read(datas);
        return 1;
    }
    if (pbuf->proto==2 && pbuf_length> read_size && pbuf_length<1800 ){
        /* we realloc and get what we miss */
        datas->buffer=g_realloc(datas->buffer, pbuf_length);
        if (gnutls_record_recv(*(c_session->tls),datas->buffer+MAX_NUFW_PACKET_SIZE,read_size-pbuf_length)<0){
            free_buffer_read(datas);
            return -1;
        }
    }
    /* check message type because USER_HELLO has to be ignored */
    if ( pbuf->msg_type == USER_HELLO){
        return 1;
    }
    /* check authorization if we're facing a multi user packet */ 
    if ( (pbuf->option == 0x0) ||
            ((pbuf->option == 0x1) && c_session->multiusers)) {
        /* this is an authorized packet we fill the buffer_read structure */
        if (c_session->multiusers) {
            datas->user_name=NULL;
            datas->user_id=0;
            datas->groups=NULL;
        } else {
            datas->user_name = g_strdup(c_session->userid);
            datas->user_id = c_session->uid;
            datas->groups = g_slist_copy (c_session->groups);
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

#ifdef DEBUG_ENABLE
        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
            g_message("Pushing packet to user_checker");
#endif
        g_thread_pool_push (nuauthdatas->user_checkers,
                datas,	
                NULL
                );
    } else {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
            g_message("Bad packet, option of header is not set or unauthorized option");
        }
        free_buffer_read(datas);
        return EOF;
    }
    return 1;
}

/**
 * \return If an error occurs returns 1, else returns 0.
 */
int tls_user_accept(struct tls_user_context_t *context) {
    int c;
    struct sockaddr_in addr_clnt;
    unsigned int len_inet = sizeof addr_clnt;

    /* Wait for a connect */
    c = accept (context->sck_inet,
            (struct sockaddr *)&addr_clnt,
            &len_inet);
    if (c == -1){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
            g_warning("accept");
        }
    }

    if ( get_number_of_clients() >= context->nuauth_tls_max_clients ) {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
            g_warning("too many clients (%d configured)\n",context->nuauth_tls_max_clients);
        }
        close(c);
        return 1;
    } else {
        /* if system is not in reload */
        if (! (nuauthdatas->need_reload)){
            struct client_connection* current_client_conn=g_new0(struct client_connection,1);
            struct pre_client_elt* new_pre_client;
            current_client_conn->socket=c;
            memcpy(&current_client_conn->addr,&addr_clnt,sizeof(struct sockaddr_in));

            if ( c+1 > context->mx )
                context->mx = c + 1;
            /* Set KEEP ALIVE on connection */
            setsockopt ( c,
                    SOL_SOCKET,
                    SO_KEEPALIVE,
                    &context->option_value,
                    sizeof(context->option_value));
            /* give the connection to a separate thread */
            /*  add element to pre_client 
                create pre_client_elt */
            new_pre_client = g_new0(struct pre_client_elt,1);
            new_pre_client->socket = c;
            new_pre_client->validity = time(NULL) + context->nuauth_auth_nego_timeout;

            g_static_mutex_lock (&pre_client_list_mutex);
            pre_client_list=g_slist_prepend(pre_client_list,new_pre_client);
            g_static_mutex_unlock (&pre_client_list_mutex);
            g_thread_pool_push (context->tls_sasl_worker,
                    current_client_conn,	
                    NULL
                    );
        } else {
            shutdown(c,SHUT_RDWR);
            close(c);
        }
    }
    return 0;
}    

void tls_user_check_activity(struct tls_user_context_t *context, int c) {
    user_session * c_session;
    int u_request;
#ifdef DEBUG_ENABLE
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
        g_message("activity on %d\n",c);
#endif

    /* we lock here but can do other thing on hash as it is not destructive 
     * in push mode modification of hash are done in push_worker */
    g_static_mutex_lock (&client_mutex);
    c_session = get_client_datas_by_socket(c);
    g_static_mutex_unlock (&client_mutex);
    if (nuauthconf->session_duration && c_session->expire < time(NULL)){
        FD_CLR(c,&context->tls_rx_set);
        g_static_mutex_lock (&client_mutex);
        delete_client_by_socket(c);
        g_static_mutex_unlock (&client_mutex);
    } else {
        u_request = treat_user_request( c_session );
        if (u_request == EOF) {
            log_user_session(c_session,SESSION_CLOSE);
#ifdef DEBUG_ENABLE
            if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                g_message("client disconnect on %d\n",c);
#endif
            FD_CLR(c,&context->tls_rx_set);
            /* clean client structure */
            if (nuauthconf->push){
                struct internal_message* message=g_new0(struct internal_message,1);
                message->type = FREE_MESSAGE;
                message->datas = GINT_TO_POINTER(c);
                g_async_queue_push(nuauthdatas->tls_push_queue,message);
            } else {
                g_static_mutex_lock (&client_mutex);
                delete_client_by_socket(c);
                g_static_mutex_unlock (&client_mutex);
            }
        }else if (u_request < 0) {
#ifdef DEBUG_ENABLE
            if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                g_message("treat_user_request() failure\n");
#endif
        }
    }
}

void tls_user_main_loop(struct tls_user_context_t *context)
{    
    gpointer c_pop;
    int i, nb_active_clients;
    fd_set wk_set; /* working set */
    struct timeval tv;

    for(;;){
        /* define timeout, need to be rewritten as select write it */
        tv.tv_sec=2;
        tv.tv_usec=30000;
        /* try to get new file descriptor to update set */
        c_pop=g_async_queue_try_pop (mx_queue);
        while (c_pop) {
            int c = GPOINTER_TO_INT(c_pop);

#ifdef DEBUG_ENABLE
            if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                g_message("checking mx against %d\n",c);
#endif
            if ( c+1 > context->mx )
                context->mx = c + 1;
            /*
             * change FD_SET
             */
            FD_SET(c,&context->tls_rx_set);
            c_pop=g_async_queue_try_pop (mx_queue);
        }


        /* copy rx set to working set */
        FD_ZERO(&wk_set);
        for (i=0;i<context->mx;++i){
            if (FD_ISSET(i,&context->tls_rx_set))
                FD_SET(i,&wk_set);
        }

        nb_active_clients = select(context->mx,&wk_set,NULL,NULL,&tv);
        if (nb_active_clients == -1) {
            g_warning("select() failed, exiting\n");
            exit(EXIT_FAILURE);
        }
        if (nb_active_clients == 0)
            continue;

        /*
         * Check if a connect has occured
         */

        if (FD_ISSET(context->sck_inet,&wk_set) ){
            if (tls_user_accept(context))
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
#ifdef DEBUG_ENABLE
            if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                g_message("setting mx to %d\n",i);
#endif
            context->mx = i;
        }
    }

    close(context->sck_inet);
}

void tls_user_init(struct tls_user_context_t *context)
{
    confparams nuauth_tls_vars[] = {
        { "nuauth_tls_max_clients" , G_TOKEN_INT ,NUAUTH_TLS_MAX_CLIENTS, NULL },
        { "nuauth_number_authcheckers" , G_TOKEN_INT ,NB_AUTHCHECK, NULL },
        { "nuauth_auth_nego_timeout" , G_TOKEN_INT ,AUTH_NEGO_TIMEOUT, NULL }
    };
    struct sockaddr_in addr_inet;
    GThread *pre_client_thread;
    int result;

    /* get config file setup */
    /* parse conf file */
    parse_conffile(DEFAULT_CONF_FILE, sizeof(nuauth_tls_vars)/sizeof(confparams),nuauth_tls_vars);
    
#define READ_CONF(KEY) \
	get_confvar_value(nuauth_tls_vars, sizeof(nuauth_tls_vars)/sizeof(confparams), KEY)

    context->nuauth_tls_max_clients = *(int*)READ_CONF("nuauth_tls_max_clients");
    context->nuauth_number_authcheckers = *(int*)READ_CONF("nuauth_number_authcheckers");
    context->nuauth_auth_nego_timeout = *(int*)READ_CONF("nuauth_auth_nego_timeout");
#undef READ_CONF    

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
    if (! pre_client_thread )
        exit(EXIT_FAILURE);

    /* create tls sasl worker thread pool */
    context->tls_sasl_worker = g_thread_pool_new  ((GFunc) tls_sasl_connect,
            NULL,
            context->nuauth_number_authcheckers,
            TRUE,
            NULL);

    /* open the socket */
    context->sck_inet = socket (AF_INET,SOCK_STREAM,0);
    if (context->sck_inet == -1)
    {
        g_warning("socket() failed, exiting");
        exit(-1);
    }

    /* set socket reuse and keep alive option */
    context->option_value=1;
    setsockopt (
            context->sck_inet,
            SOL_SOCKET,
            SO_REUSEADDR,
            &context->option_value,
            sizeof(context->option_value));
    setsockopt (
            context->sck_inet,
            SOL_SOCKET,
            SO_KEEPALIVE,
            &context->option_value,
            sizeof(context->option_value));

    /* bind */
    memset(&addr_inet,0,sizeof addr_inet);
    addr_inet.sin_family= AF_INET;
    addr_inet.sin_port=htons(nuauthconf->userpckt_port);
    addr_inet.sin_addr.s_addr=nuauthconf->client_srv->s_addr;
    result = bind (context->sck_inet,
            (struct sockaddr *)&addr_inet,
            sizeof addr_inet);
    if (result == -1)
    {
        g_warning ("user bind() failed to %s:%d at %s:%d, exiting",inet_ntoa(addr_inet.sin_addr),nuauthconf->userpckt_port,__FILE__,__LINE__);
        exit(-1);
    }

    /* listen */
    result = listen(context->sck_inet,20);
    if (result == -1)
    {
        g_warning ("user listen() failed, exiting");
        exit(-1);
    }

    /* init fd_set */
    FD_ZERO(&context->tls_rx_set);
    FD_SET(context->sck_inet,&context->tls_rx_set);
    context->mx=context->sck_inet+1;
    mx_queue=g_async_queue_new ();
}

/**
 * TLS user packet server. 
 * Thread function serving user connection.
 * 
 * \return NULL
 */
void* tls_user_authsrv() {
    struct tls_user_context_t context;
    tls_user_init(&context);
    tls_user_main_loop(&context);
    return NULL;
}

void  refresh_client (gpointer key, gpointer value, gpointer user_data)
{
    /* first check if a request is needed */
    if ( ((user_session *)value)->req_needed){
        struct timeval current_time;
        gettimeofday(&current_time,NULL);
        current_time.tv_sec=current_time.tv_sec -((user_session  *)value)->last_req.tv_sec;
        current_time.tv_usec=current_time.tv_usec -((user_session  *)value)->last_req.tv_usec;

#ifdef DEBUG_ENABLE
        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
            g_message("request needed");
        }
#endif

        /* check if timeout is reached */
        if ( 
                ( current_time.tv_sec	 > 1 ) ||			
                (  abs(current_time.tv_usec) > TLS_CLIENT_MIN_DELAY ) 

           ) {
#ifdef DEBUG_ENABLE
            if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
                g_message("request now sent");
            }
#endif
            gnutls_record_send(*((user_session*)value)->tls,
                    &((struct msg_addr_set *)user_data)->msg,
                    sizeof(struct nuv2_srv_message)
                    );
            ((user_session  *)value)->req_needed=FALSE; 
            ((user_session *)value)->last_req.tv_sec=current_time.tv_sec;
            ((user_session  *)value)->last_req.tv_usec=current_time.tv_usec;
        }
    } 
}

