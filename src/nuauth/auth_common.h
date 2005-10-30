
void search_and_fill ();

gboolean compare_connection(gconstpointer conn1, gconstpointer conn2);
int sck_auth_reply;
void send_auth_response(gpointer data, gpointer userdata);
int conn_cl_delete(gconstpointer conn);
inline char get_state(connection *elt);
#define PACKET_ALONE 0
#define PACKET_IN_HASH 1
gint take_decision(connection * element,gchar place);
gint print_connection(gpointer data,gpointer userdata);
int free_connection(connection * conn);
int lock_and_free_connection(connection * conn);
void clean_connections_list ();
guint hash_connection(gconstpointer conn_p);
void decisions_queue_work (gpointer userdata, gpointer data);

char * get_rid_of_domain(const char* user);

gboolean  get_old_conn (gpointer key,
		gpointer value,
		gpointer user_data);

/**
 * internal for send_auth_response. */

struct auth_answer {
  u_int8_t answer;
  u_int16_t user_id;
  int socket;
  nufw_session* tls;
};


