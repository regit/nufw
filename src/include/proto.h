#define PROTO_VERSION 1
#define AUTHREQ_OFFSET 12

#define AUTH_REQUEST 0x1
#define AUTH_ANSWER 0x2
#define USER_REQUEST 0x3
#define AUTH_CONTROL 0x4

/* packet field type definition for protocol v2 */
#define PACKET_FIELD 0x1
#define USERNAME_FIELD 0x2
#define AUTHENTICATION_FIELD 0x3
/* auth type definition */
#define MD5_AUTH 1

#define NOK 0
#define OK 1
#define NODECIDE 2

#define AUTHSRV_PORT 4128
#define AUTHREQ_PORT 4129


