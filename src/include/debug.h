// DEBUG_LEVEL's value is 1 to 8
#define DEBUG_LEVEL 4
// debug all
/* DEBUG_AREAS definition :
 * 1  main
 * 2  packet
 * 4  user
 * 8  gw
 * 16 auth
 * */
#define DEBUG_AREAS 15


int nufw_debug(int debug_level, int debug_areas, char *message);

