
#define PROGNAME_WIDTH 64

#define PRG_HASH_SIZE 211

static struct prg_node {
    struct prg_node *next;
    unsigned long inode;
    char name[PROGNAME_WIDTH];
} *prg_hash[PRG_HASH_SIZE];

int     prg_cache_loaded;


void prg_cache_load(void);
const char *prg_cache_get(unsigned long inode);
void prg_cache_clear(void);

