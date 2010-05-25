#define PORT 5556
#define SERVER "127.0.0.1"

#include <gnutls/gnutls.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>
#ifdef _WIN32
# include <io.h>
# include <winbase.h>
#endif

#ifndef __attribute__
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#  define __attribute__(Spec)	/* empty */
# endif
#endif

/* the number of elements in the priority structures.
 */
#define PRI_MAX 16

extern const char str_unknown[];

int print_info (gnutls_session_t state, const char *hostname, int insecure);
void print_cert_info (gnutls_session_t state, const char *hostname,
		      int insecure);
void print_list (int verbose);

void parse_comp (char **comp, int ncomp, int *comp_priority);
void parse_kx (char **kx, int nkx, int *kx_priority);
void parse_ctypes (char **ctype, int nctype, int *cert_type_priority);
void parse_macs (char **macs, int nmacs, int *mac_priority);
void parse_ciphers (char **ciphers, int nciphers, int *cipher_priority);
void parse_protocols (char **protocols, int protocols_size,
		      int *protocol_priority);
const char *raw_to_string (const unsigned char *raw, size_t raw_size);
int service_to_port (const char *service);

void sockets_init (void);
