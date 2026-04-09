/* hostinfo.c -- just print all the IP addresses for the host args */

/* Under solaris, you need to include the nsl library */
/* as in, cc hostinfo.o -o hostinfo -lnsl */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* local routines */
static void LookupHost(char *host);
static char *LookupHostByAddr(unsigned char IPaddr[4]);


int
main(
    int argc,
    char *argv[])
{
    int i;

    if (argc <= 1) {
		fprintf(stderr,"Usage: %s hostname [hostname]*\n", argv[0]);
		exit(1);
    }

    for (i=1; i < argc; ++i) {
		printf("Argument '%s':\n", argv[i]);
		LookupHost(argv[i]);
    }

    exit(0);
}



static void
LookupHost(
    char *host)
{
	struct hostent  *phe;   /* pointer to host information entry    */
	unsigned char IPaddr[4];
	int i;

	phe = gethostbyname(host);
	if (phe == NULL) {
	    printf("  Host '%s' not found\n", host);
	    return;
	}

	/* print all its aliases */
	printf("  Aliases:\n");
	for (i=0; phe->h_aliases[i]; ++i) {
	    printf("    '%s'\n", phe->h_aliases[i]);
	}
	

	/* print all it IP addresses */
	printf("  IP Addresses:\n");
	for (i=0; phe->h_addr_list[i]; ++i) {
	    bcopy(phe->h_addr_list[i], IPaddr, sizeof(IPaddr));
	    printf("    %d.%d.%d.%d  (%s)\n",
		   IPaddr[0],
		   IPaddr[1],
		   IPaddr[2],
		   IPaddr[3],
		   LookupHostByAddr(IPaddr));
	}
}


static char *
LookupHostByAddr(
    unsigned char IPaddr[4])
{
    struct hostent  *phe;

    phe = gethostbyaddr(IPaddr,4,AF_INET);
    if (phe == NULL) {
		return("<unknown>");
    }

    return(strdup(phe->h_name));
}
