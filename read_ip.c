#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <net/if.h>
#include <net/pfil.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>

static pfil_hook_t my_hook;

static pfil_return_t
my_filter(struct mbuf **mp, struct ifnet *ifp, int dir, void *arg, struct inpcb *inp) {
	// Convert an mbuf pointer to a data pointer of the specified type
	struct ip *ip = mtod(*mp, struct ip *);

	// ntohl: big endian to little endian
	int src = ntohl(ip->ip_src.s_addr);
	int dst = ntohl(ip->ip_dst.s_addr);
	printf("|pfil: src=%d.%d.%d.%d dst=%d.%d.%d.%d|\n",
		(src & 0xFF000000) >> 24,
		(src & 0x00FF0000) >> 16,
		(src & 0x0000FF00) >> 8,
		src & 0x000000FF,
		(dst & 0xFF000000) >> 24,
		(dst & 0x00FF0000) >> 16,
		(dst & 0x0000FF00) >> 8,
		dst & 0x000000FF
	);

	return PFIL_PASS;
}

struct pfil_hook_args pha = {
	.pa_version  = PFIL_VERSION,
	.pa_flags    = PFIL_IN,
	.pa_type     = PFIL_TYPE_IP4,
	.pa_mbuf_chk = my_filter,
	.pa_ruleset  = NULL,
	.pa_modname  = "my_pfil",
	.pa_rulname  = "log"
};

struct pfil_link_args pla = {
	.pa_flags    = PFIL_IN,
	.pa_headname = PFIL_INET_NAME,
	.pa_modname  = "my_pfil",
	.pa_rulname  = "log"
};

static int
my_modevent(module_t mod __unused, int type, void *arg __unused) {
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		my_hook = pfil_add_hook(&pha);
		pfil_link(&pla);
		printf("my_pfil: loaded\n");
		break;

	case MOD_UNLOAD:
		pfil_remove_hook(my_hook);
		printf("my_pfil: unloaded\n");
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return error;
}

static moduledata_t my_mod = {
	"my_pfil", my_modevent, NULL
};

DECLARE_MODULE(my_pfil, my_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
