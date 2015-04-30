/* 
 Modified for running perfquery with multiple lid:port tuples each invocation

 v1.0 April 30, 2015

 Copyright 2015 Blake Caldwell
 Oak Ridge National Laboratory

 This program is part of balanced-perfquery. 
 This program is licensed under GNU GPLv3. Full license in LICENSE
*/

/*
 * Copyright (c) 2004-2009 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2007 Xsigo Systems Inc.  All rights reserved.
 * Copyright (c) 2009 HNR Consulting.  All rights reserved.
 * Copyright (c) 2011 Mellanox Technologies LTD.  All rights reserved.
 * Copyright (c) 2015 Oak Ridge National Laboratory
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
//#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <ibdiag_version.h>

//#include <netinet/in.h>
#include <sys/stat.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>
#include <iba/ib_types.h>

//#include "ibdiag_common.h"
int ibverbose;
enum MAD_DEST ibd_dest_type = IB_DEST_LID;

/* general config options */
#define IBND_CONFIG_MLX_EPI (1 << 0)
#define IBDIAG_CONFIG_GENERAL IBDIAG_CONFIG_PATH"/ibdiag.conf"
char *ibd_ca = NULL;
int ibd_ca_port = 0;
int ibd_timeout = 0;
uint32_t ibd_ibnetdisc_flags = IBND_CONFIG_MLX_EPI;
uint64_t ibd_mkey;
uint64_t ibd_sakey = 0;
int show_keys = 0;

static const char *prog_name;
static const char *prog_args;
static const char **prog_examples;
static struct option *long_opts = NULL;
static const struct ibdiag_opt *opts_map[256];
static ib_portid_t sm_portid = { 0 };
ib_portid_t *ibd_sm_id;

#define ALL_PORTS 0xFF
#define MAX_PORTS 255
#define IBDIAG_CONFIG_GENERAL IBDIAG_CONFIG_PATH"/ibdiag.conf"

const static char *get_build_version(void)
{
        return "BUILD VERSION: " IBDIAG_VERSION " Build date: " __DATE__ " "
            __TIME__;
}

static void make_str_opts(const struct option *o, char *p, unsigned size)
{
        unsigned i, n = 0;

        for (n = 0; o->name && n + 2 + o->has_arg < size; o++) {
                p[n++] = (char)o->val;
                for (i = 0; i < (unsigned)o->has_arg; i++)
                        p[n++] = ':';
        }
        p[n] = '\0';
}

static void pretty_print(int start, int width, const char *str)
{
        int len = width - start;
        const char *p, *e;

        while (1) {
                while (isspace(*str))
                        str++;
                p = str;
                do {
                        e = p + 1;
                        p = strchr(e, ' ');
                } while (p && p - str < len);
                if (!p) {
                        fprintf(stderr, "%s", str);
                        break;
                }
                if (e - str == 1)
                        e = p;
                fprintf(stderr, "%.*s\n%*s", (int)(e - str), str, start, "");
                str = e;
        }
}


void ibexit(const char *fn, char *msg, ...)
{
        char buf[512];
        va_list va;
        int n;

        va_start(va, msg);
        n = vsprintf(buf, msg, va);
        va_end(va);
        buf[n] = 0;

        if (ibdebug)
                printf("%s: iberror: [pid %d] %s: failed: %s\n",
                       prog_name ? prog_name : "", getpid(), fn, buf);
        else
                printf("%s: iberror: failed: %s\n",
                       prog_name ? prog_name : "", buf);

        exit(-1);
}


#undef DEBUG
#define DEBUG(fmt, ...) do { \
        if (ibdebug) IBDEBUG(fmt, ## __VA_ARGS__); \
} while (0)
#define VERBOSE(fmt, ...) do { \
        if (ibverbose) IBVERBOSE(fmt, ## __VA_ARGS__); \
} while (0)
#define IBEXIT(fmt, ...) ibexit(__FUNCTION__, fmt, ## __VA_ARGS__)

/* not all versions of ib_types.h will have this define */
#ifndef IB_PM_PC_XMIT_WAIT_SUP
#define IB_PM_PC_XMIT_WAIT_SUP (CL_HTON16(((uint16_t)1)<<12))
#endif


static int reset, reset_only, port, extended;

/* BC: lids and ports form a tuple (1:1). Constructs a list of queries to perform */
static int lids[MAX_PORTS];
static int ports[MAX_PORTS];
static int ports_count;


struct ibmad_port *srcport;
struct ibdiag_opt {
        const char *name;
        char letter;
        unsigned has_arg;
        const char *arg_tmpl;
        const char *description;
};

struct perf_count {
	uint32_t portselect;
	uint32_t counterselect;
	uint32_t symbolerrors;
	uint32_t linkrecovers;
	uint32_t linkdowned;
	uint32_t rcverrors;
	uint32_t rcvremotephyerrors;
	uint32_t rcvswrelayerrors;
	uint32_t xmtdiscards;
	uint32_t xmtconstrainterrors;
	uint32_t rcvconstrainterrors;
	uint32_t linkintegrityerrors;
	uint32_t excbufoverrunerrors;
	uint32_t vl15dropped;
	uint32_t xmtdata;
	uint32_t rcvdata;
	uint32_t xmtpkts;
	uint32_t rcvpkts;
	uint32_t xmtwait;
};

struct perf_count_ext {
	uint32_t portselect;
	uint32_t counterselect;
	uint64_t portxmitdata;
	uint64_t portrcvdata;
	uint64_t portxmitpkts;
	uint64_t portrcvpkts;
	uint64_t portunicastxmitpkts;
	uint64_t portunicastrcvpkts;
	uint64_t portmulticastxmitpkits;
	uint64_t portmulticastrcvpkts;
};

static uint8_t pc[1024];

struct perf_count perf_count =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
struct perf_count_ext perf_count_ext = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

static const struct ibdiag_opt common_opts[] = {
        {"config", 'z', 1, "<config>", "use config file, default: " IBDIAG_CONFIG_GENERAL},
        {"Ca", 'C', 1, "<ca>", "Ca name to use"},
        {"Port", 'P', 1, "<port>", "Ca port number to use"},
        {"Direct", 'D', 0, NULL, "use Direct address argument"},
        {"Lid", 'L', 0, NULL, "use LID address argument"},
        {"Guid", 'G', 0, NULL, "use GUID address argument"},
        {"timeout", 't', 1, "<ms>", "timeout in ms"},
        {"sm_port", 's', 1, "<lid>", "SM port lid"},
        {"show_keys", 'K', 0, NULL, "display security keys in output"},
        {"m_key", 'y', 1, "<key>", "M_Key to use in request"},
        {"errors", 'e', 0, NULL, "show send and receive errors"},
        {"verbose", 'v', 0, NULL, "increase verbosity level"},
        {"debug", 'd', 0, NULL, "raise debug level"},
        {"help", 'h', 0, NULL, "help message"},
        {"version", 'V', 0, NULL, "show version"},
        {0}
};

static void make_opt(struct option *l, const struct ibdiag_opt *o,
                     const struct ibdiag_opt *map[])
{
        l->name = o->name;
        l->has_arg = o->has_arg;
        l->flag = NULL;
        l->val = o->letter;
        if (!map[l->val])
                map[l->val] = o;
}

static struct option *make_long_opts(const char *exclude_str,
                                     const struct ibdiag_opt *custom_opts,
                                     const struct ibdiag_opt *map[])
{
        struct option *long_opts, *l;
        const struct ibdiag_opt *o;
        unsigned n = 0;

        if (custom_opts)
                for (o = custom_opts; o->name; o++)
                        n++;

        long_opts = malloc((sizeof(common_opts) / sizeof(common_opts[0]) + n) *
                           sizeof(*long_opts));
        if (!long_opts)
                return NULL;

        l = long_opts;

        if (custom_opts)
                for (o = custom_opts; o->name; o++)
                        make_opt(l++, o, map);

        for (o = common_opts; o->name; o++) {
                if (exclude_str && strchr(exclude_str, o->letter))
                        continue;
                make_opt(l++, o, map);
        }

        memset(l, 0, sizeof(*l));

        return long_opts;
}

void ibdiag_show_usage()
{
        struct option *o = long_opts;
        int n;

        fprintf(stderr, "\nUsage: %s [options] %s\n\n", prog_name,
                prog_args ? prog_args : "");

        if (long_opts[0].name)
                fprintf(stderr, "Options:\n");
        for (o = long_opts; o->name; o++) {
                const struct ibdiag_opt *io = opts_map[o->val];
                n = fprintf(stderr, "  --%s", io->name);
                if (isprint(io->letter))
                        n += fprintf(stderr, ", -%c", io->letter);
                if (io->has_arg)
                        n += fprintf(stderr, " %s",
                                     io->arg_tmpl ? io->arg_tmpl : "<val>");
                if (io->description && *io->description) {
                        n += fprintf(stderr, "%*s  ", 24 - n > 0 ? 24 - n : 0,
                                     "");
                        pretty_print(n, 74, io->description);
                }
                fprintf(stderr, "\n");
        }

        if (prog_examples) {
                const char **p;
                fprintf(stderr, "\nExamples:\n");
                for (p = prog_examples; *p && **p; p++)
                        fprintf(stderr, "  %s %s\n", prog_name, *p);
        }

        fprintf(stderr, "\n");

        exit(2);
}

/** =========================================================================
 *  * Resolve the SM portid using the umad layer rather than using
 *   * ib_resolve_smlid_via which requires a PortInfo query on the local port.
 *    */
int resolve_sm_portid(char *ca_name, uint8_t portnum, ib_portid_t *sm_id)
{
        umad_port_t port;
        int rc;

        if (!sm_id)
                return (-1);

        if ((rc = umad_get_port(ca_name, portnum, &port)) < 0)
                return rc;

        memset(sm_id, 0, sizeof(*sm_id));
        sm_id->lid = port.sm_lid;
        sm_id->sl = port.sm_sl;

        umad_release_port(&port);

        return 0;
}

/** =========================================================================
 *  * Resolve local CA characteristics using the umad layer rather than using
 *   * ib_resolve_self_via which requires SMP queries on the local port.
 *    */
int resolve_self(char *ca_name, uint8_t ca_port, ib_portid_t *portid,
                 int *portnum, ibmad_gid_t *gid)
{
        umad_port_t port;
        uint64_t prefix, guid;
        int rc;

        if (!(portid || portnum || gid))
                return (-1);

        if ((rc = umad_get_port(ca_name, ca_port, &port)) < 0)
                return rc;

        if (portid) {
                memset(portid, 0, sizeof(*portid));
                portid->lid = port.base_lid;
                portid->sl = port.sm_sl;
        }
        if (portnum)
                *portnum = port.portnum;
        if (gid) {
                memset(gid, 0, sizeof(*gid));
                prefix = cl_hton64(port.gid_prefix);
                guid = cl_hton64(port.port_guid);
                mad_encode_field(*gid, IB_GID_PREFIX_F, &prefix);
                mad_encode_field(*gid, IB_GID_GUID_F, &guid);
        }

        umad_release_port(&port);

        return 0;
}

int resolve_gid(char *ca_name, uint8_t ca_port, ib_portid_t * portid,
                ibmad_gid_t gid, ib_portid_t * sm_id,
                const struct ibmad_port *srcport)
{
        ib_portid_t sm_portid;
        char buf[IB_SA_DATA_SIZE] = { 0 };

        if (!sm_id) {
                sm_id = &sm_portid;
                if (resolve_sm_portid(ca_name, ca_port, sm_id) < 0)
                        return -1;
        }

        if ((portid->lid =
             ib_path_query_via(srcport, gid, gid, sm_id, buf)) < 0)
                return -1;

        return 0;
}

int resolve_guid(char *ca_name, uint8_t ca_port, ib_portid_t *portid,
                 uint64_t *guid, ib_portid_t *sm_id,
                 const struct ibmad_port *srcport)
{
        ib_portid_t sm_portid;
        uint8_t buf[IB_SA_DATA_SIZE] = { 0 };
        uint64_t prefix;
        ibmad_gid_t selfgid;

        if (!sm_id) {
                sm_id = &sm_portid;
                if (resolve_sm_portid(ca_name, ca_port, sm_id) < 0)
                        return -1;
        }

        if (resolve_self(ca_name, ca_port, NULL, NULL, &selfgid) < 0)
                return -1;

        memcpy(&prefix, portid->gid, sizeof(prefix));
        if (!prefix)
                mad_set_field64(portid->gid, 0, IB_GID_PREFIX_F,
                                IB_DEFAULT_SUBN_PREFIX);
        if (guid)
                mad_set_field64(portid->gid, 0, IB_GID_GUID_F, *guid);

        if ((portid->lid =
             ib_path_query_via(srcport, selfgid, portid->gid, sm_id, buf)) < 0)
                return -1;

        mad_decode_field(buf, IB_SA_PR_SL_F, &portid->sl);
        return 0;
}

int resolve_portid_str(char *ca_name, uint8_t ca_port, ib_portid_t * portid,
                       char *addr_str, enum MAD_DEST dest_type,
                       ib_portid_t *sm_id, const struct ibmad_port *srcport)
{
        ibmad_gid_t gid;
        uint64_t guid;
        int lid;
        char *routepath;
        ib_portid_t selfportid = { 0 };
        int selfport = 0;

        memset(portid, 0, sizeof *portid);

        switch (dest_type) {
        case IB_DEST_LID:
                lid = strtol(addr_str, 0, 0);
                if (!IB_LID_VALID(lid))
                        return -1;
                return ib_portid_set(portid, lid, 0, 0);

        case IB_DEST_DRPATH:
                if (str2drpath(&portid->drpath, addr_str, 0, 0) < 0)
                        return -1;
                return 0;

        case IB_DEST_GUID:
                if (!(guid = strtoull(addr_str, 0, 0)))
                        return -1;

                /* keep guid in portid? */
                return resolve_guid(ca_name, ca_port, portid, &guid, sm_id,
                                    srcport);

        case IB_DEST_DRSLID:
                lid = strtol(addr_str, &routepath, 0);
                routepath++;
                if (!IB_LID_VALID(lid))
                        return -1;
                ib_portid_set(portid, lid, 0, 0);

                /* handle DR parsing and set DrSLID to local lid */
                if (resolve_self(ca_name, ca_port, &selfportid, &selfport,
                                 NULL) < 0)
                        return -1;
                if (str2drpath(&portid->drpath, routepath, selfportid.lid, 0) <
                    0)
                        return -1;
                return 0;

        case IB_DEST_GID:
                if (inet_pton(AF_INET6, addr_str, &gid) <= 0)
                        return -1;
                return resolve_gid(ca_name, ca_port, portid, gid, sm_id,
                                   srcport);
        default:
                IBWARN("bad dest_type %d", dest_type);
        }

        return -1;
}

static int process_opt2(int ch, char *optarg)
{
        char *endp;
        long val;

        switch (ch) {
        case 'h':
                ibdiag_show_usage();
                break;
        case 'V':
                fprintf(stderr, "%s %s\n", prog_name, get_build_version());
                exit(0);
        case 'e':
                madrpc_show_errors(1);
                break;
        case 'v':
                ibverbose++;
                break;
        case 'd':
                ibdebug++;
                madrpc_show_errors(1);
                umad_debug(ibdebug - 1);
                break;
        case 'C':
                ibd_ca = optarg;
                break;
        case 'P':
                ibd_ca_port = strtoul(optarg, 0, 0);
                break;
        case 'D':
                ibd_dest_type = IB_DEST_DRPATH;
                break;
        case 'L':
                ibd_dest_type = IB_DEST_LID;
                break;
        case 'G':
                ibd_dest_type = IB_DEST_GUID;
                break;
        case 't':
                errno = 0;
                val = strtol(optarg, &endp, 0);
                if (errno || (endp && *endp != '\0') || val <= 0 ||
                    val > INT_MAX)
                        IBEXIT("Invalid timeout \"%s\".  Timeout requires a "
                                "positive integer value < %d.", optarg, INT_MAX);
                else {
                        madrpc_set_timeout((int)val);
                        ibd_timeout = (int)val;
                }
                break;
        case 's':
                /* srcport is not required when resolving via IB_DEST_LID */
                if (resolve_portid_str(ibd_ca, ibd_ca_port, &sm_portid, optarg,
                                IB_DEST_LID, 0, NULL) < 0)
                        IBEXIT("cannot resolve SM destination port %s",
                                optarg);
                ibd_sm_id = &sm_portid;
                break;
        case 'K':
                show_keys = 1;
                break;
        case 'y':
                errno = 0;
                ibd_mkey = strtoull(optarg, &endp, 0);
                if (errno || *endp != '\0') {
                        errno = 0;
                        ibd_mkey = strtoull(getpass("M_Key: "), &endp, 0);
                        if (errno || *endp != '\0') {
                                IBEXIT("Bad M_Key");
                        }
                }
                break;
        default:
                return -1;
        }

        return 0;
}

static int process_opt(void *context, int ch, char *optarg)
{
        switch (ch) {
        case 'x':
                extended = 1;
                break;
        case 'r':
                reset++;
                break;
        case 'R':
                reset_only++;
                break;
        default:
                return -1;
        }
        return 0;
}


int ibdiag_process_opts(int argc, char *const argv[], void *cxt,
                        const char *exclude_common_str,
                        const struct ibdiag_opt custom_opts[],
                        int (*custom_handler) (void *cxt, int val,
                                               char *optarg),
                        const char *usage_args, const char *usage_examples[])
{
        char str_opts[1024];
        const struct ibdiag_opt *o;

        prog_name = argv[0];
        prog_args = usage_args;
        prog_examples = usage_examples;

        if (long_opts)
                free(long_opts);

        long_opts = make_long_opts(exclude_common_str, custom_opts, opts_map);
        if (!long_opts)
                return -1;

//        read_ibdiag_config(IBDIAG_CONFIG_GENERAL);

        make_str_opts(long_opts, str_opts, sizeof(str_opts));

        while (1) {
                int ch = getopt_long(argc, argv, str_opts, long_opts, NULL);
                if (ch == -1)
                        break;
                o = opts_map[ch];
                if (!o)
                        ibdiag_show_usage();
                if (custom_handler) {
                        if (custom_handler(cxt, ch, optarg) &&
                            process_opt2(ch, optarg))
                                ibdiag_show_usage();
                } else if (process_opt2(ch, optarg))
                        ibdiag_show_usage();
        }

        return 0;
}

/* Notes: IB semantics is to cap counters if count has exceeded limits.
 * Therefore we must check for overflows and cap the counters if necessary.
 *
 * mad_decode_field and mad_encode_field assume 32 bit integers passed in
 * for fields < 32 bits in length.
 */

static void dump_perfcounters(int extended, int timeout, uint16_t cap_mask,
			      ib_portid_t * portid, int port)
{
	char buf[1024];

//	if (extended != 1) {
		memset(pc, 0, sizeof(pc));
		if (!pma_query_via(pc, portid, port, timeout,
				   IB_GSI_PORT_COUNTERS, srcport))
			IBEXIT("perfquery");
		if (!(cap_mask & IB_PM_PC_XMIT_WAIT_SUP)) {
			/* if PortCounters:PortXmitWait not supported clear this counter */
			VERBOSE("PortXmitWait not indicated"
				" so ignore this counter");
			perf_count.xmtwait = 0;
			mad_encode_field(pc, IB_PC_XMT_WAIT_F,
					 &perf_count.xmtwait);
		}
		mad_dump_fields(buf, sizeof buf, pc, sizeof pc,
						IB_PC_FIRST_F,
						(cap_mask & IB_PM_PC_XMIT_WAIT_SUP)?IB_PC_LAST_F:(IB_PC_RCV_PKTS_F+1));
                printf("# Port counters: %s port %d "
                       "(CapMask: 0x%02X)\n%s",
                       portid2str(portid), port, ntohs(cap_mask), buf);

//	} else {
		/* 1.2 errata: bit 9 is extended counter support
		 * bit 10 is extended counter NoIETF
		 */
		if (!(cap_mask & IB_PM_EXT_WIDTH_SUPPORTED) &&
		    !(cap_mask & IB_PM_EXT_WIDTH_NOIETF_SUP))
			IBWARN
			    ("PerfMgt ClassPortInfo 0x%x; No extended counter support indicated\n",
			     ntohs(cap_mask));

		memset(pc, 0, sizeof(pc));
		if (!pma_query_via(pc, portid, port, timeout,
				   IB_GSI_PORT_COUNTERS_EXT, srcport))
			IBEXIT("perfextquery");
		mad_dump_perfcounters_ext(buf, sizeof buf, pc,
						  sizeof pc);
//	}

                printf("# Port extended counters: %s port %d "
                       "(CapMask: 0x%02X)\n%s",
                       portid2str(portid), port, ntohs(cap_mask), buf);
}

static void reset_counters(int extended, int timeout, int mask,
			   ib_portid_t * portid, int port)
{
	memset(pc, 0, sizeof(pc));
//	if (extended != 1) {
		if (!performance_reset_via(pc, portid, port, mask, timeout,
					   IB_GSI_PORT_COUNTERS, srcport))
			IBEXIT("perf reset");
//	} else {
		if (!performance_reset_via(pc, portid, port, mask, timeout,
					   IB_GSI_PORT_COUNTERS_EXT, srcport))
			IBEXIT("perf ext reset");
//	}
}


int main(int argc, char **argv)
{
	int mgmt_classes[3] = { IB_SMI_CLASS, IB_SA_CLASS, IB_PERFORMANCE_CLASS };
	ib_portid_t myportid = { 0 };
	ib_portid_t portid[MAX_PORTS];
	int mask = 0xffff;
	uint64_t ext_mask = 0xffffffffffffffffULL;
	uint16_t cap_mask;
	char tmpstr[80];
	int i;
        char *tokens;

	const struct ibdiag_opt opts[] = {
		{"extended", 'x', 0, NULL, "show extended port counters"},
		{"reset_after_read", 'r', 0, NULL, "reset counters after read"},
		{"Reset_only", 'R', 0, NULL, "only reset counters"},
		{0}
	};
	char usage_args[] = " [<lid|guid> [[port(s)] [reset_mask]]]";
	const char *usage_examples[] = {
		"\t\t# read local port's performance counters",
		"32 1\t\t# read performance counters from lid 32, port 1",
		"-x 32 1\t# read extended performance counters from lid 32, port 1",
		"-r 32 1\t# read performance counters and reset",
		"-x -r 32 1\t# read extended performance counters and reset",
		"-R 0x20 1\t# reset performance counters of port 1 only",
		"-x -R 0x20 1\t# reset extended performance counters of port 1 only",
		"-R 32 2 0x0fff\t# reset only error counters of port 2",
		"-R 32 2 0xf000\t# reset only non-error counters of port 2",
		"-l 32 1-10\t# read performance counters from lid 32, port 1-10, output each port",
		"-l 32 1,4,8\t# read performance counters from lid 32, port 1, 4, and 8, output each port",
		NULL,
	};

	ibdiag_process_opts(argc, argv, NULL, "DK", opts, process_opt,
			    usage_args, usage_examples);

	argc -= optind;
	argv += optind;
        
        for (i = 0; i < argc; i++) {
          if (strchr(argv[i], ':')) {
            tokens = strtok (argv[i],":");
            if (tokens != NULL)
              lids[ports_count] = strtoul(tokens, 0, 0);
            else
              IBEXIT("malformed lid:port tuple\n");
            tokens = strtok (NULL,":");
            if (tokens != NULL) 
              ports[ports_count] = strtoul(tokens, 0, 0);
            else
              IBEXIT("malformed lid:port tuple\n");
            ports_count++;
          }
        }

	srcport = mad_rpc_open_port(ibd_ca, ibd_ca_port, mgmt_classes, 3);
	if (!srcport)
		IBEXIT("Failed to open '%s' port '%d'", ibd_ca, ibd_ca_port);
        if (resolve_self(ibd_ca, ibd_ca_port, &myportid, &port, 0) < 0)
			IBEXIT("can't resolve self port %s", argv[0]);
        // initialize portid
        /*
        portid = malloc(sizeof(ib_portid_t) * ports_count);
        if (portid == NULL)
          IBEXIT("Failed to allocate memory for %d portids\n",ports_count);
	*/

        if (ports_count > 0) {
          for (i = 0; i < ports_count; i++) {

          sprintf(tmpstr, "%d", lids[i]);
          if (resolve_portid_str(ibd_ca, ibd_ca_port, &portid[i], tmpstr,
                                 ibd_dest_type, ibd_sm_id, srcport) < 0)
                        IBEXIT("can't resolve destination port %s", argv[0]);
  	  /* PerfMgt ClassPortInfo is a required attribute */
	  memset(pc, 0, sizeof(pc));
	  if (!pma_query_via(pc, &portid[i], ports[i], ibd_timeout, CLASS_PORT_INFO,
			   srcport))
	  	  IBEXIT("classportinfo query");
	  /* ClassPortInfo should be supported as part of libibmad */
	  memcpy(&cap_mask, pc + 2, sizeof(cap_mask));	/* CapabilityMask */

	  /* reset not supported now 
          if (reset_only)
		  goto do_reset;
          */
	  dump_perfcounters(extended, ibd_timeout, cap_mask,
					  &portid[i], ports[i]);
          }
        }
        dump_perfcounters(extended, ibd_timeout, cap_mask, &myportid,
                          port);

        if (!reset)
		goto done;
       
do_reset:
	if (argc <= 2 && (cap_mask & IB_PM_PC_XMIT_WAIT_SUP))
		mask |= (1 << 16);	/* reset portxmitwait */

	reset_counters(extended, ibd_timeout, mask, &myportid, port);

done:  
        //free(portid);
	mad_rpc_close_port(srcport);
	exit(0);
}
