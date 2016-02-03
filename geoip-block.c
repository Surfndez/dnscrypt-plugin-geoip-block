
#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef _WIN32
# include <ws2tcpip.h>
#endif

#include <dnscrypt/plugin.h>
#include <GeoIP.h>
#include <ldns/ldns.h>

DCPLUGIN_MAIN(__FILE__);

typedef struct StrList_ {
    struct StrList_ *next;
    char            *str;
} StrList;

typedef struct Context_ {
    StrList *blacklist;
    GeoIP   *geoip;
} Context;

static struct option getopt_long_options[] = {
    { "blacklist", 1, NULL, 'b' },
    { "geoipdb", 1, NULL, 'g' },
    { NULL, 0, NULL, 0 }
};
static const char *getopt_options = "bg";

static void
str_list_free(StrList * const str_list)
{
    StrList *next;
    StrList *scanned = str_list;

    while (scanned != NULL) {
        next = scanned->next;
        free(scanned->str);
        scanned->next = NULL;
        scanned->str = NULL;
        free(scanned);
        scanned = next;
    }
}

static StrList *
parse_str_list(const char * const file)
{
    char     line[300U];
    FILE    *fp;
    char    *ptr;
    StrList *str_list = NULL;
    StrList *str_list_item;
    StrList *str_list_last = NULL;

    if ((fp = fopen(file, "r")) == NULL) {
        return NULL;
    }
    while (fgets(line, (int) sizeof line, fp) != NULL) {
        while ((ptr = strchr(line, '\n')) != NULL ||
               (ptr = strchr(line, '\r')) != NULL) {
            *ptr = 0;
        }
        if (*line == 0 || *line == '#') {
            continue;
        }
        if ((str_list_item = calloc(1U, sizeof *str_list_item)) == NULL ||
            (str_list_item->str = strdup(line)) == NULL) {
            break;
        }
        str_list_item->next = NULL;
        *(str_list == NULL ? &str_list : &str_list_last->next) = str_list_item;
        str_list_last = str_list_item;
    }
    if (!feof(fp)) {
        str_list_free(str_list);
        str_list = NULL;
    }
    fclose(fp);

    return str_list;
}

const char *
dcplugin_description(DCPlugin * const dcplugin)
{
    return "Block queries resolving to a set of countries";
}

const char *
dcplugin_long_description(DCPlugin * const dcplugin)
{
    return
        "This plugin returns a REFUSED response if a query returns an IP\n"
        "address hosted in a country listed in a blacklist file.\n"
        "\n"
        "Recognized switches are:\n"
        "--blacklist=<file>\n"
        "--geoipdb=<file>\n"
        "\n"
        "A blacklist file should list one country code per line.\n"
        "For example:\n"
        "\n"
        "CA\n"
        "UK\n"
        "\n"
        "The geoipdb file should be the full path to GeoIP.dat.\n"
        "\n"
        "# dnscrypt-proxy --plugin \\\n"
        "  libgeoip_block,--blacklist=/etc/blk-countries,--geoipdb=/etc/GeoIP.dat\n";
}

int
dcplugin_init(DCPlugin * const dcplugin, int argc, char *argv[])
{
    Context  *context;
    GeoIP    *geoip;
    int       opt_flag;
    int       option_index = 0;

    if ((context = calloc((size_t) 1U, sizeof *context)) == NULL) {
        return -1;
    }
    dcplugin_set_user_data(dcplugin, context);
    if (context == NULL) {
        return -1;
    }
    context->blacklist = NULL;
    context->geoip = NULL;
    optind = 0;
#ifdef _OPTRESET
    optreset = 1;
#endif
    while ((opt_flag = getopt_long(argc, argv,
                                   getopt_options, getopt_long_options,
                                   &option_index)) != -1) {
        switch (opt_flag) {
        case 'b':
            if ((context->blacklist = parse_str_list(optarg)) == NULL) {
                return -1;
            }
            break;
        case 'g':
            if ((context->geoip = GeoIP_open(optarg, GEOIP_MEMORY_CACHE)) == NULL) {
                return -1;
            }
            break;
        default:
            return -1;
        }
    }
    if (context->blacklist == NULL || context->geoip == NULL) {
        return -1;
    }
    return 0;
}

int
dcplugin_destroy(DCPlugin * const dcplugin)
{
    Context *context = dcplugin_get_user_data(dcplugin);

    if (context == NULL) {
        return 0;
    }
    str_list_free(context->blacklist);
    context->blacklist = NULL;
    GeoIP_delete(context->geoip);
    context->geoip = NULL;
    free(context);

    return 0;
}

static DCPluginSyncFilterResult
apply_block_ips(DCPluginDNSPacket *dcp_packet, Context * const context,
                ldns_pkt * const packet)
{
    StrList      *scanned;
    ldns_rr_list *answers;
    ldns_rr      *answer;
    const char   *country;
    char         *answer_str;
    GeoIPLookup   gl;
    ldns_rr_type  type;
    size_t        answers_count;
    size_t        i;

    answers = ldns_pkt_answer(packet);
    answers_count = ldns_rr_list_rr_count(answers);
    for (i = (size_t) 0U; i < answers_count; i++) {
        answer = ldns_rr_list_rr(answers, i);
        type = ldns_rr_get_type(answer);
        if (type != LDNS_RR_TYPE_A && type != LDNS_RR_TYPE_AAAA) {
            continue;
        }
        if ((answer_str = ldns_rdf2str(ldns_rr_a_address(answer))) == NULL) {
            return DCP_SYNC_FILTER_RESULT_FATAL;
        }
        if ((country =
             GeoIP_country_code_by_addr_gl(context->geoip,
                                           answer_str, &gl)) == NULL) {
            continue;
        }
        scanned = context->blacklist;
        do {
            if (strcasecmp(scanned->str, country) == 0) {
                LDNS_RCODE_SET(dcplugin_get_wire_data(dcp_packet),
                               LDNS_RCODE_REFUSED);
                break;
            }
        } while ((scanned = scanned->next) != NULL);
        free(answer_str);
    }
    return DCP_SYNC_FILTER_RESULT_OK;
}

DCPluginSyncFilterResult
dcplugin_sync_post_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
    Context                  *context = dcplugin_get_user_data(dcplugin);
    ldns_pkt                 *packet;
    DCPluginSyncFilterResult  result = DCP_SYNC_FILTER_RESULT_OK;

    if (context->blacklist == NULL) {
        return DCP_SYNC_FILTER_RESULT_OK;
    }
    if (ldns_wire2pkt(&packet, dcplugin_get_wire_data(dcp_packet),
                      dcplugin_get_wire_data_len(dcp_packet)) != LDNS_STATUS_OK) {
        return DCP_SYNC_FILTER_RESULT_ERROR;
    }
    if ((result = apply_block_ips(dcp_packet, context, packet)
         != DCP_SYNC_FILTER_RESULT_OK)) {
        ldns_pkt_free(packet);
        return result;
    }
    ldns_pkt_free(packet);

    return DCP_SYNC_FILTER_RESULT_OK;
}
