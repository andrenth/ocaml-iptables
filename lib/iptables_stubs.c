#include <errno.h>
#include <netdb.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libiptc/libiptc.h>
#include <libiptc/libxtc.h>
#include <xtables.h>

#include <caml/bigarray.h>
#include <caml/custom.h>
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/signals.h>

#define Some_val(v)      Field(v, 0)
#define Val_none         Val_int(0)
#define Inet_addr_val(v) ((*((struct in_addr *) (v))).s_addr)

#define PROTO_INVALID 0
#define PROTO_TCP     1
#define PROTO_UDP     2

static void
finalize_iptables_entry(value ml_entry)
{
    struct ipt_entry *e = (struct ipt_entry *)Data_custom_val(ml_entry);
    free(e);
}

static struct custom_operations iptables_entry_ops = {
    "iptables entry custom ops",
    finalize_iptables_entry,
    custom_compare_default,
    custom_hash_default,
    custom_serialize_default,
    custom_deserialize_default,
};

static CAMLprim value
Val_some(value v)
{
    CAMLparam1(v);
    CAMLlocal1(r);

    r = caml_alloc(1, 0);
    Store_field(r, 0, v);

    CAMLreturn(r);
}

static void
iptables_error(const char *err)
{
    caml_raise_with_string(*caml_named_value("Iptables.Iptables_error"), err);
}

static CAMLprim value
Val_counters(struct ipt_counters *icp)
{
    CAMLparam0();
    CAMLlocal1(counters);
    counters = caml_alloc(2, 0);
    Store_field(counters, 0, copy_int64((int64_t)icp->pcnt));
    Store_field(counters, 1, copy_int64((int64_t)icp->pcnt));
    CAMLreturn(counters);
}

static void
Counters_val(struct ipt_counters *icp, value ml_counters)
{
    CAMLparam1(ml_counters);
    icp->pcnt = (uint64_t)Int64_val(Field(ml_counters, 0));
    icp->bcnt = (uint64_t)Int64_val(Field(ml_counters, 1));
    CAMLreturn0;
}

CAMLprim value
caml_iptables_is_chain(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    char *c = String_val(ml_chain);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;

    CAMLreturn(Bool_val(iptc_is_chain(c, h)));
}

CAMLprim value
caml_iptables_init(value ml_tablename)
{
    CAMLparam1(ml_tablename);
    CAMLlocal1(ml_handle);
    char *t = String_val(ml_tablename);
    struct iptc_handle *h = iptc_init(t);

    if (h == NULL)
        iptables_error(iptc_strerror(errno));

    CAMLreturn((value)h);
}

CAMLprim value
caml_iptables_free(value ml_handle)
{
    CAMLparam1(ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    iptc_free(h);
    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_first_chain(value ml_handle)
{
    CAMLparam1(ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    const char *chain = iptc_first_chain(h);

    CAMLreturn(chain != NULL ? Val_some(caml_copy_string(chain)) : Val_none);
}

CAMLprim value
caml_iptables_next_chain(value ml_handle)
{
    CAMLparam1(ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    const char *chain = iptc_next_chain(h);

    CAMLreturn(chain != NULL ? Val_some(caml_copy_string(chain)) : Val_none);
}

CAMLprim value
caml_iptables_first_rule(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    CAMLlocal2(ml_entry, res);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *chain = String_val(ml_chain);
    const struct ipt_entry *e = iptc_first_rule(chain, h);

    if (e != NULL) {
        ml_entry = caml_alloc_custom(&iptables_entry_ops, e->next_offset, 0, 1);
        memcpy(Data_custom_val(ml_entry), e, e->next_offset);
        res = Val_some(ml_entry);
    } else {
        res = Val_none;
    }

    CAMLreturn(res);
}

CAMLprim value
caml_iptables_next_rule(value ml_handle, value ml_prev)
{
    CAMLparam2(ml_prev, ml_handle);
    CAMLlocal2(ml_entry, res);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    struct ipt_entry *prev = (struct ipt_entry *)Data_custom_val(ml_prev);
    const struct ipt_entry *e = iptc_next_rule(prev, h);

    if (e != NULL) {
        ml_entry = caml_alloc_custom(&iptables_entry_ops, e->next_offset, 0, 1);
        memcpy(Data_custom_val(ml_entry), e, e->next_offset);
        res = Val_some(ml_entry);
    } else {
        res = Val_none;
    }

    CAMLreturn(res);
}

CAMLprim value
caml_iptables_get_target(value ml_handle, value ml_entry)
{
    CAMLparam2(ml_entry, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    struct ipt_entry *e = (struct ipt_entry *)Data_custom_val(ml_entry);

    CAMLreturn(caml_copy_string(iptc_get_target(e, h)));
}

CAMLprim value
caml_iptables_builtin(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    CAMLreturn(Bool_val(iptc_builtin(c, h)));
}

CAMLprim value
caml_iptables_get_policy(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    const char *policy;
    struct ipt_counters ic;

    policy = iptc_get_policy(c, &ic, h);

    CAMLreturn(policy != NULL ? Val_some(caml_copy_string(policy)) : Val_none);
}

CAMLprim value
caml_iptables_get_policy_and_counters(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    CAMLlocal1(res);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    const char *policy;
    struct ipt_counters ic;

    policy = iptc_get_policy(c, &ic, h);

    res = caml_alloc(2, 0);
    Store_field(res, 0, caml_copy_string(policy));
    Store_field(res, 1, Val_counters(&ic));

    CAMLreturn(policy != NULL ? Val_some(res) : Val_none);
}

CAMLprim value
caml_iptables_insert_entry(value ml_handle, value ml_chain, value ml_entry,
                           value ml_num)
{
    CAMLparam4(ml_chain, ml_entry, ml_num, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    struct ipt_entry *e = (struct ipt_entry *)Data_custom_val(ml_entry);

    unsigned int n = Int_val(ml_num);

    if (iptc_insert_entry(c, e, n, h) == 0)
        iptables_error(errno ? iptc_strerror(errno) : "version mismatch");

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_replace_entry(value ml_handle, value ml_chain, value ml_entry,
                            value ml_num)
{
    CAMLparam4(ml_chain, ml_entry, ml_num, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    struct ipt_entry *e = (struct ipt_entry *)Data_custom_val(ml_entry);
    unsigned int n = Val_int(ml_num);

    if (iptc_replace_entry(c, e, n, h) == 0)
        iptables_error(errno ? iptc_strerror(errno) : "version mismatch");

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_append_entry(value ml_handle, value ml_chain, value ml_entry)
{
    CAMLparam3(ml_chain, ml_entry, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    struct ipt_entry *e = (struct ipt_entry *)Data_custom_val(ml_entry);

    if (iptc_append_entry(c, e, h) == 0)
        iptables_error(errno ? iptc_strerror(errno) : "version mismatch");

    CAMLreturn(Val_unit);
}

#define MASKSIZE                                                         \
    (XT_ALIGN(sizeof(struct ipt_entry)) +                                \
     XT_ALIGN(sizeof(struct ipt_entry_match) + sizeof(struct ipt_udp)) + \
     XT_ALIGN(sizeof(struct ipt_entry_target)))

CAMLprim value
caml_iptables_check_entry(value ml_handle, value ml_chain, value ml_entry)
{
    CAMLparam3(ml_chain, ml_entry, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    struct ipt_entry *e = (struct ipt_entry *)Data_custom_val(ml_entry);
    unsigned char m[MASKSIZE];

    memset(m, 0xff, MASKSIZE);

    CAMLreturn(Bool_val(iptc_check_entry(c, e, m, h)));
}

/* From perl-iptables-libiptd */
unsigned char *
gen_delmask(struct ipt_entry *entry)
{
    unsigned int size;
    struct ipt_entry_match *match;
    struct ipt_entry_target *target;
    unsigned char *mask, *mptr;

    size = entry->next_offset;

    /* Setup the actual mask data field */
    mask = calloc(1, size);
    if (mask == NULL)
        return NULL;

    memset(mask, 0xFF, sizeof(struct ipt_entry));
    mptr = mask + sizeof(struct ipt_entry);

    for (match = (void *)entry->elems;
         (void *)match < (void *)entry + entry->target_offset;
         match = (void *)match + match->u.match_size)
    {
        size = XT_ALIGN(sizeof(struct ipt_entry_match));
        if (match->u.match_size > XT_ALIGN(sizeof(struct ipt_entry_match)))
            size = match->u.match_size;
        memset(mptr, 0xFF, size);
        mptr += match->u.match_size;
    }

    if (entry->target_offset < entry->next_offset) {
        target = (void *)entry + entry->target_offset;
        size = XT_ALIGN(sizeof(struct ipt_entry_target));
        if (target->u.target_size > XT_ALIGN(sizeof(struct ipt_entry_target)))
            size = target->u.target_size;
        memset(mptr, 0xFF, size);
    }

    return mask;
}

CAMLprim value
caml_iptables_delete_entry(value ml_handle, value ml_chain, value ml_entry)
{
    CAMLparam3(ml_chain, ml_entry, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    struct ipt_entry *e = (struct ipt_entry *)Data_custom_val(ml_entry);
    unsigned char *m = gen_delmask(e);

    if (iptc_delete_entry(c, e, m, h) == 0)
        iptables_error(errno ? iptc_strerror(errno) : "version mismatch");

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_delete_num_entry(value ml_handle, value ml_chain, value ml_num)
{
    CAMLparam3(ml_chain, ml_num, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    unsigned int n = Int_val(ml_num);

    if (iptc_delete_num_entry(c, n, h) == 0)
        iptables_error(errno ? iptc_strerror(errno) : "version mismatch");

    CAMLreturn(Val_unit);
}

//CAMLprim value
//caml_iptables_check_packet(value ml_handle, value ml_chain, value ml_entry)
//{
//    CAMLparam3(ml_chain, ml_entry, ml_handle);
//    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
//    char *c = String_val(ml_chain);
//    struct ipt_entry *e = (struct ipt_entry *)Data_custom_val(ml_entry);
//    const char *verdict;
//
//    verdict = iptc_check_packet(c, e, h);
//
//    if (verdict == NULL)
//        iptables_error(iptc_strerror(errno));
//
//    CAMLreturn(caml_copy_string(verdict));
//}

CAMLprim value
caml_iptables_flush_entries(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);

    if (iptc_flush_entries(c, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_zero_entries(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);

    if (iptc_zero_entries(c, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_create_chain(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);

    if (iptc_create_chain(c, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_delete_chain(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);

    if (iptc_delete_chain(c, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_rename_chain(value ml_handle, value ml_oldname, value ml_newname)
{
    CAMLparam3(ml_oldname, ml_newname, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *o = String_val(ml_oldname);
    char *n = String_val(ml_newname);

    if (iptc_rename_chain(o, n, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_set_policy(value ml_handle, value ml_chain, value ml_policy)
{
    CAMLparam3(ml_chain, ml_policy, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    char *p = String_val(ml_policy);

    if (iptc_set_policy(c, p, NULL, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_set_policy_and_counters(value ml_handle, value ml_chain,
                                      value ml_policy, value ml_counters)
{
    CAMLparam3(ml_chain, ml_policy, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    char *p = String_val(ml_policy);
    struct ipt_counters ic;

    Counters_val(&ic, ml_counters);

    if (iptc_set_policy(c, p, &ic, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_get_references(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    unsigned int ref;

    if (iptc_get_references(&ref, c, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_int(ref));
}

CAMLprim value
caml_iptables_read_counter(value ml_handle, value ml_chain, value ml_num)
{
    CAMLparam3(ml_chain, ml_num, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    unsigned int n = Int_val(ml_num);
    struct ipt_counters *icp;

    icp = iptc_read_counter(c, n, h);
    if (icp == NULL)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_counters(icp));
}

CAMLprim value
caml_iptables_zero_counter(value ml_handle, value ml_chain, value ml_num)
{
    CAMLparam3(ml_chain, ml_num, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    unsigned int n = Int_val(ml_num);

    if (iptc_zero_counter(c, n, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_set_counter(value ml_handle, value ml_chain, value ml_num,
                          value ml_counters)
{
    CAMLparam4(ml_chain, ml_num, ml_counters, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    unsigned int n = Int_val(ml_num);
    struct ipt_counters ic;

    Counters_val(&ic, ml_counters);

    if (iptc_set_counter(c, n, &ic, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_commit(value ml_handle)
{
    CAMLparam1(ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;

    if (iptc_commit(h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_dump_entries(value ml_handle)
{
    CAMLparam1(ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    dump_entries(h);
    CAMLreturn(Val_unit);
}

static uint16_t
protocol(value ml_proto)
{
    return xtables_parse_protocol(String_val(ml_proto));
}

static int
ipt_service_to_port(const char *name)
{
    struct servent *s;

    if ((s = getservbyname(name, "tcp")) != NULL)
        return ntohs((unsigned short)s->s_port);

    return -1;
}

static u_int16_t
ipt_parse_port(const char *port)
{
    unsigned int portnum;

    if ((portnum = ipt_service_to_port(port)) != -1)
        return (u_int16_t)portnum;
    else
        return atoi(port);
}

static void
parse_ports(const char *portstring, u_int16_t *ports)
{
    char *buffer;
    char *cp;

    buffer = strdup(portstring);
    if ((cp = strchr(buffer, ':')) == NULL) {
        ports[0] = ports[1] = ipt_parse_port(buffer);
    } else {
        *cp = '\0';
        cp++;

        ports[0] = buffer[0] ? ipt_parse_port(buffer) : 0;
        ports[1] = cp[0] ? ipt_parse_port(cp) : 0xFFFF;
    }
    free(buffer);
}

struct ipt_entry_match *
get_tcp_match(const char *sports, const char *dports, unsigned int *nfcache)
{
    struct ipt_entry_match *match;
    struct ipt_tcp *tcpinfo;
    size_t size;

    size = XT_ALIGN(sizeof(*match)) + XT_ALIGN(sizeof(*tcpinfo));
    match = calloc(1, size);
    match->u.match_size = size;
    strncpy(match->u.user.name, "tcp", IPT_FUNCTION_MAXNAMELEN);

    tcpinfo = (struct ipt_tcp *)match->data;
    tcpinfo->spts[1] = tcpinfo->dpts[1] = 0xFFFF;

    if (sports) {
        *nfcache |= NFC_IP_SRC_PT;
        parse_ports(sports, tcpinfo->spts);
    }
    if (dports) {
        *nfcache |= NFC_IP_DST_PT;
        parse_ports(dports, tcpinfo->dpts);
    }

    return match;
}

struct ipt_entry_match *
get_udp_match(const char *sports, const char *dports, unsigned int *nfcache)
{
    struct ipt_entry_match *match;
    struct ipt_udp *udpinfo;
    size_t size;

    size = XT_ALIGN(sizeof(*match)) + XT_ALIGN(sizeof(*udpinfo));
    match = calloc(1, size);
    match->u.match_size = size;
    strncpy(match->u.user.name, "udp", IPT_FUNCTION_MAXNAMELEN);

    udpinfo = (struct ipt_udp *)match->data;
    udpinfo->spts[1] = udpinfo->dpts[1] = 0xFFFF;

    if (sports) {
        *nfcache |= NFC_IP_SRC_PT;
        parse_ports(sports, udpinfo->spts);
    }
    if (dports) {
        *nfcache |= NFC_IP_DST_PT;
        parse_ports(dports, udpinfo->dpts);
    }

    return match;
}

static int
valid_target(char *target)
{
    return (strcmp(target, IPTC_LABEL_ACCEPT) == 0
         || strcmp(target, IPTC_LABEL_DROP)   == 0
         || strcmp(target, IPTC_LABEL_QUEUE)  == 0
         || strcmp(target, IPTC_LABEL_RETURN) == 0);
}

CAMLprim value
caml_iptables_create_rule(value ml_src, value ml_src_mask, value ml_src_ports,
                          value ml_dst, value ml_dst_mask, value ml_dst_ports,
                          value ml_iniface, value ml_outiface, value ml_proto,
                          value ml_target)
{
    CAMLparam3(ml_src, ml_src_mask, ml_src_ports);
    CAMLxparam3(ml_dst, ml_dst_mask, ml_dst_ports);
    CAMLxparam4(ml_iniface, ml_outiface, ml_proto, ml_target);
    CAMLlocal1(ml_entry);
    struct ipt_entry *entry;
    struct ipt_entry_match *entry_match;
    struct ipt_entry_target *entry_target;
    char *target;
    size_t target_size;
    long match_size;
    uint16_t next_offset;

    entry = calloc(1, sizeof(*entry));
    if (entry == NULL)
        iptables_error("cannot allocate memory for rule");

    if (ml_src != Val_none) {
        entry->ip.src.s_addr = Inet_addr_val(Some_val(ml_src));
        if (ml_src_mask != Val_none)
            entry->ip.smsk.s_addr = Inet_addr_val(Some_val(ml_src_mask));
        else
            entry->ip.smsk.s_addr = inet_addr("255.255.255.255");
    }

    if (ml_dst != Val_none) {
        entry->ip.dst.s_addr = Inet_addr_val(Some_val(ml_dst));
        if (ml_dst_mask != Val_none)
            entry->ip.dmsk.s_addr = Inet_addr_val(Some_val(ml_dst_mask));
        else
            entry->ip.dmsk.s_addr = inet_addr("255.255.255.255");
    }

    if (ml_iniface != Val_none) {
        char *iface = String_val(Some_val(ml_iniface));
        strncpy(entry->ip.iniface, iface, IFNAMSIZ);
    }
    if (ml_outiface != Val_none) {
        char *iface = String_val(Some_val(ml_outiface));
        strncpy(entry->ip.outiface, iface, IFNAMSIZ);
    }

    if (ml_proto != Val_none) {
        entry->ip.proto = protocol(Some_val(ml_proto));
        switch (entry->ip.proto) {
        case IPPROTO_TCP: {
            char *sps =
                ml_src_ports == Val_none
                    ? NULL
                    : String_val(Some_val(ml_src_ports));
            char *dps =
                ml_dst_ports == Val_none
                    ? NULL
                    : String_val(Some_val(ml_dst_ports));
            entry_match = get_tcp_match(sps, dps, &entry->nfcache);
            break;
        }
        case IPPROTO_UDP: {
            char *sps =
                ml_src_ports == Val_none
                    ? NULL
                    : String_val(Some_val(ml_src_ports));
            char *dps =
                ml_dst_ports == Val_none
                    ? NULL
                    : String_val(Some_val(ml_dst_ports));
            entry_match = get_udp_match(sps, dps, &entry->nfcache);
            break;
        }
        default:
            iptables_error("unsupported protocol");
        }
    } else {
        entry_match = NULL;
    }

    target = String_val(ml_target);
    if (!valid_target(target))
        iptables_error("invalid rule target");

    target_size = XT_ALIGN(sizeof(struct ipt_entry_target))
                + XT_ALIGN(sizeof(int));
    entry_target = calloc(1, target_size);
    entry_target->u.user.target_size = target_size;
    strncpy(entry_target->u.user.name, target,
            sizeof(entry_target->u.user.name) - 1);

    if (entry_match)
        match_size = entry_match->u.match_size;
    else
        match_size = 0;

    next_offset = sizeof(*entry) + match_size + entry_target->u.target_size;

    entry = realloc(entry, next_offset);
    if (entry_match)
        memcpy(entry->elems, entry_match, match_size);
    memcpy(entry->elems + match_size, entry_target,
           entry_target->u.target_size);
    entry->target_offset = sizeof(*entry) + match_size;
    entry->next_offset = next_offset;

    ml_entry = caml_alloc_custom(&iptables_entry_ops, next_offset, 0, 1);
    memcpy(Data_custom_val(ml_entry), entry, next_offset);

    free(entry_match);
    free(entry_target);
    free(entry);

    CAMLreturn(ml_entry);
}

CAMLprim value
caml_iptables_create_rule_byte(value * argv, int argc)
{
    return caml_iptables_create_rule(argv[0], argv[1], argv[2], argv[3],
                                     argv[4], argv[5], argv[6], argv[7],
                                     argv[8], argv[9]);
}
