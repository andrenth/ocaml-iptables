#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <libiptc/libiptc.h>
#include <libiptc/libxtc.h>

#include <caml/bigarray.h>
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/signals.h>

#define Val_none Val_int(0)
#define GET_INET_ADDR(v) (*((struct in_addr *) (v)))

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

#if 0
static value
alloc_ip(const void *addr, size_t len)
{
    CAMLparam0();
    CAMLlocal1(res);

    res = caml_alloc_string(len);
    memcpy(String_val(res), addr, len);

    CAMLreturn(res);
}

static CAMLprim value
Val_entry(const struct ipt_entry *iep)
{
    CAMLparam0();
    CAMLlocal4(ip, counters, elems, entry);
    intnat dims[] = { iep->next_offset - sizeof(struct ipt_entry) };
    unsigned char *elemsp = iep->elems;

    Store_field(ip, 0,  alloc_ip(&iep->ip.src, 4));
    Store_field(ip, 1,  alloc_ip(&iep->ip.dst, 4));
    Store_field(ip, 2,  alloc_ip(&iep->ip.smsk, 4));
    Store_field(ip, 3,  alloc_ip(&iep->ip.dmsk, 4));
    Store_field(ip, 4,  caml_copy_string(iep->ip.iniface));
    Store_field(ip, 5,  caml_copy_string(iep->ip.outiface));
    Store_field(ip, 6,  caml_copy_string(iep->ip.iniface_mask));
    Store_field(ip, 7,  caml_copy_string(iep->ip.outiface_mask));
    Store_field(ip, 8,  Val_int(iep->ip.proto));
    Store_field(ip, 9,  Val_int(iep->ip.flags));
    Store_field(ip, 10, Val_int(iep->ip.invflags));

    Store_field(counters, 0, caml_copy_int64((int64)iep->counters.pcnt));
    Store_field(counters, 1, caml_copy_int64((int64)iep->counters.bcnt));

    elems = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, elemsp, dims);

    Store_field(entry, 0, ip);
    Store_field(entry, 1, Val_int(iep->nfcache));
    Store_field(entry, 2, Val_int(iep->target_offset));
    Store_field(entry, 3, Val_int(iep->next_offset));
    Store_field(entry, 4, Val_int(iep->comefrom));
    Store_field(entry, 5, counters);
    Store_field(entry, 6, elems);

    CAMLreturn(entry);
}
#endif

#if 0
static void
Entry_val(struct ipt_entry *iep, value ml_entry)
{
    CAMLparam1(ml_entry);
    CAMLlocal3(ip, counters, elems);
    unsigned char *elemsp;

    ip = Field(ml_entry, 0);
    counters = Field(ml_entry, 5);
    elems = Field(ml_entry, 6);

    iep->ip.src = GET_INET_ADDR(Field(ip, 0));
    iep->ip.dst = GET_INET_ADDR(Field(ip, 1));
    iep->ip.smsk = GET_INET_ADDR(Field(ip, 2));
    iep->ip.dmsk = GET_INET_ADDR(Field(ip, 3));
    memcpy(iep->ip.iniface, String_val(Field(ip, 4)), IFNAMSIZ);
    memcpy(iep->ip.outiface, String_val(Field(ip, 5)), IFNAMSIZ);
    memcpy(iep->ip.iniface_mask, String_val(Field(ip, 6)), IFNAMSIZ);
    memcpy(iep->ip.outiface_mask, String_val(Field(ip, 7)), IFNAMSIZ);
    iep->ip.proto = Int_val(Field(ip, 8));
    iep->ip.flags = Int_val(Field(ip, 8));
    iep->ip.invflags = Int_val(Field(ip, 10));

    iep->nfcache = (unsigned int)Field(ml_entry, 1);
    iep->target_offset = (uint16_t)Field(ml_entry, 2);
    iep->next_offset = (uint16_t)Field(ml_entry, 3);
    iep->comefrom = (unsigned int)Field(ml_entry, 4);

    iep->counters.pcnt = (uint64_t)Int64_val(Field(counters, 0));
    iep->counters.bcnt = (uint64_t)Int64_val(Field(counters, 1));

    /* TODO iep->elems */

    CAMLreturn0;
}
#endif

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
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *chain = String_val(ml_chain);
    const struct ipt_entry *entry = iptc_first_rule(chain, h);
    CAMLreturn(entry != NULL ? Val_some((value)entry) : Val_none);
}

CAMLprim value
caml_iptables_next_rule(value ml_handle, value ml_prev)
{
    CAMLparam2(ml_prev, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    struct ipt_entry *prev = (struct ipt_entry *)prev;
    const struct ipt_entry *entry = iptc_next_rule(prev, h);
    CAMLreturn(entry != NULL ? Val_some((value)entry) : Val_none);
}

CAMLprim value
caml_iptables_get_target(value ml_handle, value ml_entry)
{
    CAMLparam2(ml_entry, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    struct ipt_entry *e = (struct ipt_entry *)ml_entry;

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
    struct ipt_entry *e = (struct ipt_entry *)ml_entry;

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
    struct ipt_entry *e = (struct ipt_entry *)ml_entry;
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
    struct ipt_entry *e = (struct ipt_entry *)ml_entry;

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
    struct ipt_entry *e = (struct ipt_entry *)ml_entry;
    unsigned char m[MASKSIZE];

    memset(m, 0xff, MASKSIZE);

    CAMLreturn(Bool_val(iptc_check_entry(c, e, m, h)));
}

CAMLprim value
caml_iptables_delete_entry(value ml_handle, value ml_chain, value ml_entry)
{
    CAMLparam3(ml_chain, ml_entry, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    char *c = String_val(ml_chain);
    struct ipt_entry *e = (struct ipt_entry *)ml_entry;
    unsigned char m[MASKSIZE];

    memset(m, 0xff, MASKSIZE);

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
//    struct ipt_entry *e = (struct ipt_entry *)ml_entry;
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

//CAMLprim value
//caml_iptables_get_raw_socket()
//{
//    CAMLparam0();
//    int fd = iptc_get_raw_socket();
//
//    if (fd == -1)
//        iptables_error(iptc_strerror(errno));
//
//    CAMLreturn(Val_int(fd));
//}

CAMLprim value
caml_iptables_dump_entries(value ml_handle)
{
    CAMLparam1(ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)ml_handle;
    dump_entries(h);
    CAMLreturn(Val_unit);
}
