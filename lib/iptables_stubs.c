#include <errno.h>
#include <string.h>

#include <libiptc/libiptc.h>
#include <libiptc/libxtc.h>

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/signals.h>

#define Val_none Val_int(0)

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

CAMLprim value
caml_iptables_is_chain(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    char *c = String_val(ml_chain);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);

    CAMLreturn(Bool_val(iptc_is_chain(c, h)));
}

static void
finalize_iptables(value ml_handle)
{
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    iptc_free(h);
}

static struct custom_operations iptables_ops = {
    "iptc_handle custom ops",
    finalize_iptables,
    custom_compare_default,
    custom_hash_default,
    custom_serialize_default,
    custom_deserialize_default,
};

CAMLprim value
caml_iptables_init(value ml_tablename)
{
    CAMLparam1(ml_tablename);
    CAMLlocal1(ml_handle);
    char *t = String_val(ml_tablename);
    struct iptc_handle *h = iptc_init(t);

    if (h == NULL)
        iptables_error(iptc_strerror(errno));

    ml_handle = caml_alloc_custom(&iptables_ops, sizeof(struct iptc_handle *),
                                  0, 1);
    memcpy(Data_custom_val(ml_handle), h, sizeof(struct iptc_handle *));

    CAMLreturn(ml_handle);
}

CAMLprim value
caml_iptables_first_chain(value ml_handle)
{
    CAMLparam1(ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    const char *chain = iptc_first_chain(h);

    CAMLreturn(chain != NULL ? Val_some(caml_copy_string(chain)) : Val_none);
}

CAMLprim value
caml_iptables_next_chain(value ml_handle)
{
    CAMLparam1(ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    const char *chain = iptc_next_chain(h);

    CAMLreturn(chain != NULL ? Val_some(caml_copy_string(chain)) : Val_none);
}

CAMLprim value
caml_iptables_first_rule(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *chain = String_val(ml_chain);
    const struct ipt_entry *entry = iptc_first_rule(chain, h);
    CAMLreturn(entry != NULL ? Val_some((value)entry) : Val_none);
}

CAMLprim value
caml_iptables_next_rule(value ml_handle, value ml_prev)
{
    CAMLparam2(ml_prev, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    struct ipt_entry *prev = (struct ipt_entry *)prev;
    const struct ipt_entry *entry = iptc_next_rule(prev, h);
    CAMLreturn(entry != NULL ? Val_some((value)entry) : Val_none);
}

CAMLprim value
caml_iptables_get_target(value ml_handle, value ml_entry)
{
    CAMLparam2(ml_entry, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    struct ipt_entry *e = (struct ipt_entry *)ml_entry;
    CAMLreturn(caml_copy_string(iptc_get_target(e, h)));
}

CAMLprim value
caml_iptables_builtin(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);
    CAMLreturn(Bool_val(iptc_builtin(c, h)));
}

CAMLprim value
caml_iptables_get_policy(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);
    const char *policy;
    struct ipt_counters ic;

    policy = iptc_get_policy(c, &ic, h);

    CAMLreturn(policy != NULL ? Val_some(caml_copy_string(policy)) : Val_none);
}

CAMLprim value
caml_iptables_insert_entry(value ml_handle, value ml_chain, value ml_entry,
                           value ml_num)
{
    CAMLparam4(ml_chain, ml_entry, ml_num, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
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
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
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
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);
    struct ipt_entry *e = (struct ipt_entry *)ml_entry;

    if (iptc_append_entry(c, e, h) == 0)
        iptables_error(errno ? iptc_strerror(errno) : "version mismatch");

    CAMLreturn(Val_unit);
}

#define MASKSIZE \
    (XT_ALIGN(sizeof(struct ipt_entry)) +                                \
     XT_ALIGN(sizeof(struct ipt_entry_match) + sizeof(struct ipt_udp)) + \
     XT_ALIGN(sizeof(struct ipt_entry_target)))

CAMLprim value
caml_iptables_check_entry(value ml_handle, value ml_chain, value ml_origfw)
{
    CAMLparam3(ml_chain, ml_origfw, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);
    struct ipt_entry *o = (struct ipt_entry *)ml_origfw;
    unsigned char m[MASKSIZE];

    memset(m, 0xff, MASKSIZE);

    CAMLreturn(Bool_val(iptc_check_entry(c, o, m, h)));
}

CAMLprim value
caml_iptables_delete_entry(value ml_handle, value ml_chain, value ml_origfw)
{
    CAMLparam3(ml_chain, ml_origfw, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);
    struct ipt_entry *o = (struct ipt_entry *)ml_origfw;
    unsigned char m[MASKSIZE];

    memset(m, 0xff, MASKSIZE);
    if (iptc_delete_entry(c, o, m, h) == 0)
        iptables_error(errno ? iptc_strerror(errno) : "version mismatch");

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_delete_num_entry(value ml_handle, value ml_chain, value ml_num)
{
    CAMLparam3(ml_chain, ml_num, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);
    unsigned int n = Int_val(ml_num);

    if (iptc_delete_num_entry(c, n, h) == 0)
        iptables_error(errno ? iptc_strerror(errno) : "version mismatch");

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_check_packet(value ml_handle, value ml_chain, value ml_entry)
{
    CAMLparam3(ml_chain, ml_entry, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);
    struct ipt_entry *e = (struct ipt_entry *)ml_entry;
    const char *verdict = iptc_check_packet(c, e, h);

    if (verdict == NULL)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(caml_copy_string(verdict));
}

CAMLprim value
caml_iptables_flush_entries(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);

    if (iptc_flush_entries(c, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_zero_entries(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);

    if (iptc_zero_entries(c, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_create_chain(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);

    if (iptc_create_chain(c, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_delete_chain(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);

    if (iptc_delete_chain(c, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_rename_chain(value ml_handle, value ml_oldname, value ml_newname)
{
    CAMLparam3(ml_oldname, ml_newname, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
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
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);
    char *p = String_val(ml_policy);
    struct ipt_counters ic;

    if (iptc_set_policy(c, p, &ic, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_get_references(value ml_handle, value ml_chain)
{
    CAMLparam2(ml_chain, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
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
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);
    unsigned int n = Int_val(ml_num);
    struct ipt_counters *icp;

    icp = iptc_read_counter(c, n, h);
    if (icp == NULL)
        iptables_error(iptc_strerror(errno));

    CAMLreturn((value)icp);
}

CAMLprim value
caml_iptables_zero_counter(value ml_handle, value ml_chain, value ml_num)
{
    CAMLparam3(ml_chain, ml_num, ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
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
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    char *c = String_val(ml_chain);
    unsigned int n = Int_val(ml_num);
    struct ipt_counters *icp = (struct ipt_counters *)ml_counters;

    if (iptc_set_counter(c, n, icp, h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_commit(value ml_handle)
{
    CAMLparam1(ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);

    if (iptc_commit(h) == 0)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_unit);
}

CAMLprim value
caml_iptables_get_raw_socket()
{
    CAMLparam0();
    int fd = iptc_get_raw_socket();

    if (fd == -1)
        iptables_error(iptc_strerror(errno));

    CAMLreturn(Val_int(fd));
}

CAMLprim value
caml_iptables_dump_entries(value ml_handle)
{
    CAMLparam1(ml_handle);
    struct iptc_handle *h = (struct iptc_handle *)Data_custom_val(ml_handle);
    dump_entries(h);
    CAMLreturn(Val_unit);
}
