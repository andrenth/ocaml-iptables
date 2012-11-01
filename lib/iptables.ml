type t
type entry

type counters =
  { pcnt : Uint64.t
  ; bcnt : Uint64.t
  }

exception Iptables_error of string

let _ =
  Callback.register_exception "Iptables.Iptables_error" (Iptables_error "")

external init : string -> t = "caml_iptables_init"
external free : t -> unit = "caml_iptables_free"
external is_chain : t -> string -> bool = "caml_iptables_is_chain"
external first_chain : t -> string option = "caml_iptables_first_chain"
external next_chain : t -> string option = "caml_iptables_next_chain"
external first_rule : t -> string -> entry option = "caml_iptables_first_rule"
external next_rule : t -> entry -> entry option = "caml_iptables_next_rule"
external get_target : t -> entry -> string = "caml_iptables_get_target"
external is_builtin : t -> string -> bool = "caml_iptables_builtin"
external get_policy : t -> string -> string option = "caml_iptables_get_policy"
external get_policy_and_counters : t -> string -> (string * counters) option
  = "caml_iptables_get_policy_and_counters"

external insert_entry : t -> string -> entry -> int -> unit
  = "caml_iptables_insert_entry"
external replace_entry : t -> string -> entry -> int -> unit
  = "caml_iptables_replace_entry"
external append_entry : t -> string -> entry -> unit
  = "caml_iptables_append_entry"
external check_entry : t -> string -> entry -> bool
  = "caml_iptables_check_entry"
external delete_entry : t -> string -> entry -> unit
  = "caml_iptables_delete_entry"
external delete_entry_by_number : t -> string -> int -> unit
  = "caml_iptables_delete_num_entry"
external flush_entries : t -> string -> unit
  = "caml_iptables_flush_entries"
external zero_entries : t -> string -> unit
  = "caml_iptables_zero_entries"
external create_chain : t -> string -> unit
  = "caml_iptables_create_chain"
external rename_chain : t -> string -> string -> unit
  = "caml_iptables_rename_chain"
external set_policy : t -> string -> string -> unit
  = "caml_iptables_set_policy"
external set_policy_and_counters : t -> string -> string -> counters -> unit
  = "caml_iptables_set_policy_and_counters"
external get_references : t -> string -> int
  = "caml_iptables_get_references"

external read_counters : t -> string -> int -> counters
  = "caml_iptables_read_counter"
external zero_counters : t -> string -> int -> unit
  = "caml_iptables_zero_counter"
external set_counters : t -> string -> int -> counters -> unit
  = "caml_iptables_set_counter"

external commit : t -> unit = "caml_iptables_commit"

external dump_entries : t -> unit = "caml_iptables_dump_entries"

let iter_chains ipt f =
  match first_chain ipt with
  | None ->
      ()
  | Some c ->
      let rec iter c =
        f c;
        match next_chain ipt with
        | None -> ()
        | Some c -> iter c in
      iter c

let iter_rules ipt chain f =
  match first_rule ipt chain with
  | None ->
      ()
  | Some e ->
      let rec iter e =
        f e;
        match next_rule ipt e with
        | None -> ()
        | Some next -> iter next in
      iter e

external create_rule_stub :
     Unix.inet_addr option -> Unix.inet_addr option -> string option
  -> Unix.inet_addr option -> Unix.inet_addr option -> string option
  -> string option -> string option -> string option -> string -> entry
  = "caml_iptables_create_rule_byte" "caml_iptables_create_rule"

let rule ?src ?src_mask ?src_port ?dst ?dst_mask ?dst_port
         ?in_iface ?out_iface ?proto ~target () =
  create_rule_stub
    src src_mask src_port
    dst dst_mask dst_port
    in_iface out_iface
    proto
    target

let with_chain chain f =
  let ipt = init chain in
  try
    f ipt;
    commit ipt;
    free ipt
  with e ->
    free ipt;
    raise e
