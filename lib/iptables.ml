type handle
type entry
type counters
type chain_label

exception Iptables_error of string

let _ =
  Callback.register_exception "Iptables.Iptables_error" (Iptables_error "")

external init : string -> handle = "caml_iptables_init"
external is_chain : string -> handle -> bool = "caml_iptables_is_chain"
external first_chain : handle -> string = "caml_iptables_first_chain"
external next_chain : handle -> string = "caml_iptables_next_chain"
external first_rule : string -> handle -> entry = "caml_iptables_first_rule"
external next_rule : string -> handle -> entry = "caml_iptables_next_rule"
external get_target : entry -> handle -> string = "caml_iptables_get_target"
external is_builtin : string -> handle -> bool = "caml_iptables_builtin"
external get_policy : string -> handle -> string = "caml_iptables_get_policy"

external insert_entry : string -> entry -> int -> handle -> unit
  = "caml_iptables_insert_entry"
external replace_entry : string -> entry -> int -> handle -> unit
  = "caml_iptables_replace_entry"
external append_entry : string -> entry -> handle -> unit
  = "caml_iptables_append_entry"
external check_entry : string -> entry -> handle -> bool
  = "caml_iptables_check_entry"
external delete_entry : string -> entry -> handle -> unit
  = "caml_iptables_delete_entry"
external delete_entry_by_number : string -> int -> handle -> unit
  = "caml_iptables_delete_num_entry"
external check_packet : string -> entry -> handle -> string
  = "caml_iptables_check_packet"
external flush_entries : string -> handle -> unit
  = "caml_iptables_flush_entries"
external zero_entries : string -> handle -> unit
  = "caml_iptables_zero_entries"
external create_chain : string -> handle -> unit
  = "caml_iptables_create_chain"
external rename_chain : string -> string -> handle -> unit
  = "caml_iptables_rename_chain"
external set_policy : string -> string -> handle -> unit
  = "caml_iptables_set_policy"
external get_references : string -> handle -> int
  = "caml_iptables_get_references"

external read_counters : string -> int -> handle -> counters
  = "caml_iptables_read_counter"
external zero_counters : string -> int -> handle -> unit
  = "caml_iptables_zero_counter"
external set_counter : string -> int -> counters -> handle
  = "caml_iptables_set_counter"

external commit : handle -> unit = "caml_iptables_commit"

external raw_socket : unit -> Unix.file_descr = "caml_iptables_get_raw_socket"

external dump_entries : handle -> unit = "caml_iptables_dump_entries"
