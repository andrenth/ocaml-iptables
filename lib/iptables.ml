type t
type entry
type counters
type chain_label

exception Iptables_error of string

let _ =
  Callback.register_exception "Iptables.Iptables_error" (Iptables_error "")

external init : t -> string = "caml_iptables_init"
external is_chain : t -> string -> bool = "caml_iptables_is_chain"
external first_chain : t -> string = "caml_iptables_first_chain"
external next_chain : t -> string = "caml_iptables_next_chain"
external first_rule : t -> string -> entry = "caml_iptables_first_rule"
external next_rule : t -> string -> entry = "caml_iptables_next_rule"
external get_target : t -> entry -> string = "caml_iptables_get_target"
external is_builtin : t -> string -> bool = "caml_iptables_builtin"
external get_policy : t -> string -> string = "caml_iptables_get_policy"

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
external check_packet : t -> string -> entry -> string
  = "caml_iptables_check_packet"
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
external get_references : t -> string -> int
  = "caml_iptables_get_references"

external read_counters : t -> string -> int -> counters
  = "caml_iptables_read_counter"
external zero_counters : t -> string -> int -> unit
  = "caml_iptables_zero_counter"
external set_counter : t -> string -> int -> counters
  = "caml_iptables_set_counter"

external commit : t -> unit = "caml_iptables_commit"

external raw_socket : unit -> Unix.file_descr = "caml_iptables_get_raw_socket"

external dump_entries : t -> unit = "caml_iptables_dump_entries"
