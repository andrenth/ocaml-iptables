type t
type entry
type chain_label

type c_counters =
  { pcnt_hi : int64
  ; pcnt_lo : int64
  ; bcnt_hi : int64
  ; bcnt_lo : int64
  }

type counters =
  { pcnt : Uint64.t
  ; bcnt : Uint64.t
  }

let build_ml_counters c =
  let pcnt_hi = Uint64.of_int64 c.pcnt_hi in
  let pcnt_lo = Uint64.of_int64 c.pcnt_lo in
  let bcnt_hi = Uint64.of_int64 c.bcnt_hi in
  let bcnt_lo = Uint64.of_int64 c.bcnt_lo in
  { pcnt = Uint64.add (Uint64.shift_left pcnt_hi 32) pcnt_lo
  ; bcnt = Uint64.add (Uint64.shift_left bcnt_hi 32) bcnt_lo
  }

let build_c_counters c =
  let pcnt_hi = Uint64.shift_right c.pcnt 32 in
  let pcnt_lo = Uint64.logand c.pcnt (Uint64.of_int32 (-1l)) in
  let bcnt_hi = Uint64.shift_right c.bcnt 32 in
  let bcnt_lo = Uint64.logand c.bcnt (Uint64.of_int32 (-1l)) in
  { pcnt_hi = Uint64.to_int64 pcnt_hi
  ; pcnt_lo = Uint64.to_int64 pcnt_lo
  ; bcnt_hi = Uint64.to_int64 bcnt_hi
  ; bcnt_lo = Uint64.to_int64 bcnt_lo
  }

exception Iptables_error of string

let _ =
  Callback.register_exception "Iptables.Iptables_error" (Iptables_error "")

external init : t -> string = "caml_iptables_init"
external is_chain : t -> string -> bool = "caml_iptables_is_chain"
external first_chain : t -> string option = "caml_iptables_first_chain"
external next_chain : t -> string option = "caml_iptables_next_chain"
external first_rule : t -> string -> entry option = "caml_iptables_first_rule"
external next_rule : t -> string -> entry option = "caml_iptables_next_rule"
external get_target : t -> entry -> string = "caml_iptables_get_target"
external is_builtin : t -> string -> bool = "caml_iptables_builtin"
external get_policy : t -> string -> string option = "caml_iptables_get_policy"
external ml_get_policy_and_counters :
  t -> string -> (string * c_counters) option
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
external ml_set_policy_and_counters :
  t -> string -> string -> c_counters -> unit
  = "caml_iptables_set_policy_and_counters"
external get_references : t -> string -> int
  = "caml_iptables_get_references"

external ml_read_counters : t -> string -> int -> c_counters
  = "caml_iptables_read_counter"
external zero_counters : t -> string -> int -> unit
  = "caml_iptables_zero_counter"
external ml_set_counters : t -> string -> int -> c_counters -> unit
  = "caml_iptables_set_counter"

external commit : t -> unit = "caml_iptables_commit"

external raw_socket : unit -> Unix.file_descr = "caml_iptables_get_raw_socket"

external dump_entries : t -> unit = "caml_iptables_dump_entries"

let get_policy_and_counters ipt chain =
  match ml_get_policy_and_counters ipt chain with
  | None -> None
  | Some (p, c) -> Some (p, build_ml_counters c)

let set_policy_and_counters ipt chain policy counters =
  ml_set_policy_and_counters ipt chain policy (build_c_counters counters)

let read_counters ipt chain num =
  build_ml_counters (ml_read_counters ipt chain num)

let set_counters ipt chain num counters =
  ml_set_counters ipt chain num (build_c_counters counters)
