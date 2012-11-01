open Printf

let iter_chains ipt =
  Iptables.iter_chains ipt
    (fun chain ->
      printf "got chain: %s\n%!" chain;
      (match Iptables.get_policy_and_counters ipt chain with
      | None ->
          printf "  no policy\n%!"
      | Some (p, c) ->
          printf "  policy=%s pcnt=%s bcnt=%s\n%!"
            p
            (Uint64.to_string c.Iptables.pcnt)
            (Uint64.to_string c.Iptables.bcnt));
      Iptables.iter_rules ipt chain
        (fun r ->
          let t = Iptables.get_target ipt r in
          printf "  got entry: %s\n%!" t))

let main () =
  let entry =
    Iptables.rule
      ~src:(Unix.inet_addr_of_string "10.7.5.1")
      ~dst:(Unix.inet_addr_of_string "10.7.5.14")
      ~proto:"TCP"
      ~dst_port:"80"
      ~in_iface:"eth0"
      ~target:"ACCEPT"
      () in
  Iptables.with_chain "filter"
    (fun ipt ->
      Iptables.insert_entry ipt "INPUT" entry 0;
      iter_chains ipt;
      printf "===\n%!";
      Iptables.delete_entry ipt "INPUT" entry;
      iter_chains ipt)

let () =
  if Unix.getuid () <> 0 then begin
    fprintf stderr "please run this test as root\n%!";
    exit 1
  end;
  main ()
