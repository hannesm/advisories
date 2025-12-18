
let ( let* ) = Result.bind

let err_msg fmt =
  let kerr _ = Error (Format.flush_str_formatter ()) in
  Format.kfprintf kerr Format.str_formatter fmt

let guard p e = if p then Ok () else Error e

type reference_type =
  | Advisory (* A published security advisory for the vulnerability. *)
  | Article (* An article or blog post describing the vulnerability. *)
  | Detection (* A tool, script, scanner, or other mechanism that allows for detection of the vulnerability in production environments. e.g. YARA rules, hashes, virus signature, or other scanners. *)
  | Discussion (* A social media discussion regarding the vulnerability, e.g. a Twitter, Mastodon, Hacker News, or Reddit thread. *)
  | Report (* A report, typically on a bug or issue tracker, of the vulnerability. *)
  | Fix (* A source code browser link to the fix (e.g., a GitHub commit) Note that the fix type is meant for viewing by people using web browsers. Programs interested in analyzing the exact commit range would do better to use the GIT-typed affected[].ranges entries (described above). *)
  | Introduced (* A source code browser link to the introduction of the vulnerability (e.g., a GitHub commit) Note that the introduced type is meant for viewing by people using web browsers. Programs interested in analyzing the exact commit range would do better to use the GIT-typed affected[].ranges entries (described above). *)
  | Package (* A home web page for the package. *)
  | Evidence (* A demonstration of the validity of a vulnerability claim, e.g. app.any.run replaying the exploitation of the vulnerability. *)
  | Web (* A web page *)

let reference_type_of_string = function
  | "advisory" -> Ok Advisory
  | "article" -> Ok Article
  | "detection" -> Ok Detection
  | "discussion" -> Ok Discussion
  | "report" -> Ok Report
  | "fix" -> Ok Fix
  | "introduced" -> Ok Introduced
  | "package" -> Ok Package
  | "evidence" -> Ok Evidence
  | "web" -> Ok Web
  | x -> err_msg "unknown reference type %S" x

let reference_type_to_string = function
  | Advisory -> "advisory"
  | Article -> "article"
  | Detection -> "detection"
  | Discussion -> "discussion"
  | Report -> "report"
  | Fix -> "fix"
  | Introduced -> "introduced"
  | Package -> "package"
  | Evidence -> "evidence"
  | Web -> "web"

type reference = reference_type * string

type credit_type =
  | Finder (* identified the vulnerability. *)
  | Reporter (* notified the vendor of the vulnerability to a CNA. *)
  | Analyst (* validated the vulnerability to ensure accuracy or severity. *)
  | Coordinator (* facilitated the coordinated response process. *)
  | Remediation_developer (* prepared a code change or other remediation plans. *)
  | Remediation_reviewer (* reviewed vulnerability remediation plans or code changes for effectiveness and completeness. *)
  | Remediation_verifier (* tested and verified the vulnerability or its remediation. *)
  | Tool (* names of tools used in vulnerability discovery or identification. *)
  | Sponsor (* supported the vulnerability identification or remediation activities. *)
  | Other (* any other type or role that does not fall under the categories described above. *)

let credit_type_of_string = function
  | "finder" -> Ok Finder
  | "reporter" -> Ok Reporter
  | "analyst" -> Ok Analyst
  | "coordinator" -> Ok Coordinator
  | "remediation_developer" -> Ok Remediation_developer
  | "remediation_reviewer" -> Ok Remediation_reviewer
  | "remediation_verifier" -> Ok Remediation_verifier
  | "tool" -> Ok Tool
  | "sponsor" -> Ok Sponsor
  | "other" -> Ok Other
  | x -> err_msg "unkown credit type: %S" x

let credit_type_to_string = function
  | Finder -> "finder"
  | Reporter -> "reporter"
  | Analyst -> "analyst"
  | Coordinator -> "coordinator"
  | Remediation_developer -> "remediation_developer"
  | Remediation_reviewer -> "remediation_reviewer"
  | Remediation_verifier -> "remediation_verifier"
  | Tool -> "tool"
  | Sponsor -> "sponsor"
  | Other -> "other"

type credit = credit_type * string * string list

type event_type = Introduced | Fixed | Last_affected

let event_type_of_string = function
  | "introduced" -> Ok Introduced
  | "fixed" -> Ok Fixed
  | "last_affected" -> Ok Last_affected
  | x -> err_msg "unknown event type %S" x

let event_type_to_string = function
  | Introduced -> "introduced"
  | Fixed -> "fixed"
  | Last_affected -> "last_affected"

type event_range_type = Semver | Ecosystem | Git

let event_range_type_of_string = function
  | "semver" -> Ok Semver
  | "ecosystem" -> Ok Ecosystem
  | "git" -> Ok Git
  | x -> err_msg "unknown event range type %S" x

let event_range_type_to_string = function
  | Semver -> "semver"
  | Ecosystem -> "ecosystem"
  | Git -> "git"

type event = event_range_type * string * (event_type * string) list

let pp_event ppf (rt, repo, evs) =
  Fmt.pf ppf "%s %s %a" (event_range_type_to_string rt) repo
    Fmt.(list ~sep:(any ", ") (pair ~sep:(any ":") string string))
    (List.map (fun (et, e) -> event_type_to_string et, e) evs)

type severity_type = CVSS_V2 | CVSS_V3 | CVSS_V4

let severity_type_to_string = function
  | CVSS_V2 -> "CVSS_V2"
  | CVSS_V3 -> "CVSS_V3"
  | CVSS_V4 -> "CVSS_V4"

type header = {
  id : string ;
  modified : Ptime.t ;
  published : Ptime.t option ;
  withdrawn : Ptime.t option ;
  aliases : string list ;
  upstream : string list ;
  related : string list ;
  severity : (severity_type * string) option;
  severity_score : string option ;
  affected : string ;
  events : event list ;
  references : reference list ;
  credits : credit list ;
}
(* TODO schema_version, full affected, database_specific, multiple severity *)
let pp_header ppf { id ; modified ; published ; withdrawn ; aliases ; upstream ;
                    related ; severity ; severity_score ; affected ; events ;
                    references ; credits } =
  Fmt.pf ppf "  id: %S@." id;
  Fmt.pf ppf "  modified: %a@." (Ptime.pp_rfc3339 ()) modified;
  Fmt.pf ppf "  published: %a@." Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) published;
  Fmt.pf ppf "  withdrawn: %a@." Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) withdrawn;
  Fmt.pf ppf "  aliases: %a@." Fmt.(list ~sep:(any ", ") string) aliases;
  Fmt.pf ppf "  upstream: %a@." Fmt.(list ~sep:(any ", ") string) upstream;
  Fmt.pf ppf "  related: %a@." Fmt.(list ~sep:(any ", ") string) related;
  Fmt.pf ppf "  severity: %a@." Fmt.(option ~none:(any "no") (pair ~sep:(any ", ") string string))
    (Option.map (fun (t, s) -> severity_type_to_string t, s) severity);
  Fmt.pf ppf "  severity_score: %a@." Fmt.(option ~none:(any "no") string) severity_score;
  Fmt.pf ppf "  affected: %S@." affected;
  Fmt.pf ppf "  events: %a@." Fmt.(list ~sep:(any ", ") pp_event) events;
  Fmt.pf ppf "  references: %a@."
    Fmt.(list ~sep:(any ", ") (pair ~sep:(any ": ") string string))
    (List.map (fun (rt, r) -> reference_type_to_string rt, r) references);
  Fmt.pf ppf "  credits: %a@."
    Fmt.(list ~sep:(any ", ") (pair ~sep:(any ": ") string string))
    (List.map (fun (ct, c, _con) -> credit_type_to_string ct, c) credits)

type t = {
  header : header ;
  summary : string ;
  details : string ;
}

module SM = Map.Make(String)

let parse_date ~context data =
  Result.map_error (fun msg -> Fmt.str "couldn't parse %s: %s" context msg)
    (Result.map (fun (t, _tz_off, _count) -> t)
       (Ptime.rfc3339_string_error (Ptime.of_rfc3339 data)))

let parse_severity data =
  if String.starts_with ~prefix:"CVSS:4." data then
    Ok (CVSS_V4, data)
  else if String.starts_with ~prefix:"CVSS:3." data then
    Ok (CVSS_V3, data)
  else
    Ok (CVSS_V2, data)

(*let parse_affected data =
  we generate the "package - ecosystem: opam, name: pkg_name, purl: purl" from the data
  below, we also generate the ranges (introduced and fixed)
    introduced: the things behind the >= constraint
    fixed: the thing behind the < constraint
  and we produce the list of versions below (we just put in purl)

  for a given package p and a set of constraints (likely >= and < OR only <):
    if p = ocaml, run with p = ocaml-variants, p = ocaml-base-compiler, and p = ocaml-system, and p = ocaml-secondary-compiler
    for each constraint c:
      opam info '$p$c --all-versions -f version
    build up the union of the runs
    for each element u of the union:
      let purl = pkg://opam/p/u
*)
(*
let parse_events data =
  let* range_type, off = parse_id data in
  let* range_type = event_range_type_of_string range_type in
  let* repo, off = parse_id ~off data in
  print_endline ("here " ^ data);
  let* events, off = parse_list ~off data in
  let* () = guard (off = String.length data) ("trailing data in events") in
  let* events =
    Result.map List.rev
      (List.fold_left (fun acc data ->
           if String.trim data = "" then acc else
             let data = String.trim data in
           let* acc in
           let* event_type, off = parse_id data in
           print_endline ("event_type is " ^ event_type ^ " (data: " ^ data ^ ")");
           let* event_type = event_type_of_string event_type in
           Ok ((event_type, String.sub data off (String.length data - off)) :: acc))
          (Ok []) (String.split_on_char '\n' events))
  in
  Ok (range_type, repo, events)

let parse_reference data =
  (* expect a line of <typ> URL *)
  print_endline ("reference: " ^ data);
  let* reftype, ws_idx = parse_id data in
  let* reftype = reference_type_of_string reftype in
  let url = String.sub data ws_idx (String.length data - ws_idx) in
  Ok (reftype, url)

let parse_credit data =
  (* expected a line of <typ> "<name>" [ <contact> ] (optional) *)
  let* credit, ws_idx = parse_id data in
  let* credit = credit_type_of_string credit in
  let* name, rest_off = parse_quoted_string ~off:ws_idx data in
  match parse_list ~off:rest_off data with
  | Error _ -> Ok (credit, name, [])
  | Ok (contact, final_off) ->
    let* () =
      guard (final_off = String.length data) ("trailing data in credit " ^ data)
    in
    let contact = String.trim contact in
    let c_len = String.length contact in
    let rec decode_contact acc off =
      if off = c_len then
        Ok (List.rev acc)
      else
        let* d, off = parse_quoted_string ~off contact in
        decode_contact (d :: acc) off
    in
    let* contact = decode_contact [] 0 in
    Ok (credit, name, contact)
*)
let pp_pos line_offset ppf pos =
  let OpamParserTypes.FullPos.{ start ; stop ; filename } = pos in
  Fmt.pf ppf "in %s from %u,%u to %u,%u"
    filename (fst start + line_offset) (snd start)
    (fst stop + line_offset) (snd stop)

let parse_header ?(filename = "no filename provided") line_offset data =
  let* opamfile =
    try Ok (OpamParser.FullPos.string data filename)
    with Parsing.Parse_error -> Error "parse error"
  in
  let pp_pos = pp_pos line_offset in
  (* opamfile_item list (with source position) *)
  let* _map =
    List.fold_left (fun map v ->
        let open OpamParserTypes.FullPos in
        let* map in
        match v with
        | { pelem = Variable ({ pelem = name ; _ }, value) ; pos } ->
          (match SM.find_opt name map with
           | Some (pos', _) ->
             err_msg "an entry named %s already exists (previous definition %a, this definition %a)"
               name pp_pos pos' pp_pos pos
           | None ->
             print_endline ("added " ^ name);
             Ok (SM.add name (pos, value) map))
        | { pelem = Section { section_kind = { pelem = name ; _ } ; _ } ; pos } ->
          err_msg "unexpected section %s at %a" name pp_pos pos)
      (Ok SM.empty) opamfile.OpamParserTypes.FullPos.file_contents
  in
  Ok ()
(*
  let* id =
    let* id =
      Option.to_result ~none:"missing id"
        (SM.find_opt "id" fields)
    in
    match id with
    | `string id when valid_id id -> Ok id
    | `string id -> err_msg "invalid id %S" id
    | `list _ -> err_msg "expected a single string as id, got a list"
  in
  let* modified =
    let* ts =
      Option.to_result ~none:"missing modified"
        (SM.find_opt "modified" fields)
    in
    match ts with
    | `string ts -> parse_date ~context:"modified" ts
    | `list _ -> err_msg "expected a single string as modified, got a list"
  in
  let* published =
    match SM.find_opt "published" fields with
    | Some `string ts -> Result.map (fun ts -> Some ts) (parse_date ~context:"published" ts)
    | Some `list _ -> err_msg "expected a single string as published, got a list"
    | None -> Ok None
  in
  let* withdrawn =
    match SM.find_opt "withdrawn" fields with
    | Some `string ts -> Result.map (fun ts -> Some ts) (parse_date ~context:"withdrawn" ts)
    | Some `list _ -> err_msg "expected a single string as withdrawn, got a list"
    | None -> Ok None
  in
  let* aliases =
    match SM.find_opt "aliases" fields with
    | None -> Ok []
    | Some `string s -> parse_id_list s
    | Some `list xs -> parse_id_list (String.concat " " xs)
  in
  let* upstream =
    match SM.find_opt "upstream" fields with
    | None -> Ok []
    | Some `string s -> parse_id_list s
    | Some `list xs -> parse_id_list (String.concat " " xs)
  in
  let* related =
    match SM.find_opt "related" fields with
    | None -> Ok []
    | Some `string s -> parse_id_list s
    | Some `list xs -> parse_id_list (String.concat " " xs)
  in
  let* severity =
    match SM.find_opt "severity" fields with
    | None -> Ok None
    | Some `string s -> Result.map (fun s -> Some s) (parse_severity s)
    | Some `list _ -> err_msg "expected a string for severity, found a list"
  in
  let* severity_score =
    match SM.find_opt "severity_score" fields with
    | None -> Ok None
    | Some `string s -> Ok (Some s)
    | Some `list _ -> err_msg "expected a string for severity, found a list"
  in
  let* affected =
    match SM.find_opt "affected" fields with
    | None -> err_msg "expected something being affected"
    | Some `string s -> Ok s
    | Some `list _ -> err_msg "expected a string for affected, found a list"
  in
  let* events =
    match SM.find_opt "events" fields with
    | None -> Ok []
    | Some `list xs ->
      let* data, _off = parse_list (String.concat "\n" xs) in
      print_endline ("starting to parse " ^ data);
      Result.map (fun ev -> [ ev ]) (parse_events (String.trim data))
    | Some `string _ -> err_msg "expected a list for events, found a string"
  in
  let* references =
    match SM.find_opt "references" fields with
    | None -> Ok []
    | Some `string _ -> err_msg "expected a list of references, found a string"
    | Some `list xs ->
      let* data, _ = parse_list (String.concat "\n" xs) in
      List.fold_left (fun acc data ->
          let data = String.trim data in
          if data = "" then acc else
          let* acc in
          let* reference = parse_reference data in
          Ok (reference :: acc))
        (Ok []) (String.split_on_char '\n' data) |> Result.map List.rev
  in
  let* credits =
    match SM.find_opt "credits" fields with
    | None -> Ok []
    | Some `string _ -> err_msg "expected a list of credits, found a string"
    | Some `list xs ->
      let* data, _ = parse_list (String.concat "\n" xs) in
      List.fold_left (fun acc data ->
          let data = String.trim data in
          if data = "" then acc else
          let* acc in
          let* credit = parse_credit data in
          Ok (credit :: acc))
        (Ok []) (String.split_on_char '\n' data) |> Result.map List.rev
  in
  Ok { id ; modified ; published ; withdrawn ; aliases ; upstream ; related ;
       severity ; severity_score ; affected ; events ; references ; credits }
*)

let parse_file file =
  let* data = Result.map_error (function `Msg msg -> msg) (Bos.OS.File.read file) in
  (* expected format is a header of metadata, which is separated by '```\n' from the body *)
  let* header, hdr_off, summary, description, body =
    let rec separate (hdr, hdr_off, summ) state data =
      match state, data with
      | `initial, "" :: tl -> separate (hdr, hdr_off + 1, summ) state tl
      | state, "" :: tl -> separate (hdr, hdr_off, summ) state tl
      | `initial, "```" :: tl -> separate (hdr, hdr_off + 1, summ) `header tl
      | `initial, data ->
        err_msg "expected header (```), received: %s" (String.concat "\n" data)
      | `header, "```" :: tl -> separate (List.rev hdr, hdr_off, summ) `summary tl
      | `header, hd :: tl -> separate (hd :: hdr, hdr_off, summ) `header tl
      | `header, [] ->
        err_msg "expected header (```), received: %s" (String.concat "\n" data)
      | `summary, hd :: tl when String.starts_with ~prefix:"# " hd ->
        let summary = String.sub hd 2 (String.length hd - 2) in
        if String.length summary > 120 then
          Error "summary exceeds length of 120 characters"
        else
          let details = String.concat "\n" tl in
          Ok (hdr, hdr_off, summary, details, hd ^ "\n" ^ details)
      | `summary, data ->
        err_msg "expected summary (# <summary>), received: %s" (String.concat "\n" data)
    in
    separate ([], 0, "") `initial (String.split_on_char '\n' data)
  in
  Ok (String.concat "\n" header, hdr_off, summary, description, body)

let () =
  let r =
    let filename = "OSEC-2018-1.md" in
    let* (header, hdr_off, summary, _details, _body) =
      parse_file (Fpath.v ("./" ^ filename))
    in
    print_endline "parsed file";
    let* () = parse_header ~filename hdr_off header in
    print_endline ("summary: " ^ summary);
    Ok ()
  in
  match r with
  | Ok () -> ()
  | Error str -> print_endline ("error: " ^ str)

(* validation:
check-jsonschema --schemafile osv-schema.json <output.json>
*)
