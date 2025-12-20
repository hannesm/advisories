
let ( let* ) = Result.bind

let msg fmt =
  let kerr _ = Format.flush_str_formatter () in
  Format.kfprintf kerr Format.str_formatter fmt

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

type pkg_version = OpamParserTypes.relop * string

let pp_pkg_version ppf (relop, version) =
  let[@ocaml.warning "-3"] relop_str = OpamPrinter.relop relop in
  Fmt.pf ppf "%s %S" relop_str version

type pkg_versions =
  | Atom of pkg_version
  | And of pkg_versions * pkg_versions
  | Or of pkg_versions * pkg_versions

let rec pp_pkg_versions ppf = function
  | Atom v -> pp_pkg_version ppf v
  | And (a, b) -> Fmt.pf ppf "%a & %a" pp_pkg_versions a pp_pkg_versions b
  | Or (a, b) -> Fmt.pf ppf "%a | %a" pp_pkg_versions a pp_pkg_versions b

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
  affected : string * pkg_versions ;
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
  Fmt.pf ppf "  affected: %S %a@." (fst affected) pp_pkg_versions (snd affected);
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

let pp_lines start ppf lines =
  List.iteri (fun i l -> Fmt.pf ppf "%u | %s@." (i + start) l) lines

let parse_date ~context data =
  Result.map_error (fun msg -> Fmt.str "couldn't parse %s: character %s" context msg)
    (Result.map (fun (t, _tz_off, _count) -> t)
       (Ptime.rfc3339_string_error (Ptime.of_rfc3339 data)))

let parse_severity data =
  if String.starts_with ~prefix:"CVSS:4." data then
    (CVSS_V4, data)
  else if String.starts_with ~prefix:"CVSS:3." data then
    (CVSS_V3, data)
  else
    (CVSS_V2, data)

let parse_affected pp_err lines data =
  (* TODO later:
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
      let purl = pkg://opam/p/u *)
  let open OpamParserTypes.FullPos in
  (* constraints are of the form:
     >= "1" --> Prefix_relop `Geq, String "1"
     >= "1" & < "1.2" --> Logop `And, (Prefix_relop `Geq, String "1"), (Prefix_relop `Lt, String "1.2")
     (>= "1" & < "1.2") | (>= "2.3" & < "5")
       --> Logop `Or, (Group (Prefix_relop `Geq, String "1"), (Prefix_relop `Lt, String "1.2")),
           (Group (Prefix_relop `Geq, String "2.3"), (Prefix_relop `Lt, String "5")),
  *)
  let rec parse_constraint = function
    | { pelem = Logop ({ pelem = l ; _ }, v1, v2); _ } ->
      let* c1 = parse_constraint v1 in
      let* c2 = parse_constraint v2 in
      let c = match l with `And -> And (c1, c2) | `Or -> Or (c1, c2) in
      Ok c
    | { pelem = Prefix_relop ({ pelem = relop ; _ }, { pelem = String version ; _ }) ; _ } ->
      Ok (Atom (relop, version))
    | { pelem = Group { pelem = [ cs ] ; _ } ; _ } ->
      parse_constraint cs
    | { pos; _ } as v ->
      err_msg "%a@.Expected a relative operation, a logical operation, or a group. Found %s" (pp_err pos) (lines pos)
        (OpamPrinter.FullPos.value v)
  in
  match data with
  | { pelem = Option ({ pelem = String pkg ; _ }, { pelem = [ constraints ] ; _}); _ } ->
    let* cs = parse_constraint constraints in
    Ok (pkg, cs)
  | { pos; _ } as v ->
    err_msg "%a@.Expected an option (package { constraints }). Found %s" (pp_err pos) (lines pos)
        (OpamPrinter.FullPos.value v)

let parse_events pp_err lines data =
  let open OpamParserTypes.FullPos in
  let parse_event = function
    | { pelem = List { pelem = [ { pelem = Ident event_type ; pos } ; { pelem = String data ; _ } ]; _ }; _ } ->
      let* event_type =
        Result.map_error (fun m -> msg "%a@.%s" (pp_err pos) (lines pos) m)
          (event_type_of_string event_type)
      in
      Ok (event_type, data)
    | { pos; _ } as v ->
      err_msg "%a@.Expected event_type and data, found %s." (pp_err pos) (lines pos)
        (OpamPrinter.FullPos.value v)
  in
  let parse_events = function
    | { pelem = List { pelem = [ { pelem = Ident _ ; _ } ; { pelem = String _ ; _ }]; _ }; _ } as ev ->
      let* r = parse_event ev in
      Ok [ r ]
    | { pelem = List { pelem = evs; _ }; _ } ->
      let* evs =
        List.fold_left (fun acc ev ->
            let* acc in
            let* ev = parse_event ev in
            Ok (ev :: acc))
          (Ok []) evs
      in
      Ok (List.rev evs)
    | { pos; _ } as v ->
      err_msg "%a@.Expected events (consisting of event_type and data), found %s." (pp_err pos) (lines pos)
        (OpamPrinter.FullPos.value v)
  in
  let parse_one = function
    | { pelem = List { pelem = [ { pelem = Ident range_type ; pos } ; { pelem = String repo ; _ } ; evs ]; _}; _ } ->
      let* evs = parse_events evs in
      let* range_type =
        Result.map_error (fun m -> msg "%a@.%s" (pp_err pos) (lines pos) m)
          (event_range_type_of_string range_type)
      in
      Ok (range_type, repo, evs)
    | { pos; _ } as v ->
      err_msg "%a@.Expected range_type, repo, and events, found %s." (pp_err pos) (lines pos)
        (OpamPrinter.FullPos.value v)
  in
  match data with
  | { pelem = List { pelem = ({ pelem = Ident _ ; _ } :: _); _ }; _ } ->
    let* ev = parse_one data in
    Ok [ ev ]
  | { pelem = List { pelem = ranges ; _ }; _ } ->
    let* es =
      List.fold_left (fun acc range ->
          let* acc in
          let* rt = parse_one range in
          Ok (rt :: acc))
        (Ok []) ranges
    in
    Ok (List.rev es)
  | { pos; _ } as v ->
    err_msg "%a@.Expected a list of range_type, repo, and events, found %s." (pp_err pos) (lines pos) (OpamPrinter.FullPos.value v)

let parse_references pp_err lines data =
  let open OpamParserTypes.FullPos in
  let parse_one = function
    | { pelem = List { pelem = [ { pelem = Ident typ ; pos } ; { pelem = String data ; _ } ]; _ }; _ } ->
      let* reftype =
        Result.map_error (fun m -> msg "%a@.%s" (pp_err pos) (lines pos) m)
          (reference_type_of_string typ)
      in
      Ok (reftype, data)
    | { pos; _ } as v ->
      err_msg "%a@.Expected a reference type and a string, found %s" (pp_err pos) (lines pos) (OpamPrinter.FullPos.value v)
  in
  match data with
  | { pelem = List { pelem = [ { pelem = Ident _ ; _ } ; { pelem = String _ ; _ } ] ; _ } ; _ } ->
    let* r = parse_one data in
    Ok [ r ]
  | { pelem = List { pelem = refs; _ }; _ } ->
    let* refs =
      List.fold_left (fun acc r ->
          let* acc in
          let* r = parse_one r in
          Ok (r :: acc))
        (Ok []) refs
    in
    Ok (List.rev refs)
  | { pos; _ } as v ->
    err_msg "%a@.Expected a list of reference types and strings, found %s" (pp_err pos) (lines pos) (OpamPrinter.FullPos.value v)

let parse_credits pp_err lines data =
  let open OpamParserTypes.FullPos in
  let parse_contacts = function
    | { pelem = List { pelem = cs; _ }; _ } ->
      let* contacts =
        List.fold_left (fun acc c ->
            let* acc in
            match c with
            | { pelem = String s ; _ } -> Ok (s :: acc)
            | { pos; _ } as v -> err_msg "%a@.Expected a list of strings, found %s" (pp_err pos) (lines pos) (OpamPrinter.FullPos.value v))
          (Ok []) cs
      in
      Ok (List.rev contacts)
    | { pos; _ } as v ->
      err_msg "%a@.Expected a list of strings, found %s" (pp_err pos) (lines pos) (OpamPrinter.FullPos.value v)
  in
  let parse_credit = function
    | { pelem = List { pelem = [ { pelem = Ident typ ; pos } ; { pelem = String name ; _ } ]; _ }; _ } ->
      let* credit =
        Result.map_error (fun m -> msg "%a@.%s" (pp_err pos) (lines pos) m)
          (credit_type_of_string typ)
      in
      Ok (credit, name, [])
    | { pelem = List { pelem = [ { pelem = Ident typ ; pos } ; { pelem = String name ; _ } ; contacts ]; _ }; _ } ->
      let* credit =
        Result.map_error (fun m -> msg "%a@.%s" (pp_err pos) (lines pos) m)
          (credit_type_of_string typ)
      in
      let* contacts = parse_contacts contacts in
      Ok (credit, name, contacts)
    | { pos; _ } as v ->
      err_msg "%a@.Expected a credit (typ, name, contact), found %s" (pp_err pos) (lines pos) (OpamPrinter.FullPos.value v)
  in
  match data with
  | { pelem = List { pelem = ({ pelem = Ident _; _} :: _); _ }; _ } ->
    let* c = parse_credit data in
    Ok [ c ]
  | { pelem = List { pelem = cs; _}; _ } ->
    let* cs =
      List.fold_left (fun acc c ->
          let* acc in
          let* c = parse_credit c in
          Ok (c :: acc))
        (Ok []) cs
    in
    Ok (List.rev cs)
  | { pos; _} as v ->
    err_msg "%a@.Expected a list of credits (typ, name, contact), found %s" (pp_err pos) (lines pos) (OpamPrinter.FullPos.value v)

let pp_pos line_offset ppf pos =
  let OpamParserTypes.FullPos.{ start ; stop ; filename } = pos in
  Fmt.pf ppf "in %s from %u,%u to %u,%u"
    filename (fst start + line_offset) (snd start)
    (fst stop + line_offset) (snd stop)

let pp_error line_offset pos ppf lines =
  let OpamParserTypes.FullPos.{ start ; stop ; filename } = pos in
  let stop_line = if fst start = fst stop then None else Some (fst stop + line_offset) in
  Fmt.pf ppf "File %S, line %u%a, characters %u-%u:@.%a"
    filename (fst start + line_offset)
    Fmt.(option ~none:(any "") (any "-" ++ int)) stop_line
    (snd start) (snd stop)
    (pp_lines (fst start + line_offset)) lines

let parse_header ?(filename = "no filename provided") line_offset data =
  let open OpamParserTypes.FullPos in
  let* opamfile =
    try Ok (OpamParser.FullPos.string data filename)
    with Parsing.Parse_error -> Error "parse error"
  in
  let lines = String.split_on_char '\n' data in
  let get_lines pos =
    let r = ref [] in
    for i = fst pos.start - 1 to fst pos.stop - 1 do
      r := List.nth lines i :: !r
    done;
    List.rev !r
  in
  let pp_pos = pp_pos line_offset in
  let pp_error = pp_error line_offset in
  let parse_date ~context = function
    | _, { pelem = String ts ; pos } ->
      Result.map_error (fun m -> msg "%a@.%s" (pp_error pos) (get_lines pos) m)
        (parse_date ~context ts)
    | pos, value ->
      err_msg "%a@.Expected a string for %S, found %s"
        (pp_error pos) (get_lines pos) context (OpamPrinter.FullPos.value value)
  in
  let parse_opt_id_list ~context = function
    | None -> Ok []
    | Some (_, { pelem = List { pelem = vs ; _ } ; _ }) ->
      let* vs =
        List.fold_left (fun acc v ->
            let* acc in
            match v with
            | { pelem = Ident id ; _ } -> Ok (id :: acc)
            | { pos ; _ } as v ->
              err_msg "%a@.Expected a list of identifiers for %S, found %s"
                (pp_error pos) (get_lines pos) context (OpamPrinter.FullPos.value v))
          (Ok []) vs
      in
      Ok (List.rev vs)
    | Some (_, { pelem = Ident id ; _ }) ->
      Ok [ id ]
    | Some (pos, value) ->
      err_msg "%a@.Expected a list of identifiers (or a single identifier) for %S, found %s"
        (pp_error pos) (get_lines pos) context (OpamPrinter.FullPos.value value)
  in
  (* opamfile_item list (with source position) *)
  let* fields =
    List.fold_left (fun map v ->
        let* map in
        match v with
        | { pelem = Variable ({ pelem = name ; _ }, value) ; pos } ->
          (match SM.find_opt name map with
           | Some (pos', _) ->
             err_msg "%a@.An entry named %S already exists:@.%a"
               (pp_error pos) (get_lines pos) name
               (pp_lines (line_offset + fst pos'.start)) (get_lines pos')
           | None ->
             Ok (SM.add name (pos, value) map))
        | { pelem = Section { section_kind = { pelem = name ; _ } ; _ } ; pos } ->
          err_msg "unexpected section %s at %a" name pp_pos pos)
      (Ok SM.empty) opamfile.file_contents
  in
  let* id =
    let* id =
      Option.to_result ~none:"missing id"
        (SM.find_opt "id" fields)
    in
    match id with
    | _, { pelem = Ident id ; _ } -> Ok id
    | pos, value ->
      err_msg "%a@.Expected an identifier for \"id\", found %s"
        (pp_error pos) (get_lines pos) (OpamPrinter.FullPos.value value)
  in
  let* modified =
    let* ts =
      Option.to_result ~none:"missing modified"
        (SM.find_opt "modified" fields)
    in
    parse_date ~context:"modified" ts
  in
  let* published =
    match SM.find_opt "published" fields with
    | Some x -> Result.map (fun ts -> Some ts) (parse_date ~context:"published" x)
    | None -> Ok None
  in
  let* withdrawn =
    match SM.find_opt "withdrawn" fields with
    | Some ts -> Result.map (fun ts -> Some ts) (parse_date ~context:"withdrawn" ts)
    | None -> Ok None
  in
  let* aliases =
    parse_opt_id_list ~context:"aliases" (SM.find_opt "aliases" fields)
  in
  let* upstream =
    parse_opt_id_list ~context:"upstream" (SM.find_opt "upstream" fields)
  in
  let* related =
    parse_opt_id_list ~context:"related" (SM.find_opt "related" fields)
  in
  let* severity =
    match SM.find_opt "severity" fields with
    | None -> Ok None
    | Some (_, { pelem = String s ; _ }) ->
      let s = parse_severity s in
      Ok (Some s)
    | Some (pos, value) ->
      err_msg "%a@.Expected a string for \"severity\", found %s"
        (pp_error pos) (get_lines pos) (OpamPrinter.FullPos.value value)
  in
  let* severity_score =
    match SM.find_opt "severity_score" fields with
    | None -> Ok None
    | Some (_, { pelem = String s ; _ }) -> Ok (Some s)
    | Some (pos, value) ->
      err_msg "%a@.Expected a string for \"severity_score\", found %s"
        (pp_error pos) (get_lines pos) (OpamPrinter.FullPos.value value)
  in
  let* affected =
    match SM.find_opt "affected" fields with
    | None -> err_msg "expected something being affected"
    | Some (_, elem) -> parse_affected pp_error get_lines elem
  in
  let* events =
    match SM.find_opt "events" fields with
    | None -> Ok []
    | Some (_, ({ pelem = List _ ; _ } as elem)) -> parse_events pp_error get_lines elem
    | Some (pos, value) ->
      err_msg "%a@.Expected a list for \"events\", found %s"
        (pp_error pos) (get_lines pos) (OpamPrinter.FullPos.value value)
  in
  let* references =
    match SM.find_opt "references" fields with
    | None -> Ok []
    | Some (_, elem) -> parse_references pp_error get_lines elem
  in
  let* credits =
    match SM.find_opt "credits" fields with
    | None -> Ok []
    | Some (_, elem) -> parse_credits pp_error get_lines elem
  in
  Ok { id ; modified ; published ; withdrawn ; aliases ; upstream ; related ;
       severity ; severity_score ; affected ; events ; references ; credits }

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
    let* header = parse_header ~filename hdr_off header in
    Format.printf "header:@.%a" pp_header header;
    print_endline ("summary: " ^ summary);
    Ok ()
  in
  match r with
  | Ok () -> ()
  | Error str -> print_endline ("error: " ^ str)

(* validation:
check-jsonschema --schemafile osv-schema.json <output.json>
*)
