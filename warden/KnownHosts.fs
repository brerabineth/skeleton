module Skeleton.KnownHosts

open System
open System.Security.Cryptography
open System.Text
open Skeleton.Verdict
open Skeleton.KeyFile

type KhEntry =
    { no: int
      markers: string list
      patterns: string list
      hashed: bool
      key: PubKey option
      raw: string }

let hmacSha1 (key: byte[]) (msg: byte[]) =
    use h = new HMACSHA1(Key = key)
    h.ComputeHash msg

let saltAndHash (entry: string) : byte[] * byte[] option =
    // |1|b64(salt)|b64(hmac)|
    if entry.StartsWith("|1|") then
        let parts = entry.Split('|')
        // "", "1", salt, hash
        if parts.Length >= 4 then
            try Some(b64decode parts.[2], Some(b64decode parts.[3])) with _ -> None
        else None
    else None
    |> function
        | Some(s, h) -> (s, h)
        | _ -> ([| 0uy |], None)

let rec hostMatches (pattern: string) (host: string) =
    if pattern.StartsWith("!") then
        not (hostMatches (pattern.Substring(1)) host)
    elif pattern.Contains("*") || pattern.Contains("?") then
        let escaped =
            Text.RegularExpressions.Regex.Escape(pattern)
                .Replace(@"\*", ".*")
                .Replace(@"\?", ".")
        Text.RegularExpressions.Regex.IsMatch(host, "^" + escaped + "$")
    else
        String.Equals(pattern, host, StringComparison.OrdinalIgnoreCase)

let matchesEntry (e: KhEntry) (host: string) : bool =
    e.patterns
    |> List.exists (fun p ->
        if p.StartsWith("|1|") then
            let salt, want = saltAndHash p
            match want with
            | Some want' ->
                let got = hmacSha1 salt (Encoding.ASCII.GetBytes host)
                got = want'
            | None -> false
        else hostMatches p host)

let auditFile (path: string) : Result<KhEntry list * Finding list, string> =
    try
        let lines = IO.File.ReadAllLines path
        let entries = ResizeArray<KhEntry>()
        let findings = ResizeArray<Finding>()
        let mutable plainSeen = 0
        let mutable portSeen = 0
        lines
        |> Array.iteri (fun i raw ->
            let no = i + 1
            let t = raw.Trim()
            if t <> "" && not (t.StartsWith("#")) then
                let toks = t.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                let mutable idx = 0
                let markers = ResizeArray<string>()
                while idx < toks.Length && toks.[idx].StartsWith("@") do
                    markers.Add(toks.[idx])
                    idx <- idx + 1
                if idx + 2 > toks.Length then
                    findings.Add(watch "KH_BADLINE" 8 (sprintf "%s:%d" path no) "truncated known_hosts line")
                else
                    let hostField = toks.[idx]
                    let keyField = toks.[idx + 1] + " " + toks.[idx + 2]
                    let patterns = hostField.Split(',') |> Array.toList
                    let hashed = patterns |> List.exists (fun p -> p.StartsWith("|1|"))
                    let key =
                        match parsePubLine keyField with
                        | Ok k -> Some k
                        | Error _ ->
                            findings.Add(watch "KH_BADLINE" 8 (sprintf "%s:%d" path no) "unreadable host key")
                            None
                    patterns
                    |> List.iter (fun p ->
                        if not (p.StartsWith("|1|")) then plainSeen <- plainSeen + 1
                        if p.StartsWith("[") && p.Contains("]:") then portSeen <- portSeen + 1)
                    if markers.Contains("@revoked") then
                        findings.Add(
                            note "KH_REVOKED"
                                (sprintf "%s:%d" path no)
                                ("revoked key on record: "
                                 + (match key with Some k -> k.fp | None -> "unreadable")))
                    if markers.Contains("@cert-authority") then
                        findings.Add(note "KH_CA" (sprintf "%s:%d" path no) "host ca pinned")
                    entries.Add
                        { no = no
                          markers = markers |> Seq.toList
                          patterns = patterns
                          hashed = hashed
                          key = key
                          raw = t })
        if plainSeen > 0 then
            findings.Add(watch "KH_PLAINTEXT" 3 path (sprintf "%d plaintext hostnames stored in the clear" plainSeen))
        if portSeen > 0 then
            findings.Add(note "KH_PORT" path (sprintf "%d entries pin non-standard ports" portSeen))
        // duplicates and conflicts per pattern
        let byPattern =
            entries
            |> Seq.collect (fun e -> e.patterns |> List.map (fun p -> p, e))
            |> Seq.groupBy fst
            |> Seq.map (fun (p, g) -> p, g |> Seq.map snd |> Seq.toList)
            |> Seq.toList
        for p, grp in byPattern do
            if p.StartsWith("|1|") then ()
            else
                let hashes =
                    grp
                    |> List.choose (fun e -> e.key |> Option.map (fun k -> k.bhash))
                    |> List.distinct
                if grp.Length > 1 && hashes.Length = 1 then
                    findings.Add(watch "KH_DUP" 12 path (sprintf "pattern %s repeated %d times with identical key" p grp.Length))
                elif hashes.Length > 1 then
                    findings.Add(
                        suspect "KH_CONFLICT" 45
                            path
                            (sprintf
                                "pattern %s carries %d different keys; torn tofu reset or a mitm in progress"
                                p
                                hashes.Length))
        Ok(entries |> Seq.toList, findings |> Seq.toList)
    with ex -> Error ex.Message

let checkHosts (entries: KhEntry list) (hosts: string list) : string list =
    hosts
    |> List.collect (fun h ->
        let hits = entries |> List.filter (fun e -> matchesEntry e h)
        match hits with
        | [] -> [ sprintf "%s: no pinned record" h ]
        | _ ->
            hits
            |> List.map (fun e ->
                let marker =
                    if List.contains "@revoked" e.markers then " REVOKED"
                    elif List.contains "@cert-authority" e.markers then " CA"
                    else ""
                let vis = if e.hashed then "hashed" else "plain"
                sprintf
                    "%s: %s%s (%s)"
                    h
                    (match e.key with Some k -> k.fp | None -> "?")
                    marker
                    vis))
