module Skeleton.Authorized

open System
open Skeleton.Verdict
open Skeleton.KeyFile

// ---------- option parsing (comma separated, quote aware) ----------

let splitOpts (s: string) : string list =
    let acc = ResizeArray<string>()
    let buf = Text.StringBuilder()
    let mutable quoted = false
    let mutable escaped = false
    for c in s do
        if escaped then
            buf.Append(c) |> ignore
            escaped <- false
        elif c = '\\' && quoted then
            buf.Append(c) |> ignore
            escaped <- true
        elif c = '"' then
            quoted <- not quoted
            buf.Append(c) |> ignore
        elif c = ',' && not quoted then
            acc.Add(buf.ToString())
            buf.Clear() |> ignore
        else buf.Append(c) |> ignore
    if buf.Length > 0 then acc.Add(buf.ToString())
    acc |> Seq.filter (fun x -> x.Trim() <> "") |> Seq.map (fun x -> x.Trim()) |> Seq.toList

// split "opts keyblob comment" — opts end at first whitespace outside quotes
let splitLine (line: string) : string option * string * string =
    let mutable quoted = false
    let mutable escaped = false
    let mutable idx = -1
    let chars = line.ToCharArray()
    for i in 0 .. chars.Length - 1 do
        if idx = -1 then
            let c = chars[i]
            if escaped then escaped <- false
            elif c = '\\' && quoted then escaped <- true
            elif c = '"' then quoted <- not quoted
            elif c = ' ' && not quoted then idx <- i
    if idx = -1 then None, line.Trim(), ""
    else
        let head = line.Substring(0, idx).Trim()
        let rest = line.Substring(idx + 1).Trim()
        if head.Contains("ssh-") || head.Contains("ecdsa-") || head.StartsWith("sk-") then
            // no options; head is the key type
            let toks = line.Trim().Split(' ', 3)
            None,
            (if toks.Length > 1 then toks.[0] + " " + toks.[1] else toks.[0]),
            (if toks.Length > 2 then toks.[2] else "")
        else
            let toks = rest.Split(' ', 3)   // type, blob, comment
            Some head,
            (if toks.Length > 1 then toks.[0] + " " + toks.[1] else toks.[0]),
            (if toks.Length > 2 then toks.[2] else "")

type OptMap = Map<string, string>   // name -> value ("" when flag)

let parseOpts (s: string) : OptMap =
    splitOpts s
    |> List.choose (fun o ->
        let eq = o.IndexOf('=')
        if eq >= 0 then
            let k = o.Substring(0, eq).Trim().ToLowerInvariant()
            let v = o.Substring(eq + 1).Trim()
            let unq =
                if v.StartsWith("\"") && v.EndsWith("\"") && v.Length >= 2 then
                    v.Substring(1, v.Length - 2)
                else v
            Some(k, unq)
        else Some(o.ToLowerInvariant(), ""))
    |> Map.ofList

// ---------- forced-command analysis ----------

let safeFixed = [ "git-shell"; "rrsync"; "svnserve"; "cvs"; "bzr"; "hg"; "sftp-server"; "internal-sftp" ]

let interpreterBits (cmd: string) =
    [ "sh -c"; "bash -c"; "dash -c"; "zsh -c"; "ksh -c"; "python -c"; "python3 -c"; "perl -e"; "ruby -e"; "eval " ]
    |> List.exists cmd.Contains

let netBits (cmd: string) =
    [ "curl"; "wget"; "nc "; "ncat"; "netcat"; "socat"; "/dev/tcp/"; "base64 -d"; "openssl s_client"; "telnet " ]
    |> List.exists (fun p -> cmd.Contains p)
    || cmd.Contains("base64 --decode")

let metachars (cmd: string) =
    cmd.Contains("|") || cmd.Contains("&&") || cmd.Contains(";")
    || cmd.Contains("`") || cmd.Contains("$(")

let commandVerdict (where: string) (cmd: string) : Finding list =
    let hasOrig = cmd.Contains("SSH_ORIGINAL_COMMAND")
    if netBits cmd && not hasOrig then
        [ hostile "AUTH_CAGED_NET" 80 where "forced command pulls or pipes over the network; no original-command jail" ]
    elif interpreterBits cmd && not hasOrig then
        [ suspect "AUTH_CAGED_SHELL" 45 where "forced command runs an interpreter one-liner without SSH_ORIGINAL_COMMAND" ]
    elif hasOrig then
        [ note "AUTH_CAGED_JAIL" where "forced command re-runs the client's request through a wrapper" ]
    elif metachars cmd then
        [ suspect "AUTH_CAGED_SHELL" 45 where "forced command uses shell metacharacters; not a plain fixed binary" ]
    elif safeFixed |> List.exists (fun s -> cmd.Contains s) then
        [ note "AUTH_CAGED_SAFE" where ("fixed command: " + cmd) ]
    else
        [ note "AUTH_CAGED_SAFE" where ("fixed command: " + cmd) ]

let expiryPast (v: string) =
    let digits = v |> String.filter Char.IsDigit
    if digits.Length >= 8 then
        match
            try
                Some(DateOnly.ParseExact(digits.Substring(0, 8), "yyyyMMdd"))
            with _ -> None
        with
        | Some d -> d < DateOnly.FromDateTime DateTime.UtcNow
        | None -> false
    else false

// ---------- per-line audit ----------

let auditLine (where: string) (lineNo: int) (line: string) : Finding list * PubKey option =
    let at = sprintf "%s:%d" where lineNo
    let t = line.Trim()
    if t = "" || t.StartsWith("#") then [], None
    elif t.StartsWith("@") then
        // marker lines: @cert-authority pattern type blob [comment]
        match t.IndexOf(' ') with
        | -1 -> [ watch "AUTH_BADLINE" 10 at "bare marker with no key" ], None
        | sp ->
            let marker = t.Substring(0, sp)
            let afterMarker = t.Substring(sp + 1).Trim()
            match afterMarker.IndexOf(' ') with
            | -1 -> [ watch "AUTH_BADLINE" 10 at "marker with no key material" ], None
            | sp2 ->
                let pattern = afterMarker.Substring(0, sp2)
                match parsePubLine (afterMarker.Substring(sp2 + 1).Trim()) with
                | Error why -> [ watch "AUTH_BADLINE" 10 at ("unparseable marker line: " + why) ], None
                | Ok key ->
                    let tail =
                        if marker = "@cert-authority" then
                            [ note "AUTH_CA" at ("cert-authority for '" + pattern + "'; trusts every key it signed") ]
                        elif marker = "@principals" then
                            [ note "AUTH_PRINCIPALS" at ("principals-restricted entry for '" + pattern + "'") ]
                        else [ watch "AUTH_BADLINE" 10 at ("unknown marker: " + marker) ]
                    tail, Some key
    else
        let opts, rest, comment = splitLine t
        let optMap = opts |> Option.map parseOpts
        let keyResult = parsePubLine rest
        match keyResult with
        | Error why -> [ watch "AUTH_BADLINE" 10 at ("unparseable line: " + why) ], None
        | Ok key ->
            let keyFindings = pubVerdict key at
            let whereTag = if comment <> "" then sprintf "%s (%s)" at comment else at
            let optFindings =
                match optMap with
                | None -> [ note "AUTH_UNCAGED" whereTag "no options; opens a full interactive shell" ]
                | Some m ->
                    if m.ContainsKey("restrict") then
                        [ note "AUTH_RESTRICT" whereTag "restrict; all forwarding and pty locked down" ]
                    else
                        let out = ResizeArray<Finding>()
                        if m.ContainsKey("command") then
                            commandVerdict whereTag m.["command"] |> out.AddRange
                        else out.Add(note "AUTH_UNCAGED" whereTag "no forced command; opens a full interactive shell")
                        (match m.TryFind "from" with
                         | Some v when v = "*" || v = "" ->
                             out.Add(watch "AUTH_FROM_BROAD" 10 whereTag "from= accepts any source address")
                         | Some v -> out.Add(note "AUTH_FROM" whereTag ("source restricted: " + v))
                         | None -> ())
                        if m.ContainsKey("environment") then
                            out.Add(watch "AUTH_ENV" 8 whereTag "environment= injects variables into the session")
                        if m.ContainsKey("no-pty") && not (m.ContainsKey("command")) then
                            out.Add(watch "AUTH_NOPTY_ONLY" 4 whereTag "no-pty without a forced command; tunnel-style access")
                        (match m.TryFind "expiry-time" with
                         | Some v when expiryPast v -> out.Add(note "AUTH_EXPIRED" whereTag ("expiry already passed: " + v))
                         | Some v -> out.Add(note "AUTH_EXPIRY" whereTag ("expires " + v))
                         | None -> ())
                        if m.ContainsKey("cert-authority") then
                            out.Add(note "AUTH_CA" whereTag "cert-authority; trusts every key it signed")
                        if m.ContainsKey("tunnel") then out.Add(note "AUTH_TUNNEL" whereTag "tunnel device access")
                        if m.ContainsKey("permitopen") || m.ContainsKey("permitlisten") then
                            out.Add(note "AUTH_PERMIT" whereTag "forwarding pinned to specific endpoints")
                        if m.ContainsKey("no-agent-forwarding") || m.ContainsKey("no-port-forwarding") then
                            out.Add(note "AUTH_LOCKED" whereTag "forwarding explicitly disabled")
                        out |> Seq.toList
            keyFindings @ optFindings, Some key

let auditFile (path: string) : Result<Finding list * PubKey list, string> =
    try
        let lines = IO.File.ReadAllLines path
        let all = lines |> Array.mapi (fun i l -> auditLine path (i + 1) l)
        let findings = all |> Array.map fst |> Array.toList |> List.concat
        let keys = all |> Array.choose snd |> Array.toList
        Ok(findings, keys)
    with ex -> Error ex.Message

// cross-file duplicate detection over collected keys
let dupFindings (files: (string * PubKey list) list) : Finding list =
    files
    |> List.collect (fun (f, ks) -> ks |> List.map (fun k -> k.bhash, f, k))
    |> List.groupBy (fun (h, _, _) -> h)
    |> List.choose (fun (h, grp) ->
        if grp.Length > 1 then
            let places = grp |> List.map (fun (_, f, k) -> sprintf "%s %s" f (k.fp.Substring(0, 20))) |> String.concat " | "
            Some [ watch "AUTH_DUP" 15 (grp |> List.head |> fun (_, f, _) -> f) ("same key material in multiple files: " + places + " …") ]
        else None)
    |> List.concat
