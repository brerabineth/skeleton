module Skeleton.Program

open System
open Skeleton.Verdict
open Skeleton.KeyFile
open Skeleton.Authorized
open Skeleton.SshConfig
open Skeleton.KnownHosts
open Skeleton.Sweep
open Skeleton.Render

let usage =
    sprintf
        """skeleton %s — first-hour autopsy for ssh artifacts

  skeleton keys PATH...            inventory keys: type, bits, fingerprint, passphrase, perms
  skeleton authorized FILE...      authorized_keys audit: caged, uncaged, backdoor wrappers
  skeleton config FILE...          sshd_config / ssh_config hardening and backdoor relocation
  skeleton known FILE... [--check HOST,HOST]   known_hosts: hashed pins, ca, revoked, conflicts
  skeleton sweep ROOT... [--fresh N]           hunt keys and authorized_keys where they don't belong
  skeleton fp PATH...              one fingerprint line per key, for timelines and tickets
  skeleton version                 print the version

flags:
  --json                           single-line machine report on stdout
  --no-color                       plain output even on a tty

every command leaves the machine untouched: reads only, no network, no agent calls.
exit codes: 0 clean, 1 watch, 2 suspicious, 3 hostile, 64 usage."""
        version

let parseFlags (argv: string[]) =
    let mutable json = false
    let mutable noColor = false
    let mutable checkHosts = []
    let mutable fresh = None
    let positional = ResizeArray<string>()
    let mutable i = 0
    let mutable usageError = false
    while i < argv.Length do
        match argv[i] with
        | "--json" -> json <- true
        | "--no-color" -> noColor <- true
        | "--check" ->
            if i + 1 < argv.Length then
                checkHosts <-
                    argv[i + 1].Split(',') |> Array.filter (fun s -> s <> "") |> Array.toList
                i <- i + 1
            else usageError <- true
        | "--fresh" ->
            if i + 1 < argv.Length then
                match Int32.TryParse argv[i + 1] with
                | true, n when n > 0 -> fresh <- Some n
                | _ -> usageError <- true
                i <- i + 1
            else usageError <- true
        | a -> positional.Add a
        i <- i + 1
    json, noColor, checkHosts, fresh, (positional |> Seq.toList), usageError

let emit (json: bool) (cmd: string) (findings: Finding list) : int =
    if json then
        printfn "%s" (jsonFindings cmd findings)
    else
        let t = themeFor false
        let total, forced = score findings
        findings |> List.iter (printFinding t)
        if findings.IsEmpty then printfn " · nothing on the table"
        summary t total forced
    let total, forced = score findings
    exitCode total forced

// ---------- instruments ----------

let runKeys (paths: string list) (json: bool) =
    let findings =
        [ for p in paths do
              if not (IO.File.Exists p) then
                  yield watch "IO_MISSING" 10 p "path does not exist"
              else
                  try
                      let head =
                          use fs = IO.File.OpenRead p
                          let buf = Array.zeroCreate 2048
                          let n = fs.Read(buf, 0, buf.Length)
                          Text.Encoding.Latin1.GetString(buf, 0, n)
                      if head.Contains("-----BEGIN") && head.Contains("PRIVATE KEY-----") then
                          yield! permFindings p true
                          match sniffPrivate p with
                          | Ok priv ->
                              if priv.encrypted then
                                  yield note "KEY_ENC_SAFE" p (sprintf "%s, passphrase protected" priv.format)
                              else
                                  yield suspect "KEY_UNENCRYPTED" 25 p (sprintf "%s, no passphrase" priv.format)
                          | Error why -> yield watch "KEY_UNREADABLE" 5 p ("unreadable key material: " + why)
                      else
                          let lines = IO.File.ReadAllLines p
                          let pubFindings =
                              lines
                              |> Array.indexed
                              |> Array.collect (fun (i, line) ->
                                  let t = line.Trim()
                                  if t.StartsWith("ssh-") || t.StartsWith("ecdsa-") || t.StartsWith("sk-") then
                                      match parsePubLine t with
                                      | Ok k -> pubVerdict k (sprintf "%s:%d" p (i + 1)) |> Array.ofList
                                      | Error why ->
                                          [| watch "KEY_UNREADABLE" 5 (sprintf "%s:%d" p (i + 1)) ("unreadable public key: " + why) |]
                                  else [||])
                          if Array.isEmpty pubFindings then
                              yield watch "KEY_UNREADABLE" 5 p "neither a private key nor a public key line"
                          else
                              yield! (pubFindings |> Array.toList)
                  with ex -> yield watch "IO_ERROR" 5 p ex.Message ]
    emit json "keys" findings

let runAuthorized (paths: string list) (json: bool) =
    let results = paths |> List.map (fun p -> p, Authorized.auditFile p)
    let perFile =
        [ for p, r in results do
              match r with
              | Error why -> yield watch "IO_MISSING" 10 p why
              | Ok (f, _) -> yield! f ]
    let keySets =
        [ for p, r in results do
              match r with
              | Ok (_, ks) -> (p, ks)
              | Error _ -> (p, []) ]
    let dups = dupFindings keySets
    emit json "authorized" (perFile @ dups)

let runConfig (paths: string list) (json: bool) =
    let findings =
        [ for p in paths do
              match SshConfig.auditFile p with
              | Error why -> yield watch "IO_MISSING" 10 p why
              | Ok (kind, f) ->
                  if not json then
                      let t = themeFor false
                      printfn " %s· %s parsed as %s config%s" t.dim p kind t.reset
                  yield! f ]
    emit json "config" findings

let runKnown (paths: string list) (hosts: string list) (json: bool) =
    let all = paths |> List.map (fun p -> p, KnownHosts.auditFile p)
    let findings =
        [ for p, r in all do
              match r with
              | Error why -> yield watch "IO_MISSING" 10 p why
              | Ok (_, f) -> yield! f ]
    let entries = all |> List.choose (fun (_, r) -> match r with Ok (e, _) -> Some e | Error _ -> None) |> List.concat
    let matches =
        if hosts.IsEmpty then []
        else
            checkHosts entries hosts
            |> List.map (fun line -> note "KH_MATCH" (hosts |> List.head) line)
    emit json "known" (findings @ matches)

let runSweep (roots: string list) (fresh: int option) (json: bool) =
    let all = roots |> List.map (fun r -> r, sweepRoot r fresh)
    let hits = all |> List.choose (fun (_, r) -> match r with Ok (h, _) -> Some h | Error _ -> None) |> List.concat
    let findings =
        [ for r, res in all do
              match res with
              | Error why -> yield watch "IO_MISSING" 10 r why
              | Ok (_, f) -> yield! f ]
        @ twinFindings hits
    if not json then
        let t = themeFor false
        let counts =
            hits
            |> List.groupBy (fun h -> h.kind)
            |> List.map (fun (k, g) -> sprintf "%d %s" g.Length k)
            |> String.concat ", "
        if counts <> "" then printfn " %s· inventory: %s%s" t.dim counts t.reset
    emit json "sweep" findings

let runFp (paths: string list) : int =
    let mutable bad = 0
    for p in paths do
        try
            let first = IO.File.ReadLines p |> Seq.head
            match parsePubLine first with
            | Ok k ->
                printfn "%s  %d bits  %s  %s" k.fp k.bits k.ptype k.comment
            | Error why ->
                eprintfn "skeleton: %s: %s" p why
                bad <- bad + 1
        with ex ->
            eprintfn "skeleton: %s: %s" p ex.Message
            bad <- bad + 1
    if bad > 0 then 1 else 0

// ---------- dispatch ----------

[<EntryPoint>]
let main (argv: string[]) : int =
    if argv.Length = 0 then
        eprintfn "%s" usage
        64
    else
        let cmd = argv.[0]
        if cmd = "version" then
            printfn "skeleton %s" version
            0
        elif cmd = "help" || cmd = "--help" || cmd = "-h" then
            printfn "%s" usage
            0
        else
            let rest = argv.[1..]
            let json, noColor, checkHosts, fresh, positional, usageError = parseFlags rest
            if usageError then
                eprintfn "skeleton: bad flag use"
                eprintfn "%s" usage
                64
            else
                Skeleton.Render.noColorGlobal <- noColor
                match cmd with
                | "keys" when positional.Length > 0 -> runKeys positional json
                | "authorized" when positional.Length > 0 -> runAuthorized positional json
                | "config" when positional.Length > 0 -> runConfig positional json
                | "known" when positional.Length > 0 -> runKnown positional checkHosts json
                | "sweep" when positional.Length > 0 -> runSweep positional fresh json
                | "fp" when positional.Length > 0 -> runFp positional
                | _ ->
                    eprintfn "skeleton: nothing to dissect (try: skeleton help)"
                    64
