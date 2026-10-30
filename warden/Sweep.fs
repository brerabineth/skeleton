module Skeleton.Sweep

open System
open System.IO
open Skeleton.Verdict
open Skeleton.KeyFile
open Skeleton.Authorized

let tmpRoots = [ "/tmp/"; "/var/tmp/"; "/dev/shm/"; "/run/"; "/var/run/" ]

let isTmp (path: string) =
    tmpRoots |> List.exists (fun t -> path.Contains(t))

let sysStandard (path: string) =
    path.Contains("/etc/ssh/")

let homeStandard (path: string) =
    // authorized_keys living directly in a .ssh directory of some home
    let dir = Path.GetDirectoryName(path)
    if isNull dir then false else dir.EndsWith("/.ssh") || dir = ".ssh"

let placement (path: string) (kind: string) : Finding list =
    if isTmp path then
        [ hostile "SWP_TMP_PLANT" 80 path (kind + " planted in scratch space") ]
    elif sysStandard path || homeStandard path then []
    else [ suspect "SWP_ODD_DIR" 55 path (kind + " outside any .ssh directory or /etc/ssh") ]

let unixMode (path: string) : int option =
    try
        let m = File.GetUnixFileMode path
        Some(int m)
    with _ -> None

let permFindings (path: string) (sensitive: bool) : Finding list =
    match unixMode path with
    | None -> []
    | Some m ->
        let worldW = m &&& 0o002 <> 0
        let worldR = m &&& 0o004 <> 0
        let groupW = m &&& 0o020 <> 0
        if worldW then
            [ hostile "SWP_WORLD_WRITE" 80 path "world-writable; anyone can append a backdoor key" ]
        elif sensitive && worldR then
            [ suspect "SWP_KEY_WORLD_READ" 45 path "private key readable by every account on the box" ]
        elif groupW then
            [ suspect "SWP_GROUP_WRITE" 40 path "group-writable" ]
        else []

let isPrivateHeader (bytes: byte[]) =
    let text = Text.Encoding.Latin1.GetString bytes
    text.Contains("-----BEGIN") && text.Contains("PRIVATE KEY-----")

let pubLine (bytes: byte[]) =
    let text = Text.Encoding.UTF8.GetString bytes
    let first =
        text.Split('\n') |> Array.tryHead |> Option.map (fun l -> l.Trim()) |> Option.defaultValue ""
    first.StartsWith("ssh-") || first.StartsWith("ecdsa-") || first.StartsWith("sk-")

type SweepHit =
    { path: string
      kind: string        // authorized | private | public | known | config | rc | sshdir
      detail: string }

let sweepRoot (root: string) (fresh: int option) : Result<SweepHit list * Finding list, string> =
    try
        if not (Directory.Exists root) && not (File.Exists root) then
            Error (sprintf "no such path: %s" root)
        else
            let hits = ResizeArray<SweepHit>()
            let findings = ResizeArray<Finding>()
            let opts = EnumerationOptions()
            opts.IgnoreInaccessible <- true
            opts.RecurseSubdirectories <- true
            opts.AttributesToSkip <- FileAttributes.ReparsePoint
            // process directories then recurse manually for control
            let rec walk (dir: string) =
                let dirFindings =
                    if dir.EndsWith("/.ssh") || dir = ".ssh" then
                        hits.Add { path = dir; kind = "sshdir"; detail = "" }
                        permFindings dir false
                    else []
                dirFindings |> findings.AddRange
                let enumOpts = EnumerationOptions()
                enumOpts.IgnoreInaccessible <- true
                enumOpts.AttributesToSkip <- FileAttributes.ReparsePoint
                try
                    for f in Directory.EnumerateFiles(dir, "*", enumOpts) do
                        inspect f
                    for d in Directory.EnumerateDirectories(dir, "*", enumOpts) do
                        walk d
                with _ -> ()
            and inspect (f: string) =
                let name = Path.GetFileName f
                try
                    let fi = FileInfo f
                    if fi.Length > 1_000_000L then ()
                    else
                        let isAuthorized = name = "authorized_keys" || name = "authorized_keys2"
                        let isKnown = name.StartsWith("known_hosts")
                        let isRc = name = "rc" && (f.Contains("/.ssh/") || f.Contains("/etc/ssh/"))
                        let isConfig = name = "config" && (f.Contains("/.ssh/") || f.Contains("/etc/ssh/"))
                        if isAuthorized || isKnown || isRc || isConfig then
                            use fs = File.OpenRead f
                            let buf = Array.zeroCreate 512
                            let n = fs.Read(buf, 0, buf.Length)
                            let head = Text.Encoding.Latin1.GetString(buf, 0, n)
                            if isAuthorized then
                                hits.Add { path = f; kind = "authorized"; detail = "" }
                                placement f "authorized_keys" |> findings.AddRange
                                permFindings f false |> findings.AddRange
                                if name = "authorized_keys2" then
                                    findings.Add(watch "SWP_AK2" 12 f "legacy authorized_keys2; retired filename, still alive here")
                                (match fresh with
                                 | Some days when (DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays < float days ->
                                     findings.Add(note "SWP_FRESH" f (sprintf "modified within the last %d days" days))
                                 | _ -> ())
                            elif isRc then
                                hits.Add { path = f; kind = "rc"; detail = "" }
                                findings.Add(watch "SWP_RC" 25 f "ssh rc file; every login executes this script")
                            elif isConfig then
                                hits.Add { path = f; kind = "config"; detail = "" }
                            else // known_hosts
                                hits.Add { path = f; kind = "known"; detail = "" }
                                if not (sysStandard f) && not (homeStandard f) then
                                    findings.Add(watch "SWP_KNOWN_ODD" 20 f "known_hosts outside a .ssh directory")
                        else
                            use fs = File.OpenRead f
                            let buf = Array.zeroCreate 256
                            let n = fs.Read(buf, 0, buf.Length)
                            if n > 20 && isPrivateHeader buf then
                                hits.Add { path = f; kind = "private"; detail = "" }
                                placement f "private key" |> findings.AddRange
                                permFindings f true |> findings.AddRange
                                (match fresh with
                                 | Some days when (DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays < float days ->
                                     findings.Add(note "SWP_FRESH" f (sprintf "modified within the last %d days" days))
                                 | _ -> ())
                            elif n > 8 && pubLine buf && (name.EndsWith(".pub") || name.Contains("authorized")) then
                                hits.Add { path = f; kind = "public"; detail = "" }
                with _ -> ()
            if File.Exists root then
                inspect root
            else
                walk (if Directory.Exists root then root else Path.GetDirectoryName root)
            Ok(hits |> Seq.toList, findings |> Seq.toList)
    with ex -> Error ex.Message

let twinFindings (hits: SweepHit list) : Finding list =
    hits
    |> List.filter (fun h -> h.kind = "authorized")
    |> List.groupBy (fun h ->
        try IO.File.ReadAllBytes h.path |> blobHash
        with _ -> Guid.NewGuid().ToString())
    |> List.choose (fun (h, grp) ->
        if grp.Length > 1 then
            let places = grp |> List.map (fun g -> g.path) |> String.concat " | "
            Some [ watch "SWP_AK_TWIN" 20 (grp |> List.head |> fun g -> g.path)
                       (sprintf "identical authorized_keys content in %d places: %s" grp.Length places) ]
        else None)
    |> List.concat
