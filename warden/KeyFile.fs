module Skeleton.KeyFile

open System
open System.Security.Cryptography
open Skeleton.Verdict

// ---------- wire-format primitives ----------

let b64decode (s: string) =
    let trimmed =
        s.Trim().Replace("\n", "").Replace("\r", "")
        |> fun t -> t.TrimEnd('=')
    let pad = (4 - trimmed.Length % 4) % 4
    Convert.FromBase64String(trimmed + String.replicate pad "=")

let readStr (data: byte[]) (off: int) : byte[] * int =
    if off + 4 > data.Length then failwith "truncated string"
    let len =
        (int data[off] <<< 24)
        ||| (int data[off + 1] <<< 16)
        ||| (int data[off + 2] <<< 8)
        ||| int data[off + 3]
    if len < 0 || off + 4 + len > data.Length then failwith "bad string length"
    data.[off + 4 .. off + 4 + len - 1], off + 4 + len

let mpintBits (data: byte[]) =
    let n = Array.length data
    if n = 0 then 0
    else
        let mutable lead = 0
        while lead < n && data[lead] = 0uy do lead <- lead + 1
        if lead = n then 0
        else
            let first = int data[lead]
            let mutable bits = 0
            let mutable v = first
            while v > 0 do
                bits <- bits + 1
                v <- v >>> 1
            (n - lead - 1) * 8 + bits

let sha256b64 (data: byte[]) =
    use sha = SHA256.Create()
    let h = sha.ComputeHash(data)
    "SHA256:" + Convert.ToBase64String(h).TrimEnd('=')

let blobHash (data: byte[]) =
    use sha = SHA256.Create()
    let h = sha.ComputeHash(data)
    Convert.ToHexString(h).ToLowerInvariant()

// ---------- public keys ----------

type PubKey =
    { ptype: string
      bits: int
      fp: string
      bhash: string
      comment: string
      isCert: bool }

let curveBits (curve: string) =
    if curve.Contains("nistp521") then 521
    elif curve.Contains("nistp384") then 384
    elif curve.Contains("nistp256") then 256
    else 0

// parse the wire blob; returns (bits, isCert) — tolerant: on failure return 0 bits
let parseBlob (blob: byte[]) : int * bool =
    try
        let t, off1 = readStr blob 0
        let ty = Text.Encoding.ASCII.GetString(t)
        let isCert = ty.Contains("-cert-v01@openssh.com")
        if ty.StartsWith("ssh-rsa") then
            let _, o1 = readStr blob off1        // e
            let n, _ = readStr blob o1           // n
            mpintBits n, isCert
        elif ty.StartsWith("ssh-dss") then
            let p, _ = readStr blob off1         // p
            mpintBits p, isCert
        elif ty.Contains("ecdsa-sha2") then
            let c, _ = readStr blob off1         // curve name
            curveBits (Text.Encoding.ASCII.GetString c), isCert
        elif ty.Contains("ed25519") then
            256, isCert
        else
            0, isCert
    with _ ->
        0, false

// parse one "type base64 [comment]" line
let parsePubLine (line: string) : Result<PubKey, string> =
    let parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries)
    if parts.Length < 2 then
        Error "not a public key line"
    else
        try
            let blob = b64decode parts.[1]
            if blob.Length < 8 then Error "blob too small"
            else
                let t0, _ = readStr blob 0
                let ty = Text.Encoding.ASCII.GetString t0
                if not (parts.[0] = ty) then Error "type mismatch with blob"
                else
                    let bits, isCert = parseBlob blob
                    let comment =
                        if parts.Length >= 3 then String.concat " " parts.[2..] else ""
                    Ok
                        { ptype = ty
                          bits = bits
                          fp = sha256b64 blob
                          bhash = blobHash blob
                          comment = comment
                          isCert = isCert }
        with _ -> Error "unreadable blob"

// ---------- private keys ----------

type PrivKey =
    { format: string    // openssh | pkcs1-rsa | pkcs1-ec | pkcs1-dsa | pkcs8
      encrypted: bool }

let sniffPrivate (path: string) : Result<PrivKey, string> =
    try
        use sr = new IO.StreamReader(path)
        let mutable header = ""
        let mutable body = ""
        let mutable inBody = false
        let mutable found = None
        while not sr.EndOfStream && found.IsNone do
            let line = sr.ReadLine()
            let t = line.Trim()
            if t.StartsWith("-----BEGIN ") && t.EndsWith("-----") then
                header <- t
                inBody <- true
            elif inBody && t.StartsWith("-----END") then
                found <- Some(header.TrimStart('-').Replace("BEGIN ", "").TrimEnd('-'))
            elif inBody && t <> "" then
                if t.Contains(":") then body <- body + t + "\n"   // armored header, e.g. Proc-Type
                elif body.Length < 4096 then body <- body + t
        match found with
        | None -> Error "no private key header"
        | Some kind ->
            let encrypted =
                if kind.StartsWith("ENCRYPTED") then true
                elif kind = "OPENSSH PRIVATE KEY" then
                    try
                        let raw = b64decode body
                        // magic "openssh-key-v1\0" (15 bytes), then ciphername string
                        let magic = Text.Encoding.ASCII.GetBytes("openssh-key-v1\u0000")
                        if raw.Length > 19 && raw.[0..14] = magic then
                            let cipher, _ = readStr raw 15
                            Text.Encoding.ASCII.GetString cipher <> "none"
                        else true // unreadable: assume protected
                    with _ -> true
                else
                    body.Contains("Proc-Type:") && body.Contains("ENCRYPTED")
            Ok { format = kind.ToLowerInvariant(); encrypted = encrypted }
    with ex -> Error ex.Message

// classify a key type for scoring
let keyClass (ty: string) : string =
    if ty.Contains("ssh-dss") then "dsa"
    elif ty.Contains("ssh-rsa") && not (ty.Contains("cert")) then "rsa"
    elif ty.Contains("ecdsa-sha2") && not (ty.Contains("cert")) then "ecdsa"
    elif ty.Contains("ed25519") && not (ty.Contains("cert")) then "ed25519"
    elif ty.Contains("sk-") then "fido"
    elif ty.Contains("cert-v01") then "cert"
    else "other"

let rsaVerdict bits (where: string) =
    if bits > 0 && bits < 2048 then
        [ suspect "KEY_RSA_WEAK" 60 where (sprintf "%d-bit rsa; factorable at rest" bits) ]
    elif bits = 2048 then
        [ watch "KEY_RSA2048" 10 where "2048-bit rsa; 3072+ is the current floor" ]
    else []

let pubVerdict (k: PubKey) (where: string) : Finding list =
    match keyClass k.ptype with
    | "dsa" -> [ suspect "KEY_DSA" 40 where "dsa key; deprecated, disabled in modern openssh" ]
    | "rsa" -> rsaVerdict k.bits where
    | "fido" -> [ note "KEY_FIDO" where ("hardware-backed " + k.ptype) ]
    | "cert" -> [ note "KEY_CERT" where (sprintf "%s certificate" k.ptype) ]
    | _ -> [ note ("KEY_" + keyClass k.ptype |> fun s -> s.ToUpper()) where (sprintf "%s, %d bits" k.ptype k.bits) ]
