module Skeleton.SshConfig

open System
open Skeleton.Verdict

type Line = { no: int; key: string; args: string[]; raw: string }

let tokenize (raw: string) : Line option =
    let noComment =
        let i = raw.IndexOf('#')
        if i >= 0 then raw.Substring(0, i) else raw
    let t = noComment.Trim()
    if t = "" then None
    else
        let eq = t.IndexOf('=')
        let head, rest =
            if eq > 0 && not (t.Contains(" ") || t.Contains "\t") then
                t.Substring(0, eq), t.Substring(eq + 1)
            elif eq > 0 && t.IndexOf(' ') > eq then
                t.Substring(0, eq), t.Substring(eq + 1)
            else
                let sp = t.IndexOfAny [| ' '; '\t' |]
                if sp < 0 then t, ""
                else t.Substring(0, sp), t.Substring(sp + 1)
        let args =
            rest.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.map (fun a -> a.Trim('"'))
        Some { no = 0; key = head.Trim().ToLowerInvariant(); args = args; raw = t }

let sshdKnown =
    set [ "acceptenv"; "addressfamily"; "allowagentforwarding"; "allowgroups"; "allowstreamlocalforwarding"
          "allowtcpforwarding"; "allowusers"; "authenticationmethods"; "authorizedkeyscommand"; "authorizedkeyscommanduser"
          "authorizedkeysfile"; "authorizedprincipalscommand"; "authorizedprincipalscommanduser"; "authorizedprincipalsfile"
          "banner"; "chrootdirectory"; "ciphers"; "clientalivecountmax"; "clientaliveinterval"; "compression"
          "debianbanner"; "denygroups"; "denyusers"; "disableforwarding"; "exposeauthinfo"; "fingerprinthash"
          "forcecommand"; "gatewayports"; "gssapiauthentication"; "gssapicleanupcredentials"; "hostbasedacceptedalgorithms"
          "hostbasedauthentication"; "hostbasedusesnamefrompacketsonly"; "hostkey"; "hostkeyalgorithms"; "ignorehosts"
          "ignorerhosts"; "ignoreruserknownhosts"; "ignoreuserknownhosts"; "include"; "ipqos"; "kbdinteractiveauthentication"
          "kerberosauthentication"; "kexalgorithms"; "listenaddress"; "logingracetime"; "loglevel"; "macs"; "maxauthtries"
          "maxconnections"; "maxsessions"; "maxstartups"; "permitemptypasswords"; "permitlisten"; "permitopen"
          "permitrootlogin"; "permittty"; "permituserenvironment"; "permituserrc"; "pidfile"; "port"; "printedmotd"
          "pubkeyacceptedalgorithms"; "pubkeyauthentication"; "rekeylimit"; "revokedkeys"; "rdns"; "securitykeyprovider"
          "setenv"; "streamlocalbindmask"; "streamlocalbindunmask"; "strictmodes"; "subsystem"; "syslogfacility"
          "tcpkeepalive"; "trustedusercakeys"; "usedns"; "usepam"; "x11displayoffset"; "x11forwarding"; "x11uselocalhost" ]

let weakCipher (tok: string) =
    tok.Contains("cbc") || tok.Contains("arcfour") || tok.Contains("3des")

let weakKex (tok: string) =
    tok.Contains("sha1") || tok.Contains("group1") || tok.Contains("group-exchange-sha1")

let weakMac (tok: string) =
    tok.Contains("md5") || tok.Contains("-96") || tok = "hmac-sha1"

let auditSshdLine (where: string) (l: Line) : Finding list =
    let at = sprintf "%s:%d" where l.no
    match l.key with
    | "permitrootlogin" ->
        (match l.args |> Array.tryHead |> Option.map (fun a -> a.ToLowerInvariant()) with
         | Some "yes" -> [ watch "CFG_ROOT_ANY" 30 at "direct root login permitted" ]
         | Some "prohibit-password" -> [ note "CFG_ROOT_KEYONLY" at "root limited to key auth" ]
         | Some "forced-commands-only" -> [ note "CFG_ROOT_FC" at "root only via forced commands" ]
         | Some "no" -> [ note "CFG_ROOT_OFF" at "root login disabled" ]
         | _ -> [])
    | "permitemptypasswords" ->
        (match l.args |> Array.tryHead |> Option.map (fun a -> a.ToLowerInvariant()) with
         | Some "yes" -> [ hostile "CFG_EMPTY_PW" 60 at "empty passwords accepted" ]
         | _ -> [])
    | "passwordauthentication" ->
        (match l.args |> Array.tryHead |> Option.map (fun a -> a.ToLowerInvariant()) with
         | Some "yes" -> [ watch "CFG_PW_AUTH" 15 at "password auth enabled; brute-force surface" ]
         | Some "no" -> [ note "CFG_PW_OFF" at "password auth disabled" ]
         | _ -> [])
    | "authorizedkeysfile" ->
        if l.args |> Array.exists (fun a -> a.ToLowerInvariant() = "none") then
            [ note "CFG_AKF_NONE" at "authorized_keys lookup disabled" ]
        else
            let odd =
                l.args
                |> Array.filter (fun a ->
                    not (a.StartsWith(".ssh/")) && not (a.StartsWith("%h/.ssh/")))
            if odd.Length > 0 then
                [ suspect "CFG_AKF_ODD" 45 at ("keys read from unusual paths: " + String.concat " " odd) ]
            else []
    | "authorizedkeyscommand" ->
        if l.args.Length > 0 then
            [ watch "CFG_AKCMD" 25 at ("external command answers for keys: " + String.concat " " l.args) ]
        else []
    | "permituserenvironment" ->
        (match l.args |> Array.tryHead |> Option.map (fun a -> a.ToLowerInvariant()) with
         | Some "yes" -> [ suspect "CFG_USERENV" 45 at "user-controlled environment variables accepted" ]
         | _ -> [])
    | "ciphers" ->
        l.args |> Array.collect (fun a -> a.Split(','))
        |> Array.filter weakCipher
        |> Array.map (fun c -> watch "CFG_WEAK_CIPHER" 18 at ("weak cipher offered: " + c))
        |> Array.toList
    | "kexalgorithms" ->
        l.args |> Array.collect (fun a -> a.Split(','))
        |> Array.filter weakKex
        |> Array.map (fun k -> watch "CFG_WEAK_KEX" 18 at ("weak kex offered: " + k))
        |> Array.toList
    | "macs" ->
        l.args |> Array.collect (fun a -> a.Split(','))
        |> Array.filter weakMac
        |> Array.map (fun m -> watch "CFG_WEAK_MAC" 12 at ("weak mac offered: " + m))
        |> Array.toList
    | "x11forwarding" ->
        (match l.args |> Array.tryHead |> Option.map (fun a -> a.ToLowerInvariant()) with
         | Some "yes" -> [ watch "CFG_X11" 6 at "x11 forwarding on" ]
         | _ -> [])
    | "gatewayports" ->
        (match l.args |> Array.tryHead |> Option.map (fun a -> a.ToLowerInvariant()) with
         | Some "yes" | Some "clientspecified" -> [ watch "CFG_GATEWAY" 15 at "remote forwards bind non-loopback" ]
         | _ -> [])
    | "include" ->
        l.args
        |> Array.filter (fun a -> a.StartsWith("/") && not (a.StartsWith("/etc/ssh")))
        |> Array.map (fun a -> watch "CFG_INCLUDE_ODD" 30 at ("include pulls config from outside /etc/ssh: " + a))
        |> Array.toList
    | "trustedusercakeys" ->
        if l.args.Length > 0 then [ note "CFG_CAKEYS" at ("ca trust anchor: " + l.args.[0]) ] else []
    | "allowusers" | "allowgroups" ->
        if l.args.Length > 0 then [ note "CFG_ALLOWLIST" at (l.key + " pinning in place") ] else []
    | "port" | "listenaddress" -> [ note "CFG_LISTEN" at l.raw ]
    | "subsystem" -> [ note "CFG_SUBSYSTEM" at l.raw ]
    | "forcecommand" ->
        if l.args.Length > 0 then [ note "CFG_FORCECMD" at ("global forced command: " + String.concat " " l.args) ] else []
    | k when Set.contains k sshdKnown -> []
    | _ -> [ watch "CFG_UNKNOWN" 2 at ("unknown keyword; sshd would refuse to start: " + l.key) ]

let clientKnown =
    set [ "host"; "match"; "addkeystoagent"; "addressfamily"; "batchmode"; "bindaddress"; "bindinterface"; "canonicaldomains"
          "canonicalizefallbacklocal"; "canonicalizehostname"; "canonicalizemaxdots"; "canonicalizepermittedcnames"
          "cafile"; "certificatefile"; "challengeresponseauthentication"; "checkhostip"; "cipher"; "ciphers"; "compression"
          "compressionlevel"; "connectionattempts"; "connecttimeout"; "controlmaster"; "controlpath"; "controlpersist"
          "dynamicforward"; "enablesshkeysign"; "escapechar"; "exitonforwardfailure"; "fingerprinthash"; "forwardagent"
          "forwardx11"; "forwardx11timeout"; "forwardx11trusted"; "gatewayports"; "globalknownhostsfile"; "gssapiauthentication"
          "hashknownhosts"; "hostbasedauthentication"; "hostkeyalias"; "hostkeyalgorithms"; "hostbasedkeytypes"
          "hostname"; "hostnames"; "identitiesonly"; "identityagent"; "identityfile"; "ignoreunknown"; "include"
          "ipqos"; "kbdinteractiveauthentication"; "kbdinteractivedevices"; "kexalgorithms"; "localcommand"
          "localforward"; "loglevel"; "logverbose"; "macs"; "nohostauthenticationforlocalhost"; "numberofpasswordprompts"
          "passwordauthentication"; "permitlocalcommand"; "pkcs11provider"; "port"; "preferredauthentications"
          "proxycommand"; "proxyjump"; "proxyusefdpass"; "pubkeyacceptedalgorithms"; "pubkeyauthentication"
          "rekeylimit"; "remoteforward"; "requesttty"; "revokedhosts"; "securitykeyprovider"; "sendenv"; "serveralivecountmax"
          "serveraliveinterval"; "setenv"; "streamlocalbindmask"; "stricthostkeychecking"; "syslogfacility"; "tcpkeepalive"
          "tunnel"; "tunneldevice"; "updatehostkeys"; "user"; "userknownhostsfile"; "verifyhostkeydns"; "visualhostkey" ]

let auditClientLine (where: string) (l: Line) : Finding list =
    let at = sprintf "%s:%d" where l.no
    match l.key with
    | "stricthostkeychecking" ->
        (match l.args |> Array.tryHead |> Option.map (fun a -> a.ToLowerInvariant()) with
         | Some "no" -> [ suspect "CFG_STRICT_NO" 45 at "host key checking disabled; mitm is invisible" ]
         | Some "accept-new" -> [ watch "CFG_STRICT_ACCEPTNEW" 12 at "first-contact keys pinned automatically" ]
         | Some "yes" -> [ note "CFG_STRICT_YES" at "host keys pinned" ]
         | _ -> [])
    | "userknownhostsfile" ->
        if l.args |> Array.exists (fun a -> a = "/dev/null") then
            [ hostile "CFG_KNOWN_DEVNULL" 60 at "known hosts pointed at /dev/null; host pinning erased" ]
        else []
    | "forwardagent" ->
        (match l.args |> Array.tryHead |> Option.map (fun a -> a.ToLowerInvariant()) with
         | Some "yes" -> [ watch "CFG_FWDAGENT" 10 at "agent forwarding; remote host can ride local keys" ]
         | _ -> [])
    | "proxycommand" ->
        let cmd = String.concat " " l.args
        if cmd <> "" && (Skeleton.Authorized.netBits cmd || Skeleton.Authorized.metachars cmd) then
            [ watch "CFG_PROXY_ODD" 25 at ("proxy command pipes through a shell: " + cmd) ]
        else []
    | "hashknownhosts" ->
        (match l.args |> Array.tryHead |> Option.map (fun a -> a.ToLowerInvariant()) with
         | Some "yes" -> [ note "CFG_HASHKNOWN" at "known hosts hashed on write" ]
         | _ -> [])
    | "host" ->
        if l.args.Length > 0 then [ note "CFG_HOSTBLOCK" at ("host block: " + String.concat " " l.args) ] else []
    | "identityfile" ->
        if l.args.Length > 0 then [ note "CFG_IDFILE" at ("identity: " + l.args.[0]) ] else []
    | k when Set.contains k clientKnown -> []
    | _ -> [ watch "CFG_UNKNOWN_C" 2 at ("unknown client keyword: " + l.key) ]

let detectKind (lines: string[]) =
    let tokens = lines |> Array.choose tokenize |> Array.map (fun l -> l.key)
    let hasAny keys = tokens |> Array.exists (fun t -> Set.contains t keys)
    if hasAny (set [ "permitrootlogin"; "permitemptypasswords"; "authorizedkeysfile"; "authorizedkeyscommand"
                     "trustedusercakeys"; "allowagentforwarding"; "gatewayports"; "subsystem"; "maxauthtries" ]) then "sshd"
    elif hasAny (set [ "forwardagent"; "proxycommand"; "hashknownhosts"; "stricthostkeychecking"; "host" ]) then "client"
    else "sshd"

let auditFile (path: string) : Result<string * Finding list, string> =
    try
        let lines = IO.File.ReadAllLines path
        let kind = detectKind lines
        let numbered = lines |> Array.mapi (fun i l -> (i + 1, l))
        let parsed =
            numbered
            |> Array.choose (fun (no, raw) ->
                tokenize raw |> Option.map (fun l -> { l with no = no }))
        let audit = if kind = "sshd" then auditSshdLine else auditClientLine
        let findings = parsed |> Array.map (audit path) |> Array.toList |> List.concat
        Ok(kind, findings)
    with ex -> Error ex.Message
