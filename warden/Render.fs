module Skeleton.Render

open System
open Skeleton.Verdict

let version = "26.10.1"

type Theme =
    { hostile: string
      suspicious: string
      watch: string
      note: string
      good: string
      dim: string
      bold: string
      reset: string }

let plain =
    { hostile = ""; suspicious = ""; watch = ""; note = ""; good = ""; dim = ""; bold = ""; reset = "" }

let colorTheme =
    { hostile = "\u001b[1;31m"
      suspicious = "\u001b[33m"
      watch = "\u001b[36m"
      note = "\u001b[90m"
      good = "\u001b[32m"
      dim = "\u001b[90m"
      bold = "\u001b[1m"
      reset = "\u001b[0m" }

let mutable noColorGlobal = false

let themeFor (_noColor: bool) =
    let forced = Environment.GetEnvironmentVariable "SKELETON_FORCE_COLOR"
    if noColorGlobal || Environment.GetEnvironmentVariable("NO_COLOR") <> null then plain
    elif forced = "1" then colorTheme
    elif Console.IsOutputRedirected then plain
    else colorTheme

let symbol sev =
    match sev with
    | Hostile -> "\u25cf"       // ●
    | Suspicious -> "\u25c6"    // ◆
    | Watch -> "\u25cb"         // ○
    | Note -> "\u00b7"          // ·

let sevColor t sev =
    match sev with
    | Hostile -> t.hostile
    | Suspicious -> t.suspicious
    | Watch -> t.watch
    | Note -> t.note

let header (t: Theme) (cmd: string) =
    sprintf "%sskeleton %s%s — %s" t.bold version t.reset cmd

let rule (t: Theme) =
    if t = plain then "----------------------------------------------------------------------"
    else "\u001b[90m" + String.replicate 70 "\u2500" + "\u001b[0m"

let printFinding (t: Theme) (f: Finding) =
    let c = sevColor t f.sev
    printfn " %s%s%s %s%-18s%s %s%s%s  %s"
        c (symbol f.sev) t.reset t.bold f.id t.reset t.dim f.where t.reset f.note

let summary (t: Theme) (score: int) (forced: bool) =
    let band = bandName score forced
    let c =
        match band with
        | "hostile" -> t.hostile
        | "suspicious" -> t.suspicious
        | "watch" -> t.watch
        | _ -> t.good
    printfn "%s" (rule t)
    printfn " %sverdict: %s%s%s — score %d%s"
        t.bold c band t.reset score (if forced then " (forced)" else "")

let jsonEscape (s: string) =
    let sb = Text.StringBuilder()
    for c in s do
        match c with
        | '"' -> sb.Append "\\\"" |> ignore
        | '\\' -> sb.Append "\\\\" |> ignore
        | '\n' -> sb.Append "\\n" |> ignore
        | '\r' -> sb.Append "\\r" |> ignore
        | '\t' -> sb.Append "\\t" |> ignore
        | c when int c < 32 -> sb.Append(sprintf "\\u%04x" (int c)) |> ignore
        | c -> sb.Append c |> ignore
    sb.ToString()

let jsonFindings (cmd: string) (findings: Finding list) =
    let items =
        findings
        |> List.map (fun f ->
            sprintf
                "{\"id\":\"%s\",\"sev\":\"%s\",\"weight\":%d,\"where\":\"%s\",\"note\":\"%s\"}"
                (jsonEscape f.id)
                (sevName f.sev)
                f.weight
                (jsonEscape f.where)
                (jsonEscape f.note))
        |> String.concat ","
    let total, forced = Skeleton.Verdict.score findings
    sprintf
        "{\"tool\":\"skeleton\",\"version\":\"%s\",\"command\":\"%s\",\"score\":%d,\"band\":\"%s\",\"forced\":%s,\"count\":%d,\"findings\":[%s]}"
        version
        (jsonEscape cmd)
        total
        (bandName total forced)
        (if forced then "true" else "false")
        findings.Length
        items
