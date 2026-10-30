module Skeleton.Verdict

// every finding carries its own weight; banding is additive.
// weight >= 80 is a forced-hostile rule: the whole run floors to hostile.

type Severity =
    | Note
    | Watch
    | Suspicious
    | Hostile

type Finding =
    { id: string
      sev: Severity
      weight: int
      where: string
      note: string }

let sevName s =
    match s with
    | Note -> "note"
    | Watch -> "watch"
    | Suspicious -> "suspicious"
    | Hostile -> "hostile"

let bandName (score: int) (forced: bool) =
    if forced then "hostile"
    elif score >= 60 then "hostile"
    elif score >= 30 then "suspicious"
    elif score >= 10 then "watch"
    else "clean"

let exitCode (score: int) (forced: bool) =
    if forced then 3
    elif score >= 60 then 3
    elif score >= 30 then 2
    elif score >= 10 then 1
    else 0

let score (findings: Finding list) =
    let total = findings |> List.sumBy (fun f -> f.weight)
    let forced = findings |> List.exists (fun f -> f.weight >= 80)
    total, forced

let mk (id: string) (sev: Severity) (w: int) (where: string) (note: string) : Finding =
    { id = id; sev = sev; weight = w; where = where; note = note }

// convenience constructors used across instruments
let note id where note' = mk id Note 0 where note'
let watch id w where note' = mk id Watch w where note'
let suspect id w where note' = mk id Suspicious w where note'
let hostile id w where note' = mk id Hostile w where note'
