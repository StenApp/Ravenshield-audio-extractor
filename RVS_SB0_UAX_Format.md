# RavenShield Sound Extractor — Format-Dokumentation

## Übersicht

RavenShield verwendet das **DARE Audio Engine**-Format von Ubisoft.  
Sounds bestehen aus zwei Dateien:
- **UAX** (Unreal Audio Package) — enthält Event-Definitionen (DareEvent-Objekte)
- **SB0** (Sound Bank) — enthält die eigentlichen Audio-Daten

Das Spiel ruft UAX-Events auf → DareAudio spielt den zugehörigen SB0-Track ab.

---

## UAX-Format

Standard Unreal Engine 2 Package (.uax), aber mit proprietären DareEvent-Objekten.

### Package-Header (0x00)
| Offset | Typ   | Beschreibung         |
|--------|-------|----------------------|
| 0x00   | u32   | Magic: `0x9E2A83C1`  |
| 0x0C   | u32   | Anzahl Namen         |
| 0x10   | u32   | Offset Namen-Tabelle |
| 0x14   | u32   | Anzahl Exports       |
| 0x18   | u32   | Offset Export-Tabelle|

### Export-Eintrag
Felder werden mit **compact integer** kodiert (variable Länge):
```
class_idx, super_idx, package(u32), name_idx, flags(u32), size, offset
```

### DareEvent Payload (11 Bytes, kein UE2 Property-Stream)
```
[flags1:u8][flags2:u8][ref_lo:u8][ref_hi:u8][bank_lo:u8][bank_hi:u8][pad:5]
```
- `flags1`, `flags2`: 0x00 oder 0x01
- `full_rid = ((bank_hi<<8)|bank_lo)<<16 | ((ref_hi<<8)|ref_lo)`
- `full_rid` entspricht dem `s1_rid` in Section1 der SB0

### Event-Typen
- **Play_xxx**: Spielt Sound ab → für Export relevant
- **Stop_xxx**: Stoppt Sound → wird beim Matching ignoriert
- **Play_xxx_In/Out/Insert/Semi**: Adaptive Musik-Controller → N:1, kein eigener Track

---

## SB0-Format (fmt_tag = 0x0B für RVS)

### Header
| Offset | Typ | Beschreibung              |
|--------|-----|---------------------------|
| 0x00   | u32 | fmt_tag (0x0B)            |
| 0x04   | u32 | s1_num (= Version)        |
| 0x0C   | u32 | s2_num                    |
| 0x1C   | u32 | sX_size (SectionX Größe)  |
| 0x20   | —   | Beginn Section1           |

### Section1 (0x5C Bytes/Eintrag) — Event-Definitionen
| Offset | Typ | Beschreibung                    |
|--------|-----|---------------------------------|
| +0x00  | u32 | s1_rid (Resource-ID des Events) |
| +0x08  | u32 | s2_comp (Index in Section2)     |

### Section2 (0x7C Bytes/Eintrag) — Audio-Tracks
| Offset | Typ | Beschreibung              |
|--------|-----|---------------------------|
| +0x00  | u32 | rid (Resource-ID)         |
| +0x04  | u32 | etype (Entry-Typ)         |
| +0x08  | u32 | stream_size               |
| +0x10  | u32 | stream_offset             |
| +0x40  | u32 | sample_rate               |
| +0x46  | u16 | channels                  |
| +0x4C  | str | interner Dateiname (ASCII)|

### Section2 etype-Werte
| etype | Bedeutung                                  |
|-------|--------------------------------------------|
| 0x01  | TYPE_AUDIO — PCM oder SS0-Referenz         |
| 0x04  | GROUP — Zufalls-Pool (enthält AUDIO-Tracks)|
| 0x06  | TYPE_LAYER                                 |
| 0x08  | GROUP — wie 0x04                           |
| 0x0A  | GROUP/Sub-Pool                             |
| 0x0C  | GROUP/Sub-Pool                             |
| 0x0D  | TYPE_LAYER_OLD                             |
| 0x0F  | Placeholder/leer — kein Audio              |

### Audio-Typen (etype 0x01)
- Interner Name endet auf `.SS0` → Streaming-Audio (via vgmstream-cli)
- Sonst → internes PCM (direkt aus SB0-Daten als WAV exportierbar)

---

## UAX → SB0 Matching (build_rid_map)

`full_rid` aus UAX-Payload → `s1_rid` in Section1 → `s2_comp` → TYPE_AUDIO-Tracks

### Prioritäten

**Stop-Events überspringen:**  
Stop-rids aus UAX werden aus Section1 ausgefiltert — sie würden sonst
Methode C fälschlicherweise blockieren.

**Methode A** (s2_comp direkt TYPE_AUDIO):  
`s1_rid → [s2_comp]`  
Einfachster Fall, s2_comp ist bereits der Audio-Track.

**Methode C** (s2_comp ist GROUP):  
Sammle alle TYPE_AUDIO-Tracks ab s2_comp+1 bis zum nächsten s2_comp-Anker.  
- Stopp bei GROUP-Eintrag dessen Index in `s2_comps` ist (anderes Event)
- Stopp bei AUDIO-Track der s2_comp eines anderen (nicht-Stop) s1-Events ist  

**Direkt-Fallback** (wenn Methode C nichts findet):  
`s1_rid == s2.rid` → direkte rid-Übereinstimmung in Section2

### SB0-Typen und dominante Methode

| Typ         | Beispiel              | Methode      | Anmerkung                    |
|-------------|----------------------|--------------|------------------------------|
| Musik       | Music.SB0            | C + Direkt   | SS0-Tracks, Pool-Varianten   |
| Ambiences   | Ambiences_Airport1   | Direkt       | Ein SS0-Track, viele Events  |
| Voices      | Voices_Terro_German01| A            | PCM, jeder Track eigener s1  |
| Waffen      | Assault_AK47         | C            | PCM, GROUP mit 2 Varianten   |
| Common      | CommonSniper         | A + C        | Mix, Stop-Events beachten    |
| SFX         | SFX_Airport1         | A            | PCM, direkte s2_comp         |
| Foley       | Foley_NPC_Training   | C            | Große Pools, viele Varianten |
| Bullet SFX  | Bullet_Impacts       | C            | Ricochet-Varianten im Pool   |

### N:1-Kollisionen (mehrere UAX-Events → gleicher Track)
Bekannte Fälle in Music.SB0:
- `theme_Ambients`, `random_themes_Mystery` → gleicher Track wie `theme_Menu3_InGame`
- `Ambient1` → gleicher Track wie `theme_MissionVictory`
- `theme_ActionDanger1` → gleicher Track wie `theme_ActionUrgency1`

**Verhalten:** Erster Play-Event in UAX-Reihenfolge bekommt den Namen, Aliase werden ignoriert.

---

## vgmstream Subsong-Nummerierung

vgmstream zählt **alle** s2-Einträge mit `stream_size > 0` als Subsongs (sequenziell).  
Das umfasst auch GROUP-Einträge mit gültiger Größe.  
Unser `_vgm_subsong` bildet diese Nummerierung ab:  
`s2_vgm_rank[i]` = Position von s2[i] in der vollständigen vgmstream-Liste.

---

## Scanner-Logik

UAX als Anker im `sounds/`-Root.  
SB0-Suchpfad: `ger/` → `int/` → gleicher Ordner → `high/`

| Kategorie    | UAX-Ort     | SB0-Ort    |
|-------------|-------------|------------|
| Musik        | sounds/     | sounds/    |
| Ambiences    | sounds/     | sounds/    |
| SFX          | sounds/     | sounds/    |
| Voices       | sounds/     | sounds/ger/ oder int/ |
| Waffen       | sounds/     | sounds/high/ |
| Foley        | sounds/     | sounds/    |

Gilt gleichermaßen für RavenShield, AthenaSword und IronWrath.
