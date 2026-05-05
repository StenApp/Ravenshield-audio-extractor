#!/usr/bin/env python3
"""
Ravenshield Sound Extractor v6
Verifiziert gegen alle Beispieldateien.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import struct
import subprocess
import os
import re
from collections import Counter

# =============================================================================
# UAX Parser
# =============================================================================

def _read_compact(d, pos):
    b = d[pos]; pos += 1
    neg = bool(b & 0x80); val = b & 0x3F
    if b & 0x40:
        b = d[pos]; pos += 1; val |= (b & 0x7F) << 6
        if b & 0x80:
            b = d[pos]; pos += 1; val |= (b & 0x7F) << 13
            if b & 0x80:
                b = d[pos]; pos += 1; val |= (b & 0x7F) << 20
    return (-val if neg else val), pos


def parse_uax(path, rid_to_s2idx=None):
    """
    Parst eine UAX-Datei und gibt (direct_map, ordered_list) zurück.

    direct_map:   {section2_idx: event_name}
    ordered_list: [event_name, ...]  (alle Play-Events in UAX-Reihenfolge)

    rid_to_s2idx: {full_resource_id: section2_idx}
      Wenn übergeben, wird der full_rid aus dem Payload via Section1-Lookup
      auf den section2_idx gemappt.
      Wenn None, wird payload[2:4] direkt als section2_idx-Näherung benutzt.

    Payload-Format (11 Bytes):
      [flags1:u8][flags2:u8][ref_lo:u8][ref_hi:u8][bank_lo:u8][bank_hi:u8][pad:5]
      full_rid = ((bank_hi<<8)|bank_lo)<<16 | ((ref_hi<<8)|ref_lo)
    """
    if not path or not os.path.isfile(path):
        return {}, []

    with open(path, 'rb') as f:
        d = f.read()

    def u32(o): return int.from_bytes(d[o:o+4], 'little')
    def u16(o): return int.from_bytes(d[o:o+2], 'little')

    if u32(0) != 0x9E2A83C1:
        return {}, []

    name_cnt = u32(0x0C); name_off = u32(0x10)
    exp_cnt  = u32(0x14); exp_off  = u32(0x18)

    # Namen-Tabelle lesen
    names = []; pos = name_off
    for _ in range(name_cnt):
        slen = d[pos]; pos += 1
        if slen == 0:
            names.append(''); continue
        names.append(d[pos:pos+slen-1].decode('latin-1', errors='replace'))
        pos += slen + 4

    direct_map   = {}   # section2_idx -> name
    ordered_list = []   # alle Play-Event-Namen in Reihenfolge

    pos = exp_off
    for _ in range(exp_cnt):
        _, pos = _read_compact(d, pos)
        _, pos = _read_compact(d, pos)
        pos += 4
        ni,  pos = _read_compact(d, pos)
        pos += 4
        ss,  pos = _read_compact(d, pos)
        so,  pos = _read_compact(d, pos)

        name = names[ni] if 0 <= ni < len(names) else ''
        if name.lower().startswith('stop_'):
            continue
        clean = re.sub(r'^Play_', '', name, flags=re.IGNORECASE)
        ordered_list.append(clean)

        if ss < 6:
            continue

        payload = d[so:so+ss]
        # Payload scannen: suche [flags1][flags2][ref_lo][ref_hi][bank_lo][bank_hi]
        # flags1 und flags2 sind jeweils 0x00 oder 0x01
        p = 0
        while p + 6 <= len(payload):
            f1 = payload[p]; f2 = payload[p+1]
            if f1 in (0x00, 0x01) and f2 in (0x00, 0x01):
                ref  = payload[p+2] | (payload[p+3] << 8)
                bank = payload[p+4] | (payload[p+5] << 8)
                full_rid = (bank << 16) | ref

                if rid_to_s2idx is not None:
                    targets = rid_to_s2idx.get(full_rid)
                    if targets is not None:
                        if isinstance(targets, int):
                            targets = [targets]
                        for s2idx in targets:
                            existing = direct_map.get(s2idx)
                            if existing is None:
                                direct_map[s2idx] = clean
                            else:
                                # Play_theme_* hat immer Priorität
                                _is_theme = re.compile(r'^theme_', re.I)
                                _tech = re.compile(r'(_\d+dB|_In(_|$)|_Out(_|$)|_Insert|_Semi|_Trck\d|Fullin|OutinRoom|FromRoom|_Middle)', re.I)
                                if _is_theme.match(clean) and not _is_theme.match(existing):
                                    direct_map[s2idx] = clean
                                elif _tech.search(existing) and not _tech.search(clean) and not _is_theme.match(existing):
                                    direct_map[s2idx] = clean
                else:
                    if ref not in direct_map:
                        direct_map[ref] = clean
                p += 7  # 7 Bytes pro Referenz-Block
            elif payload[p] == 0x07:
                break
            else:
                p += 1

    return direct_map, ordered_list


def get_stop_rids(uax_path):
    """Gibt set von full_rids für Stop-Events aus UAX zurück."""
    if not uax_path or not os.path.isfile(uax_path):
        return set()
    with open(uax_path, 'rb') as f:
        d = f.read()
    def u32(o): return int.from_bytes(d[o:o+4], 'little')
    if u32(0) != 0x9E2A83C1:
        return set()
    nc=u32(0x0C); no=u32(0x10); ec=u32(0x14); eo=u32(0x18)
    names=[]; pos=no
    for _ in range(nc):
        slen=d[pos]; pos+=1
        if slen==0: names.append(''); continue
        names.append(d[pos:pos+slen-1].decode('latin-1','replace')); pos+=slen+4
    stop_rids=set(); pos=eo
    for _ in range(ec):
        _,pos=_read_compact(d,pos); _,pos=_read_compact(d,pos)
        pos+=4; ni,pos=_read_compact(d,pos); pos+=4
        ss,pos=_read_compact(d,pos); so,pos=_read_compact(d,pos)
        name=names[ni] if 0<=ni<len(names) else ''
        if not name.lower().startswith('stop_') or ss < 6: continue
        p=d[so:so+11]
        ref=p[2]|(p[3]<<8); bank=p[4]|(p[5]<<8)
        stop_rids.add((bank<<16)|ref)
    return stop_rids

_TYPE_AUDIO     = 0x01
_TYPE_LAYER     = 0x06
_TYPE_LAYER_OLD = 0x0D
_VALID_ETYPES   = (_TYPE_AUDIO, _TYPE_LAYER, _TYPE_LAYER_OLD)


def _u32(d, o): return int.from_bytes(d[o:o+4], 'little')
def _u16(d, o): return int.from_bytes(d[o:o+2], 'little')


def _sb0_str(d, o, maxlen=64):
    chunk = d[o:o+maxlen]
    end   = chunk.find(0)
    raw   = chunk[:end] if end >= 0 else chunk
    return raw.decode('latin-1', errors='replace').strip()


def _sb0_header(data):
    """
    Liest SB0-Header. Alle RVS-SB0s haben fmt_tag=0x0B.
    Gibt (s1_num, s2_num, s1_off, s2_off, sX_off, sX_size, audio_base, version) zurück.
    """
    fmt_tag = _u32(data, 0x00)
    if fmt_tag <= 0x0B:
        s1_num  = _u32(data, 0x04)   # = version
        s2_num  = _u32(data, 0x0C)
        sX_size = _u32(data, 0x1C)
        s1_off  = 0x20
    elif fmt_tag <= 0x0A0000:
        s1_num  = _u32(data, 0x04)
        s2_num  = _u32(data, 0x08)
        sX_size = _u32(data, 0x10)
        s1_off  = 0x18
    else:
        s1_num  = _u32(data, 0x04)
        s2_num  = _u32(data, 0x08)
        sX_size = _u32(data, 0x10)
        s1_off  = 0x1C

    S1 = 0x5C; S2 = 0x7C
    s2_off  = s1_off + s1_num * S1
    sX_off  = s2_off + s2_num * S2
    audio_base = sX_off + sX_size  # Basis für interne PCM-Offsets

    version = _u32(data, 0x04)  # = s1_num für RVS
    return s1_num, s2_num, s1_off, s2_off, sX_off, sX_size, audio_base, version


def parse_sb0(path):
    """
    Parst SB0, gibt Track-Liste zurück.
    Jeder Track hat mindestens: type, section2_idx, _resource_id,
    internal_name, name, sample_rate, channels, bits, num_samples.
    """
    with open(path, 'rb') as f:
        data = f.read()

    filesize = len(data)
    s1_num, s2_num, s1_off, s2_off, sX_off, sX_size, audio_base, version = \
        _sb0_header(data)

    # Voices erkennen: liegen in ger/ oder int/, oder Name beginnt mit 'voice'
    sb0_name = os.path.basename(path).lower()
    sb0_dir  = os.path.basename(os.path.dirname(path)).lower()
    is_voice = sb0_dir in ('ger', 'int') or sb0_name.startswith('voice')
    sr_override = 16000 if is_voice else None

    # audio_base sanity check
    if audio_base > filesize:
        # Berechne aus echten Offsets
        max_end = 0
        for i in range(s2_num):
            eb = s2_off + i * 0x7C
            if eb + 0x7C > filesize: break
            if _u32(data, eb+4) != _TYPE_AUDIO: continue
            rel = _u32(data, eb+0x10); sz = _u32(data, eb+0x08)
            if rel < 0xF0000000 and sz > 0:
                max_end = max(max_end, rel + sz)
        audio_base = filesize - max_end if max_end else filesize

    tracks = []

    # vgmstream zählt ALLE s2-Einträge mit ss>0 als Subsongs (nicht nur TYPE_AUDIO)
    # Vorberechnung: s2_idx -> vgm_subsong
    s2_vgm_rank = {}
    vgm_counter = 0
    for i in range(s2_num):
        eb = s2_off + i * 0x7C
        if eb + 0x7C > filesize: break
        ss = _u32(data, eb + 0x08)
        if ss == 0: continue
        vgm_counter += 1
        s2_vgm_rank[i] = vgm_counter

    vgm_rank = 0  # für Layer-Tracks die keinen eigenen s2_idx haben

    for i in range(s2_num):
        eb = s2_off + i * 0x7C
        if eb + 0x7C > filesize:
            break

        etype = _u32(data, eb + 0x04)
        rid   = _u32(data, eb + 0x00)

        # ── TYPE_AUDIO ────────────────────────────────────────────────────
        if etype == _TYPE_AUDIO:
            stream_size   = _u32(data, eb + 0x08)
            stream_offset = _u32(data, eb + 0x10)
            num_samples   = _u32(data, eb + 0x2C)
            sample_rate   = _u32(data, eb + 0x40)
            channels      = _u16(data, eb + 0x46) or 1
            stream_name   = _sb0_str(data, eb + 0x4C)

            if stream_size == 0 or stream_offset >= 0xF0000000:
                continue

            if stream_name.upper().endswith('.SS0'):
                tracks.append({
                    'type':          'ss0',
                    'section2_idx':  i,
                    '_resource_id':  rid,
                    '_vgm_subsong':  s2_vgm_rank.get(i, 0),
                    'internal_name': stream_name,
                    'name':          '',
                    'ss0_file':      stream_name,
                    'ss0_offset':    stream_offset,
                    'byte_size':     stream_size,
                    'sample_rate':   sample_rate or 44100,
                    'channels':      channels,
                    'bits':          16,
                    'num_samples':   num_samples,
                })
                continue

            # Internes PCM
            data_offset = audio_base + stream_offset
            available   = max(0, filesize - data_offset)
            byte_size   = min(stream_size, available)
            if byte_size == 0:
                continue

            if sr_override:
                sample_rate = sr_override

            tracks.append({
                'type':          'pcm',
                'section2_idx':  i,
                '_resource_id':  rid,
                '_vgm_subsong':  s2_vgm_rank.get(i, 0),
                'internal_name': stream_name,
                'name':          '',
                'byte_size':     byte_size,
                'num_samples':   byte_size // (channels * 2),
                'sample_rate':   sample_rate or 22050,
                'channels':      channels,
                'bits':          16,
                'data_offset':   data_offset,
                '_sb0_data':     data,
            })

        # ── TYPE_LAYER / TYPE_LAYER_OLD ───────────────────────────────────
        elif etype in (_TYPE_LAYER, _TYPE_LAYER_OLD):
            layer_count   = _u32(data, eb + 0x20)
            stream_size   = _u32(data, eb + 0x08) if etype == _TYPE_LAYER_OLD \
                            else _u32(data, eb + 0x60)
            stream_offset = _u32(data, eb + 0x58)
            stream_name   = _sb0_str(data, eb + 0x30)

            if stream_size == 0 or stream_offset >= 0xF0000000:
                continue

            # Sub-Header in sectionX für SR/CH/NS
            extra_off = _u32(data, eb + 0x0C)
            layer_sr = 44100; layer_ch = 2; layer_ns = 0
            if extra_off < sX_size and sX_off + extra_off + 0x14 <= filesize:
                sub      = sX_off + extra_off
                layer_sr = _u32(data, sub + 0x00) or 44100
                layer_ch = _u16(data, sub + 0x06) or 2
                layer_ns = _u32(data, sub + 0x10)

            tracks.append({
                'type':          'ss0',
                'section2_idx':  i,
                '_resource_id':  rid,
                '_etype':        etype,
                '_vgm_subsong':  s2_vgm_rank.get(i, 0),
                'internal_name': stream_name,
                'name':          '',
                'ss0_file':      stream_name,
                'ss0_offset':    stream_offset,
                'byte_size':     stream_size,
                'sample_rate':   layer_sr,
                'channels':      layer_ch * (layer_count or 1),
                'layer_count':   layer_count,
                'bits':          16,
                'num_samples':   layer_ns,
            })

        # ── 0x0C ADPCM Container (z.B. Ambiences_Island2) ────────────────
        elif etype == 0x0C:
            stream_size   = _u32(data, eb + 0x08)
            stream_offset = _u32(data, eb + 0x10)
            sr_raw        = _u32(data, eb + 0x40)
            # Nur valide ADPCM-Container: sr=0xFFFF0000 sind reine Controller
            if stream_size == 0 or stream_offset >= 0xF0000000 or sr_raw == 0xFFFF0000:
                continue
            tracks.append({
                'type':          'ss0',
                'section2_idx':  i,
                '_resource_id':  rid,
                '_etype':        etype,
                '_vgm_subsong':  s2_vgm_rank.get(i, 0),
                'internal_name': '',
                'name':          '',
                'ss0_file':      '',
                'ss0_offset':    stream_offset,
                'byte_size':     stream_size,
                'sample_rate':   44100,
                'channels':      4,
                'bits':          16,
                'num_samples':   0,
            })

    return tracks


# =============================================================================
# rid_map aufbauen: Section1 → UAX-RID → section2_idx
# =============================================================================

def build_rid_map(sb0_path, stop_rids=None):
    """
    Baut {full_rid: [section2_idx, ...]}

    stop_rids: set van s1_rids die Stop-events zijn (uit UAX) — worden
               uitgesloten van method_a_comp_to_s1 zodat ze Methode C
               niet blokkeren.
    """
    try:
        with open(sb0_path, 'rb') as f:
            d = f.read()
    except OSError:
        return {}

    s1_num, s2_num, s1_off, s2_off, *_ = _sb0_header(d)
    S1 = 0x5C; S2 = 0x7C

    s2_info = {}
    for i in range(s2_num):
        base = s2_off + i * S2
        if base + 8 <= len(d):
            s2_info[i] = (_u32(d, base), _u32(d, base + 4))

    # s2.rid → [idx] für TYPE_AUDIO (direkt-Match)
    s2_rid_to_idxs = {}
    for idx, (rid, etype) in s2_info.items():
        if etype == _TYPE_AUDIO:
            s2_rid_to_idxs.setdefault(rid, []).append(idx)

    s1_entries = []; s2_comps = set()
    for i in range(s1_num):
        base    = s1_off + i * S1
        s1_rid  = _u32(d, base)
        s2_comp = _u32(d, base + 8)
        s1_entries.append((s1_rid, s2_comp))
        # s2_comps nur für nicht-Stop-Events befüllen
        if stop_rids is None or s1_rid not in stop_rids:
            s2_comps.add(s2_comp)

    method_a_rids = {sr for sr, sc in s1_entries
                     if s2_info.get(sc, (0,0))[1] == _TYPE_AUDIO}

    # s2_comp → s1_rid mapping voor Methode A events (excl. Stop-events)
    method_a_comp_to_s1 = {sc: sr for sr, sc in s1_entries
                            if s2_info.get(sc, (0,0))[1] == _TYPE_AUDIO
                            and (stop_rids is None or sr not in stop_rids)}

    rid_map = {}

    for s1_rid, s2_comp in s1_entries:
        # Stop-events komplett überspringen
        if stop_rids and s1_rid in stop_rids:
            continue

        comp_etype = s2_info.get(s2_comp, (0, 0))[1]

        # Methode A: s2_comp direkt TYPE_AUDIO
        if comp_etype == _TYPE_AUDIO:
            rid_map[s1_rid] = [s2_comp]
            continue

        # s2_comp ist eine GROUP → Methode C zuerst, dann Direkt als Fallback
        # Methode C: alle TYPE_AUDIO-Tracks im Block bis zum nächsten s2_comp-Anker
        audio = []
        for nb in range(s2_comp + 1, s2_num):
            nb_rid, nb_etype = s2_info.get(nb, (0, 0))
            if nb_etype in (_TYPE_AUDIO, _TYPE_LAYER, _TYPE_LAYER_OLD):
                # AUDIO/LAYER: stopp nur wenn s2_comp eines anderen s1-Events
                if nb in method_a_comp_to_s1 and method_a_comp_to_s1[nb] != s1_rid:
                    break
                audio.append(nb)
            else:
                # GROUP: stopp bei s2_comp-Anker eines anderen s1-Eintrags
                if nb in s2_comps and nb != s2_comp:
                    break
        if audio:
            rid_map[s1_rid] = audio
            continue

        # Direkt: s1_rid == s2.rid (Fallback wenn Methode C nichts findet)
        if s1_rid in s2_rid_to_idxs:
            rid_map[s1_rid] = s2_rid_to_idxs[s1_rid]

    return rid_map


# =============================================================================
# UAX-Namen auf Tracks anwenden
# =============================================================================

def _apply_uax_names(tracks, uax_result, sb0_path):
    """
    Wendet UAX-Namen auf Tracks an.

    direct_map: {section2_idx: event_name}  (von parse_uax via rid_map)
    Für jeden UAX-Event können mehrere Tracks existieren (m/f Varianten).
    Diese bekommen alle denselben Basisnamen, Varianten erhalten _1/_2 Suffix.
    """
    direct_map, ordered_list = uax_result if isinstance(uax_result, tuple) \
        else (uax_result, [])

    pcm_tracks = [t for t in tracks if t['type'] == 'pcm']
    ss0_tracks = [t for t in tracks if t['type'] == 'ss0']

    # N:1-Schutz: ordered_list-Fallback nur wenn Events ≤ Tracks
    use_ordered_fallback = len(ordered_list) <= len(pcm_tracks) * 1.5

    # Hauptthema für SS0
    main_theme = ''
    for n in ordered_list:
        if not any(x in n.lower() for x in ('insert', '_in', '_out', 'semi')):
            main_theme = n; break

    sb0_base = os.path.splitext(os.path.basename(sb0_path))[0]

    for t in tracks:
        idx   = t['section2_idx']
        iname = os.path.splitext(t['internal_name'])[0]

        # 1. Exakter Match über direct_map (section2_idx → name)
        uname = direct_map.get(idx, '')

        if not uname:
            if t['type'] == 'ss0':
                if len(ss0_tracks) == 1 and main_theme:
                    uname = main_theme
                else:
                    rank = ss0_tracks.index(t) + 1
                    uname = f'{sb0_base}_{rank:02d}'
            # PCM ohne Match → interner Name (keine ordered_list-Spekulation)

        t['name'] = uname or iname or f'track_{idx}'

    # Varianten-Suffix bei Namens-Kollisionen
    name_count = Counter(t['name'] for t in tracks)
    name_seen  = {}
    for t in tracks:
        n = t['name']
        if name_count[n] > 1:
            name_seen[n] = name_seen.get(n, 0) + 1
            t['name'] = f'{n}_{name_seen[n]}'


# =============================================================================
# WAV Writer
# =============================================================================

def _wav_header(num_samples, sample_rate, channels, bits):
    ba = channels * (bits // 8)
    ds = num_samples * ba
    h  = struct.pack('<4sI4s', b'RIFF', 36 + ds, b'WAVE')
    h += struct.pack('<4sIHHIIHH', b'fmt ', 16, 1,
                     channels, sample_rate, sample_rate * ba, ba, bits)
    h += struct.pack('<4sI', b'data', ds)
    return h


def write_pcm_wav(track, out_path):
    data = track['_sb0_data']
    pcm  = data[track['data_offset']:track['data_offset'] + track['byte_size']]
    hdr  = _wav_header(track['num_samples'], track['sample_rate'],
                       track['channels'], track['bits'])
    with open(out_path, 'wb') as f:
        f.write(hdr); f.write(pcm)


def _find_vgmstream():
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ('vgmstream-cli.exe', 'vgmstream-cli', 'vgmstream_cli.exe'):
        p = os.path.join(here, name)
        if os.path.isfile(p):
            return p
    return None


def decode_and_write_wav(track, ss0_path, out_path):
    """Exportiert SS0-Track als WAV via vgmstream-cli."""
    vgm = _find_vgmstream()
    if not vgm:
        raise FileNotFoundError(tr("dlg_novgm_msg"))

    sb0_path = track.get('_sb0_path', '')
    subsong  = track.get('_vgm_subsong', 1)

    result = subprocess.run(
        [vgm, '-s', str(subsong), '-o', out_path, sb0_path],
        capture_output=True, timeout=60
    )
    if result.returncode != 0 or not os.path.isfile(out_path):
        raise RuntimeError(result.stderr.decode(errors='replace')[:300])


# =============================================================================
# Scanner
# =============================================================================

def scan_sounds_folder(folder, use_sb0_names=False):
    """
    UAX als Anker im sounds/-Root.
    SB0 in: ger/ → int/ → gleicher Ordner → high/
    SS0 immer neben UAX.
    """
    # UAX sammeln — nur Root + eine Ebene tiefer
    uax_files = {}
    search_dirs = [folder]
    try:
        search_dirs += [os.path.join(folder, d)
                        for d in os.listdir(folder)
                        if os.path.isdir(os.path.join(folder, d))]
    except OSError:
        pass

    for sdir in search_dirs:
        try:
            for fn in os.listdir(sdir):
                if fn.lower().endswith('.uax'):
                    bl = os.path.splitext(fn)[0].lower()
                    if bl not in uax_files:
                        uax_files[bl] = os.path.join(sdir, fn)
        except OSError:
            pass

    categories = []

    for base_low, uax_path in sorted(uax_files.items()):
        uax_dir  = os.path.dirname(uax_path)
        fn_sb0   = base_low + '.sb0'
        sb0_path = None

        for cdir in (
            os.path.join(uax_dir, 'ger'),
            os.path.join(uax_dir, 'int'),
            uax_dir,
            os.path.join(uax_dir, 'high'),
        ):
            candidate = os.path.join(cdir, fn_sb0)
            if os.path.isfile(candidate):
                sb0_path = candidate; break

        if not sb0_path:
            continue

        try:
            tracks = parse_sb0(sb0_path)
        except Exception as e:
            print(f'parse_sb0 Fehler {sb0_path}: {e}')
            continue

        if not tracks:
            continue

        # UAX→Track-Matching (überspringen wenn SB0-Namen gewünscht)
        if not use_sb0_names:
            rid_map    = build_rid_map(sb0_path, stop_rids=get_stop_rids(uax_path))
            uax_result = parse_uax(uax_path, rid_map)
            _apply_uax_names(tracks, uax_result, sb0_path)
        else:
            # SB0-Namen-Modus:
            # PCM → interner Dateiname (eindeutig, z.B. AK47_1a)
            # SS0 → sb0_basename_01/02/... (STREAM.SS0 wäre nichtssagend)
            sb0_base = os.path.splitext(os.path.basename(sb0_path))[0]
            ss0_tracks = [t for t in tracks if t['type'] == 'ss0']
            ss0_counter = {}
            for t in tracks:
                if t['type'] == 'pcm':
                    t['name'] = os.path.splitext(t['internal_name'])[0] or f'track_{t["section2_idx"]}'
                else:
                    # SS0: eindeutiger interner Name? Sonst sb0_basename+index
                    iname = os.path.splitext(t['internal_name'])[0]
                    generic = iname.upper() in ('STREAM', 'HD_MUSIC', 'MUSIC', '')
                    if generic or len(ss0_tracks) > 1:
                        n = len(ss0_counter) + 1
                        ss0_counter[t['section2_idx']] = n
                        t['name'] = f'{sb0_base}_{n:02d}'
                    else:
                        t['name'] = iname

        for t in tracks:
            t['_sb0_path'] = sb0_path
            t['_ss0_dir']  = uax_dir

        rel = os.path.relpath(sb0_path, folder)
        categories.append({
            'name':   rel,
            'sb0':    sb0_path,
            'tracks': tracks,
        })

    return categories


# =============================================================================
# Mehrsprachigkeit
# =============================================================================

LANG = {
    'de': {
        'title':         'Ravenshield Sound Extractor',
        'btn_folder':    'Ordner waehlen...',
        'btn_all':       'Alle auswaehlen',
        'btn_none':      'Keine auswaehlen',
        'btn_export':    'Exportieren',
        'btn_lang':      '🇬🇧 EN',
        'lbl_no_folder': 'Kein Ordner gewaehlt',
        'lbl_filter':    'Filter:',
        'lbl_type':      '  Typ:',
        'chk_sb0':       'SB0-Namen verwenden',
        'type_all':      'Alle',
        'type_pcm':      'PCM',
        'type_ss0':      'SS0 (Musik/Ambience)',
        'col_cat':       '  Kategorie / Asset',
        'col_typ':       'Typ',
        'col_name':      'Asset-Name',
        'col_dur':       'Dauer',
        'col_hz':        'Hz',
        'col_ch':        'Ch',
        'status_ready':  'Bereit.',
        'status_scan':   'Scanne...',
        'status_sel':    '{n} Tracks ausgewaehlt.',
        'status_tracks': '{t} Tracks in {c} Kategorien.',
        'status_export': 'Exportiere... {ok} OK, {err} Fehler',
        'status_done':   'Export: {ok} OK, {err} Fehler  ->  {dir}',
        'status_abort':  'Export abgebrochen.',
        'dlg_folder':    'sounds/-Ordner waehlen',
        'dlg_output':    'Ausgabeordner waehlen',
        'dlg_export_title': 'Export',
        'dlg_export_msg':   '{ok} Track(s) exportiert.\n{err} Fehler.\n\nAusgabe: {dir}',
        'dlg_nosel':     'Keine Tracks ausgewaehlt.',
        'dlg_novgm_title': 'vgmstream-cli nicht gefunden',
        'dlg_novgm_msg': 'SS0-Tracks koennen nicht exportiert werden.\n\nvgmstream-cli.exe neben die .py-Datei legen:\nhttps://github.com/vgmstream/vgmstream/releases',
        'tracks':        '{n} Tracks',
    },
    'en': {
        'title':         'Ravenshield Sound Extractor',
        'btn_folder':    'Choose folder...',
        'btn_all':       'Select all',
        'btn_none':      'Select none',
        'btn_export':    'Export',
        'btn_lang':      '🇩🇪 DE',
        'lbl_no_folder': 'No folder selected',
        'lbl_filter':    'Filter:',
        'lbl_type':      '  Type:',
        'chk_sb0':       'Use SB0 names',
        'type_all':      'All',
        'type_pcm':      'PCM',
        'type_ss0':      'SS0 (Music/Ambience)',
        'col_cat':       '  Category / Asset',
        'col_typ':       'Type',
        'col_name':      'Asset Name',
        'col_dur':       'Duration',
        'col_hz':        'Hz',
        'col_ch':        'Ch',
        'status_ready':  'Ready.',
        'status_scan':   'Scanning...',
        'status_sel':    '{n} tracks selected.',
        'status_tracks': '{t} tracks in {c} categories.',
        'status_export': 'Exporting... {ok} OK, {err} errors',
        'status_done':   'Export: {ok} OK, {err} errors  ->  {dir}',
        'status_abort':  'Export aborted.',
        'dlg_folder':    'Choose sounds/ folder',
        'dlg_output':    'Choose output folder',
        'dlg_export_title': 'Export',
        'dlg_export_msg':   '{ok} track(s) exported.\n{err} errors.\n\nOutput: {dir}',
        'dlg_nosel':     'No tracks selected.',
        'dlg_novgm_title': 'vgmstream-cli not found',
        'dlg_novgm_msg': 'SS0 tracks cannot be exported.\n\nPlace vgmstream-cli.exe next to the .py file:\nhttps://github.com/vgmstream/vgmstream/releases',
        'tracks':        '{n} Tracks',
    },
}

_current_lang = 'de'

def tr(key, **kw):
    s = LANG[_current_lang].get(key, key)
    return s.format(**kw) if kw else s

class RVSExtractor:
    def __init__(self, root):
        self.root = root
        root.geometry("960x680")
        root.resizable(True, True)
        self.categories = []
        self.check_vars = {}
        self._current_folder = None
        self._build_ui()

    def _build_ui(self):
        global _current_lang
        self.root.title(tr('title'))

        tb = tk.Frame(self.root, pady=4, padx=6)
        tb.pack(fill='x')
        self.btn_folder = tk.Button(tb, text=tr('btn_folder'),
                                     command=self._choose_folder, width=16)
        self.btn_folder.pack(side='left', padx=2)
        self.btn_all = tk.Button(tb, text=tr('btn_all'),
                                  command=self._select_all, width=14)
        self.btn_all.pack(side='left', padx=2)
        self.btn_none = tk.Button(tb, text=tr('btn_none'),
                                   command=self._select_none, width=14)
        self.btn_none.pack(side='left', padx=2)
        self.btn_export = tk.Button(tb, text=tr('btn_export'),
                                     command=self._export,
                                     width=12, bg='#2E7D32', fg='white')
        self.btn_export.pack(side='left', padx=8)
        self.btn_lang = tk.Button(tb, text=tr('btn_lang'),
                                   command=self._toggle_lang, width=6)
        self.btn_lang.pack(side='right', padx=4)
        self.lbl_folder = tk.Label(tb, text=tr('lbl_no_folder'),
                                    fg='gray', anchor='w')
        self.lbl_folder.pack(side='left', fill='x', expand=True, padx=4)

        fbar = tk.Frame(self.root, padx=6)
        fbar.pack(fill='x')
        self.lbl_filter = tk.Label(fbar, text=tr('lbl_filter'))
        self.lbl_filter.pack(side='left')
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add('write', lambda *_: self._apply_filter())
        tk.Entry(fbar, textvariable=self.filter_var,
                 width=30).pack(side='left', padx=4)
        self.lbl_type = tk.Label(fbar, text=tr('lbl_type'))
        self.lbl_type.pack(side='left')
        self.type_var = tk.StringVar(value=tr('type_all'))
        self.opt_type = tk.OptionMenu(fbar, self.type_var,
                      tr('type_all'), tr('type_pcm'), tr('type_ss0'),
                      command=lambda _: self._apply_filter())
        self.opt_type.pack(side='left')
        self.use_sb0_names = tk.BooleanVar(value=False)
        self.chk_sb0 = tk.Checkbutton(fbar, text=tr('chk_sb0'),
                       variable=self.use_sb0_names,
                       command=self._rescan)
        self.chk_sb0.pack(side='left', padx=10)

        frame = tk.Frame(self.root)
        frame.pack(fill='both', expand=True, padx=6, pady=4)
        cols = ('sel', 'typ', 'name', 'dauer', 'hz', 'ch')
        self.tree = ttk.Treeview(frame, columns=cols,
                                  show='tree headings', selectmode='none')
        self.tree.heading('#0',    text='  '+tr('col_cat'))
        self.tree.heading('sel',   text='✓')
        self.tree.heading('typ',   text=tr('col_typ'))
        self.tree.heading('name',  text=tr('col_name'))
        self.tree.heading('dauer', text=tr('col_dur'))
        self.tree.heading('hz',    text=tr('col_hz'))
        self.tree.heading('ch',    text=tr('col_ch'))
        self.tree.column('#0',    width=280, stretch=True)
        self.tree.column('sel',   width=28,  stretch=False, anchor='c')
        self.tree.column('typ',   width=55,  stretch=False)
        self.tree.column('name',  width=240, stretch=True)
        self.tree.column('dauer', width=65,  stretch=False, anchor='e')
        self.tree.column('hz',    width=55,  stretch=False, anchor='e')
        self.tree.column('ch',    width=30,  stretch=False, anchor='c')
        vsb = ttk.Scrollbar(frame, orient='vertical',   command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        self.tree.bind('<Button-1>', self._on_click)

        self.status = tk.Label(self.root, text=tr("status_ready"), anchor='w',
                               relief='sunken', padx=4)
        self.status.pack(fill='x', side='bottom')
        self.progress = ttk.Progressbar(self.root, mode='determinate')

    def _toggle_lang(self):
        global _current_lang
        _current_lang = 'en' if _current_lang == 'de' else 'de'
        # UI neu aufbauen
        for w in self.root.winfo_children():
            w.destroy()
        self._build_ui()
        # Zustand wiederherstellen
        if self._current_folder:
            self.lbl_folder.config(text=self._current_folder, fg='black')
            self._populate_tree()
        self.status.config(text=tr('status_ready'))

    def _choose_folder(self):
        folder = filedialog.askdirectory(title=tr("dlg_folder"))
        if not folder: return
        self._current_folder = folder
        self.lbl_folder.config(text=folder, fg='black')
        self._do_scan(folder)

    def _rescan(self):
        folder = getattr(self, '_current_folder', None)
        if folder:
            self._do_scan(folder)

    def _do_scan(self, folder):
        self.status.config(text=tr("status_scan"))
        self.tree.delete(*self.tree.get_children())
        self.check_vars.clear()
        threading.Thread(target=self._scan_thread, args=(folder,),
                         daemon=True).start()

    def _scan_thread(self, folder):
        use_sb0 = getattr(self, 'use_sb0_names', None)
        use_sb0 = use_sb0.get() if use_sb0 else False
        cats = scan_sounds_folder(folder, use_sb0_names=use_sb0)
        self.categories = cats
        self.root.after(0, self._populate_tree)

    def _populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.check_vars.clear()
        total = 0
        for cat in self.categories:
            tracks = cat['tracks']
            if not tracks: continue
            cat_var = tk.BooleanVar(value=False)
            cat_iid = self.tree.insert('', 'end',
                text=f'{cat["name"]}  (' + tr("tracks", n=len(tracks)) + ')',
                values=('', '', '', '', '', ''), tags=('cat',))
            self.check_vars[cat_iid] = (cat_var, 'cat', cat)
            for t in tracks:
                t_var = tk.BooleanVar(value=False)
                t_iid = self.tree.insert(cat_iid, 'end',
                    text=f'  {t["internal_name"]}',
                    values=('', 'SS0' if t['type'] == 'ss0' else 'PCM',
                            t['name'], self._fmt_dur(t),
                            t['sample_rate'], t['channels']))
                self.check_vars[t_iid] = (t_var, 'track', t)
                total += 1
        self.tree.tag_configure('cat', background='#E8EAF6')
        # Alle Kategorien aufklappen
        for iid in self.tree.get_children():
            self.tree.item(iid, open=True)
        self.status.config(
            text=tr("status_tracks", t=total, c=len(self.categories)))

    def _set_sel(self, iid, val):
        sym = '✓' if val else ''
        vals = list(self.tree.item(iid, 'values'))
        if vals: vals[0] = sym
        self.tree.item(iid, values=vals)

    def _on_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid or iid not in self.check_vars: return
        var, kind, obj = self.check_vars[iid]
        new_val = not var.get(); var.set(new_val)
        self._set_sel(iid, new_val)
        if kind == 'cat':
            for child in self.tree.get_children(iid):
                if child in self.check_vars:
                    cv, ck, co = self.check_vars[child]
                    cv.set(new_val)
                    self._set_sel(child, new_val)
        self._update_status_count()

    def _update_status_count(self):
        sel = sum(1 for _, (v,k,_) in self.check_vars.items()
                  if k=='track' and v.get())
        self.status.config(text=tr("status_sel", n=sel))

    def _select_all(self):  self._set_all(True)
    def _select_none(self): self._set_all(False)

    def _set_all(self, val):
        for iid, (v,k,_) in self.check_vars.items():
            v.set(val)
            self._set_sel(iid, val)
        self._update_status_count()

    def _apply_filter(self):
        txt = self.filter_var.get().lower()
        typ = self.type_var.get()
        self.tree.delete(*self.tree.get_children())
        self.check_vars.clear()
        for cat in self.categories:
            cat_lower = cat['name'].lower()
            filtered = []
            for t in cat['tracks']:
                if typ == 'PCM' and t['type'] != 'pcm': continue
                if typ == 'SS0 (Musik/Ambience)' and t['type'] != 'ss0': continue
                if txt and txt not in t['name'].lower() \
                       and txt not in t['internal_name'].lower() \
                       and txt not in cat_lower:
                    continue
                filtered.append(t)
            if not filtered: continue
            cat_var = tk.BooleanVar(value=False)
            cat_iid = self.tree.insert('', 'end',
                text=f'{cat["name"]}  (' + tr("tracks", n=len(filtered)) + ')',
                values=('','','','',''), tags=('cat',))
            self.check_vars[cat_iid] = (cat_var, 'cat', cat)
            for t in filtered:
                t_var = tk.BooleanVar(value=False)
                t_iid = self.tree.insert(cat_iid, 'end',
                    text=f'  {t["internal_name"]}',
                    values=('', 'SS0' if t['type']=='ss0' else 'PCM',
                            t['name'], self._fmt_dur(t),
                            t['sample_rate'], t['channels']))
                self.check_vars[t_iid] = (t_var, 'track', t)
        self.tree.tag_configure('cat', background='#E8EAF6')
        for iid in self.tree.get_children():
            self.tree.item(iid, open=True)

    def _export(self):
        selected = [(iid, obj) for iid,(v,k,obj) in self.check_vars.items()
                    if k=='track' and v.get()]
        if not selected:
            messagebox.showinfo(tr("dlg_export_title"), tr("dlg_nosel")); return
        out_dir = filedialog.askdirectory(title=tr("dlg_output"))
        if not out_dir: return
        self.progress['maximum'] = len(selected)
        self.progress['value']   = 0
        self.progress.pack(fill='x', side='bottom', before=self.status)
        threading.Thread(target=self._export_thread,
                         args=(selected, out_dir), daemon=True).start()

    def _export_thread(self, selected, out_dir):
        has_ss0 = any(t['type']=='ss0' for _,t in selected)
        if has_ss0 and not _find_vgmstream():
            self.root.after(0, lambda: messagebox.showerror(
                tr("dlg_novgm_title"),
                tr("dlg_novgm_msg")))
            self.root.after(0, self._export_abort)
            return
        ok = err = 0
        for i, (iid, t) in enumerate(selected):
            try:
                cat_name = os.path.splitext(os.path.basename(t['_sb0_path']))[0]
                cat_dir  = os.path.join(out_dir, cat_name)
                os.makedirs(cat_dir, exist_ok=True)
                safe = re.sub(r'[\\/:*?"<>|]', '_',
                              t['name'] or t['internal_name'])
                out_path = os.path.join(cat_dir,
                                        os.path.splitext(safe)[0] + '.wav')
                if t['type'] == 'pcm':
                    write_pcm_wav(t, out_path)
                else:
                    ss0_path = os.path.join(t['_ss0_dir'], t['ss0_file'])
                    if not os.path.isfile(ss0_path):
                        raise FileNotFoundError(f"SS0 nicht gefunden: {ss0_path}")
                    decode_and_write_wav(t, ss0_path, out_path)
                ok += 1
            except Exception as e:
                err += 1
                print(f"Fehler {t.get('name','?')}: {e}")
            self.root.after(0, self._progress_update, i+1, ok, err)
        self.root.after(0, self._export_done, ok, err, out_dir)

    def _progress_update(self, val, ok, err):
        self.progress['value'] = val
        self.status.config(text=tr("status_export", ok=ok, err=err))

    def _export_abort(self):
        self.progress.pack_forget()
        self.status.config(text=tr("status_abort"))

    def _export_done(self, ok, err, out_dir):
        self.progress.pack_forget()
        self.status.config(text=tr("status_done", ok=ok, err=err, dir=out_dir))
        messagebox.showinfo(tr("dlg_export_title"),
            tr("dlg_export_msg", ok=ok, err=err, dir=out_dir))

    @staticmethod
    def _fmt_dur(t):
        sr = t['sample_rate']
        if not sr: return '?'
        if t['type'] == 'pcm':
            secs = t['byte_size'] / (sr * t['channels'] * (t['bits']//8))
        else:
            ns = t.get('num_samples', 0)
            secs = ns / sr if ns else 0
            if not secs: return '?'
        if secs >= 60:
            return f"{int(secs)//60}m{int(secs)%60:02d}s"
        return f"{secs:.1f}s"


def main():
    root = tk.Tk()
    RVSExtractor(root)
    root.mainloop()


if __name__ == '__main__':
    main()
