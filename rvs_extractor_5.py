#!/usr/bin/env python3
"""
Ravenshield Sound Extractor
Scannt den sounds/-Ordner, zeigt alle Sounds in einer Baumstruktur
und exportiert selektierte Tracks als WAV.

SB0-Parser: strukturbasiert (section1/section2 direkt lesen),
kein Regex-Scan.  Basiert auf vgmstream ubi_sb.c.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import struct
import os
import re
from collections import Counter

# =============================================================================
# UAX Parser
# =============================================================================

def _read_compact(d, pos):
    b = d[pos]; pos += 1
    neg = bool(b & 0x80)
    val = b & 0x3F
    if b & 0x40:
        b = d[pos]; pos += 1; val |= (b & 0x7F) << 6
        if b & 0x80:
            b = d[pos]; pos += 1; val |= (b & 0x7F) << 13
            if b & 0x80:
                b = d[pos]; pos += 1; val |= (b & 0x7F) << 20
                if b & 0x80:
                    b = d[pos]; pos += 1; val |= (b & 0x3F) << 27
    return (-val if neg else val), pos


def parse_uax(path, sb0_resource_map=None):
    """
    Returns (direct_map {section2_idx: name}, ordered_list [name,...]).
    
    sb0_resource_map: optional dict {resource_id_low_byte: section2_idx}
    Wenn übergeben, wird payload[2] als resource_id low byte interpretiert.
    Sonst wird payload[2] direkt als section2_idx verwendet (Fallback).
    """
    if not path or not os.path.isfile(path):
        return {}, []
    with open(path, 'rb') as f:
        d = f.read()

    def u32(o): return int.from_bytes(d[o:o+4], 'little')

    if u32(0) != 0x9E2A83C1:
        return {}, []

    name_cnt = u32(0x0C); name_off = u32(0x10)
    exp_cnt  = u32(0x14); exp_off  = u32(0x18)

    names = []; pos = name_off
    for _ in range(name_cnt):
        slen = d[pos]; pos += 1
        names.append(d[pos:pos+slen-1].decode('latin-1', errors='replace'))
        pos += slen + 4

    direct_map   = {}
    ordered_list = []
    pos = exp_off
    for _ in range(exp_cnt):
        _, pos = _read_compact(d, pos)
        _, pos = _read_compact(d, pos)
        pos += 4
        ni, pos = _read_compact(d, pos)
        pos += 4
        ss, pos = _read_compact(d, pos)
        so, pos = _read_compact(d, pos)
        name = names[ni] if 0 <= ni < len(names) else ''
        if name.lower().startswith('stop_'):
            continue
        clean = re.sub(r'^Play_', '', name, flags=re.IGNORECASE)
        ordered_list.append(clean)
        if ss >= 7:
            payload = d[so:so+ss]
            p = 0
            while p + 7 <= len(payload):
                if payload[p] in (0x00, 0x01) and payload[p+1] in (0x00, 0x01):
                    # Resource-ID: high word bei payload[p+4..p+5], low byte bei payload[p+2]
                    high = payload[p+4] | (payload[p+5] << 8)
                    low  = payload[p+2]
                    full_rid = (high << 16) | low
                    if sb0_resource_map is not None:
                        s2idx = sb0_resource_map.get(full_rid)
                        if s2idx is not None and s2idx not in direct_map:
                            direct_map[s2idx] = clean
                    else:
                        if low not in direct_map:
                            direct_map[low] = clean
                    p += 7
                elif payload[p] == 0x07:
                    break
                else:
                    p += 1

    return direct_map, ordered_list


# =============================================================================
# SB0 Parser  (vgmstream ubi_sb.c)
# =============================================================================

def _u32(d, o): return int.from_bytes(d[o:o+4], 'little')
def _u16(d, o): return int.from_bytes(d[o:o+2], 'little')

def _sb0_str(d, o, maxlen=64):
    chunk = d[o:o+maxlen]
    end   = chunk.find(0)
    raw   = chunk[:end] if end >= 0 else chunk
    return raw.decode('ascii', errors='replace').strip()

TYPE_AUDIO     = 0x01
TYPE_LAYER     = 0x06
TYPE_LAYER_OLD = 0x0D

# Voices-SB0 schreibt sr=22050 ins Entry, korrekt ist 16000 Hz
_VOICE_SR = 16000


def _parse_header(data):
    """
    Liest Header-Felder.
    0x00 = Format-Tag (immer 11=0x0B fuer RavenShield)
    0x04 = Version (3, 5, 7, 13, 21, 32 ...)

    vgmstream init_sb_header liest version aus 0x00 weil es den Format-Tag
    als version behandelt. Fuer RavenShield gilt:
      format_tag (0x00) <= 0x0B  ->  s1@0x04  s2@0x0C  sX@0x1C  s1_off=0x20
    Die eigentliche Spielversion (3/5/7/13/21/32) steht bei 0x04.
    """
    fmt_tag = _u32(data, 0x00)   # immer 11 bei RavenShield
    version = _u32(data, 0x04)   # 3, 5, 7, 13, 21, 32 ...

    # Layout-Auswahl nach Format-Tag (wie vgmstream, der 0x00 als version liest)
    if fmt_tag <= 0x0B:
        s1_num  = _u32(data, 0x04)   # = version (beide im gleichen Feld!)
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

    S1 = 0x5C
    S2 = 0x7C
    s2_off = s1_off + s1_num * S1
    sX_off = s2_off + s2_num * S2
    s3_off = sX_off + sX_size  # audio_base fuer interne Streams

    return version, s2_num, s2_off, sX_off, sX_size, s3_off, S2


# version=13 (Voices): sr-Feld im Entry enthaelt 22050 (falsch), korrekt ist 16000.
_VERSION_SR_OVERRIDE = {
    13: 16000,
}


def parse_sb0(path):
    """
    Parst eine SB0-Datei und gibt Track-Liste zurueck.
    type='pcm'  -> internes PCM-Audio
    type='ss0'  -> externer SS0-Stream (Decoder TODO)
    """
    with open(path, 'rb') as f:
        data = f.read()

    filesize = len(data)
    version, s2_num, s2_off, sX_off, sX_size, audio_base, S2 = \
        _parse_header(data)
    #sr_override = _VERSION_SR_OVERRIDE.get(version)
    
    # Voices-Erkennung: Ordner oder Dateiname
    sb0_name = os.path.basename(path).lower()
    sb0_dir  = os.path.basename(os.path.dirname(path)).lower()

    is_voice = (
        sb0_dir in ('ger', 'int') or
        sb0_name.startswith('voice') or
        sb0_name.startswith('voices')
    )

    if is_voice:
        sr_override = 16000
    else:
        sr_override = _VERSION_SR_OVERRIDE.get(version)

    # Sanity: audio_base darf nicht groesser als Datei sein
    if audio_base > filesize:
        # Fallback: filesize - max(rel+size) aller TYPE_AUDIO Entries
        max_end = 0
        for i in range(s2_num):
            eb = s2_off + i * S2
            if eb + S2 > filesize: break
            if _u32(data, eb + 0x04) != TYPE_AUDIO: continue
            rel  = _u32(data, eb + 0x10)
            size = _u32(data, eb + 0x08)
            if rel < 0xF0000000 and size > 0:
                max_end = max(max_end, rel + size)
        if max_end:
            audio_base = filesize - max_end

    tracks = []

    for i in range(s2_num):
        eb = s2_off + i * S2
        if eb + S2 > filesize:
            break

        etype = _u32(data, eb + 0x04)

        # ── TYPE_AUDIO ────────────────────────────────────────────────────
        if etype == TYPE_AUDIO:
            stream_size   = _u32(data, eb + 0x08)
            stream_offset = _u32(data, eb + 0x10)
            num_samples   = _u32(data, eb + 0x2C)
            sample_rate   = _u32(data, eb + 0x40)
            channels      = _u16(data, eb + 0x46) or 1
            stream_name   = _sb0_str(data, eb + 0x4C)

            if stream_size == 0 or stream_offset >= 0xF0000000:
                continue

            # Externer SS0-Verweis?
            if stream_name.upper().endswith('.SS0'):
                tracks.append({
                    'type':          'ss0',
                    'section2_idx':  i,
                    '_etype':        etype,
                    '_resource_id':  _u32(data, eb + 0x00),
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

            # sr-Korrektur fuer bekannte falsche Werte (z.B. version=13 Voices)
            if sr_override:
                sample_rate = sr_override

            tracks.append({
                'type':          'pcm',
                'section2_idx':  i,
                '_resource_id':  _u32(data, eb + 0x00),
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
        elif etype in (TYPE_LAYER, TYPE_LAYER_OLD):
            layer_count   = _u32(data, eb + 0x20)
            # TYPE_LAYER_OLD (0x0D): stream_size @ +0x08
            # TYPE_LAYER     (0x06): stream_size @ +0x60
            stream_size   = _u32(data, eb + 0x08) if etype == TYPE_LAYER_OLD else _u32(data, eb + 0x60)
            stream_offset = _u32(data, eb + 0x58)
            stream_name   = _sb0_str(data, eb + 0x30)

            if stream_size == 0 or stream_offset >= 0xF0000000:
                continue

            # Sub-Header in sectionX
            extra_off  = _u32(data, eb + 0x0C)
            layer_sr   = 44100
            layer_ch   = 2
            layer_ns   = 0
            if extra_off < sX_size and sX_off + extra_off + 0x14 <= filesize:
                sub      = sX_off + extra_off
                layer_sr = _u32(data, sub + 0x00) or 44100
                layer_ch = _u16(data, sub + 0x06) or 2
                layer_ns = _u32(data, sub + 0x10)

            tracks.append({
                'type':          'ss0',
                'section2_idx':  i,
                '_etype':        etype,
                '_resource_id':  _u32(data, eb + 0x00),
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

    return tracks


# =============================================================================
# UAX-Namen auf Tracks anwenden
# =============================================================================

def _apply_uax_names(tracks, uax_result, sb0_path):
    direct_map, ordered_list = uax_result if isinstance(uax_result, tuple) else (uax_result, [])

    # Hauptthema-Name: erster Name der Play_ hat und kein Insert/In/Out/Semi ist
    def _main_name(ol):
        for n in ol:
            low = n.lower()
            if not any(x in low for x in ('insert', '_in', '_out', 'semi')):
                return n
        return ol[0] if ol else ''

    pcm_tracks = [t for t in tracks if t['type'] == 'pcm']
    ss0_tracks = [t for t in tracks if t['type'] == 'ss0']
    main_theme = _main_name(ordered_list) if ordered_list else ''

    for t in tracks:
        idx   = t['section2_idx']
        iname = os.path.splitext(t['internal_name'])[0]

        if t['type'] == 'ss0':
            uname = direct_map.get(idx, '') or direct_map.get(idx - 1, '')
            if not uname and len(ss0_tracks) == 1:
                uname = main_theme
            if not uname:
                sb0_base = os.path.splitext(os.path.basename(sb0_path))[0]
                uname = f'{sb0_base}_{ss0_tracks.index(t)+1:02d}'
            t['name'] = uname
        else:
            # PCM: Index-Lookup zuerst, dann Reihenfolge, dann interner Name
            uname = direct_map.get(idx, '')
            if not uname and ordered_list:
                pi = pcm_tracks.index(t) if t in pcm_tracks else -1
                if 0 <= pi < len(ordered_list):
                    uname = ordered_list[pi]
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
        f.write(hdr)
        f.write(pcm)


# =============================================================================
# Ubisoft 4/6-bit ADPCM Decoder
# Portiert aus vgmstream src/coding/ubi_adpcm_decoder.c
# =============================================================================

# --- 6-bit Tabellen ---
_adpcm6_table1 = [
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0040, 0x0040, 0x0040, 0x0040, 0x0040, 0x0040, 0x0040, 0x0040,
    0x0040, 0x0040, 0x0040, 0x0040, 0x0040, 0x0040, 0x0040, 0x0040,
    0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100,
    0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100,
    0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
    0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
]
_adpcm6_table2 = [
    0x0000, 0x0040, 0x0100, 0x0400, 0x1000, 0x4000, 0x7FFF, 0x7FFF,
    0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x0000, 0x0000,
    0x0000, 0x0040, 0x0100, 0x0400, 0x1000, 0x4000, 0x7FFF, 0x7FFF,
    0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x0000, 0x0000,
    0x0000, 0x0040, 0x0100, 0x0400, 0x1000, 0x4000, 0x7FFF, 0x7FFF,
    0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x0000, 0x0000,
    0x0000, 0x0040, 0x0100, 0x0400, 0x1000, 0x4000, 0x7FFF, 0x7FFF,
    0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x0000, 0x0000,
]

# --- 4-bit Tabellen ---
_adpcm4_table1 = [
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100,
]
_adpcm4_table2 = [
    0x0000, 0x0100, 0x0400, 0x1000, 0x7FFF, 0x7FFF, 0x0000, 0x0000,
    0x0000, 0x0100, 0x0400, 0x1000, 0x7FFF, 0x7FFF, 0x0000, 0x0000,
]

# Vorzeichen: erste Haelfte positiv, zweite negativ
_delta6 = [1] * 32 + [-1] * 32
_delta4 = [1] * 8  + [-1] * 8


def _clamp16(v):
    if v >  0x7FFF: return  0x7FFF
    if v < -0x8000: return -0x8000
    return v


def _read_codes(data, bit_pos, count, bps):
    """Liest 'count' Codes a 'bps' Bits (LSB-first) aus data ab bit_pos."""
    mask = (1 << bps) - 1
    codes = []
    for _ in range(count):
        byte_idx = bit_pos >> 3
        bit_off  = bit_pos & 7
        # Max 13 bits noetig (6+7), zwei Bytes reichen immer
        if byte_idx + 1 < len(data):
            word = data[byte_idx] | (data[byte_idx + 1] << 8)
        elif byte_idx < len(data):
            word = data[byte_idx]
        else:
            word = 0
        codes.append((word >> bit_off) & mask)
        bit_pos += bps
    return codes, bit_pos


def _decode_channel(data, bit_pos, total_codes, bps):
    """
    Dekodiert einen kompletten Kanal-Bitstream.
    Verarbeitet CodesPerSF Codes pro Subframe kontinuierlich.
    Gibt (samples_list, end_bit_pos) zurueck.
    """
    if bps == 6:
        t1, t2, delta = _adpcm6_table1, _adpcm6_table2, _delta6
    else:
        t1, t2, delta = _adpcm4_table1, _adpcm4_table2, _delta4

    predictor = 0
    step      = 0
    samples   = []

    codes, bit_pos = _read_codes(data, bit_pos, total_codes, bps)
    for code in codes:
        d     = delta[code]
        step  = min(step + t1[code], 0x7FFF)
        s     = predictor + d * (t2[code] + (step >> 3))
        s     = _clamp16(s)
        predictor = s
        step  = max(step - (step >> 3), 0)
        samples.append(s)

    return samples, bit_pos


def _parse_ss0_header(raw, ss0_name, track_type):
    """
    Parst den Stream-Header. Fuer hd_music/stream_music wird der
    track_type anhand des tatsaechlichen Inhalts verifiziert (auto-detect).
    """
    def u32(o): return int.from_bytes(raw[o:o+4], 'little') if o+4 <= len(raw) else 0

    # track_type kommt von _detect_stream_type und ist korrekt bestimmt.
    # Kein Auto-Detect noetig -- die Feld-Layouts ueberlappen sich und
    # eine zuverlässige Unterscheidung anhand des Inhalts ist nicht moeglich.

    if track_type == 'hd_music':
        ho          = 0
        total_codes = u32(ho + 0x04)
        sf          = u32(ho + 0x08)
        last        = u32(ho + 0x0C)
        cpsf        = u32(ho + 0x10)
        sr          = u32(ho + 0x18)
        bps         = u32(ho + 0x24)
        ch          = u32(ho + 0x2C)
        audio_off   = 0x98
        cpsf_val    = (cpsf // ch) if ch else cpsf

    elif track_type == 'stream_music':
        prolog_size = u32(0x00)   # = 8
        ho          = prolog_size
        sf          = u32(ho + 0x00)
        last        = u32(ho + 0x04)
        cpsf        = u32(ho + 0x08)
        ch          = u32(ho + 0x0C)
        sr          = u32(ho + 0x10)
        bps         = u32(ho + 0x1C)
        total_codes = (sf - 1) * cpsf + last
        audio_off   = ho + 0x90
        cpsf_val    = (cpsf // ch) if ch else cpsf   # pro Kanal pro Subframe

    else:  # ambience
        # Prolog (0x0C): [layer_count][variant][data_size][hdr_flags]
        # Outer header (0x14) @ 0x0C
        # Layer-Blöcke: layer_count × 0x30 @ 0x20
        #   Jeder Block: +0x0C=TotalCodes, +0x18=CodesPerSF, +0x1C=ch, +0x20=sr, +0x2C=bps
        # State-Block: 0x80 bytes
        # Audio: 0x0C + 0x14 + layer_count*0x30 + 0x80
        layer_count = int.from_bytes(raw[0x00:0x04], 'little') or 1
        block0      = 0x20                        # erster Layer-Block
        total_codes = u32(block0 + 0x0C)
        cpsf_raw    = u32(block0 + 0x18)
        ch          = u32(block0 + 0x1C) or 2
        sr          = u32(block0 + 0x20) or 44100
        bps         = u32(block0 + 0x2C) or 6
        audio_off   = 0x0C + 0x14 + layer_count * 0x30 + 0x80
        cpsf_val    = (cpsf_raw // ch) if ch else cpsf_raw

    return {
        'audio_offset': audio_off,
        'total_codes':  total_codes,
        'sr':           sr,
        'ch':           ch,
        'bps':          bps,
        'cpsf':         cpsf_val,
        'stream_type':  track_type,
    }


def _decode_ss0(raw, info):
    """
    Dekodiert rohe SS0-Bytes gemaess info-dict.
    Gibt interleaved int16-Liste zurueck.
    """
    audio_off   = info['audio_offset']
    total_codes = info['total_codes']   # beide Kanaele zusammen
    ch          = info['ch']
    bps         = info['bps']
    cpsf        = info.get('cpsf', 1536)  # Codes pro Subframe pro Kanal

    if total_codes == 0 or ch == 0:
        return []

    codes_per_ch = total_codes // ch    # Codes pro Kanal gesamt

    if bps == 6:
        t1, t2, delta_t = _adpcm6_table1, _adpcm6_table2, _delta6
    else:
        t1, t2, delta_t = _adpcm4_table1, _adpcm4_table2, _delta4

    mask = (1 << bps) - 1

    # Pro-Kanal ADPCM-State
    predictor = [0] * ch
    step      = [0] * ch

    # Output: interleaved L/R pro Sample (nach Unmix)
    # Wir sammeln erst alle Samples pro Kanal, dann unmixen, dann interleave
    ch_samples = [[] for _ in range(ch)]

    bit_pos = audio_off * 8
    remaining = codes_per_ch  # Codes die noch fuer jeden Kanal dekodiert werden muessen

    while remaining > 0:
        # Codes in diesem Subframe (pro Kanal)
        sf_codes = min(cpsf, remaining)

        for c in range(ch):
            for _ in range(sf_codes):
                byte_idx = bit_pos >> 3
                bit_off  = bit_pos & 7
                if byte_idx + 1 < len(raw):
                    word = raw[byte_idx] | (raw[byte_idx + 1] << 8)
                elif byte_idx < len(raw):
                    word = raw[byte_idx]
                else:
                    word = 0
                code = (word >> bit_off) & mask
                bit_pos += bps

                d        = delta_t[code]
                step[c]  = min(step[c] + t1[code], 0x7FFF)
                s        = predictor[c] + d * (t2[code] + (step[c] >> 3))
                s        = _clamp16(s)
                predictor[c] = s
                step[c]  = max(step[c] - (step[c] >> 3), 0)
                ch_samples[c].append(s)

        remaining -= sf_codes

    # Joint-Stereo-Unmix (Mid/Side -> L/R) fuer Stereo
    if ch == 2:
        L, R = ch_samples[0], ch_samples[1]
        n = min(len(L), len(R))
        block = 8
        for b in range(n // block):
            for i in range(block):
                idx  = b * block + i
                mid  = L[idx]
                side = R[idx]
                L[idx] = _clamp16((mid + side) >> 1)
                R[idx] = _clamp16((mid - side) >> 1)
        ch_samples = [L[:n], R[:n]]

    # Interleaved ausgeben
    n = min(len(s) for s in ch_samples)
    out = []
    for i in range(n):
        for c in range(ch):
            out.append(ch_samples[c][i])
    return out


def _detect_stream_type(track):
    """Bestimmt den Stream-Typ anhand des SB0-Entry."""
    ss0 = track.get('ss0_file', '').upper()
    etype = track.get('_etype', 0)

    # Ambiences immer zuerst prüfen (TYPE_LAYER / TYPE_LAYER_OLD)
    if etype in (TYPE_LAYER, TYPE_LAYER_OLD):
        return 'ambience'

    # HD_Music-Format: kein Prolog, Header direkt bei ss0_offset
    # RVS: HD_Music.SS0
    # IW:  MP2_Music.SS0  (Menü/Victory, ~15 MB)
    # Erkennungsmerkmal: enthält "HD_MUSIC" oder ist explizit MP2_MUSIC
    if 'HD_MUSIC' in ss0 or ss0 == 'MP2_MUSIC.SS0':
        return 'hd_music'

    # Alles andere (STREAM.SS0, MP1_Stream.SS0, MP2_Singleplayer.SS0 etc.)
    return 'stream_music'


def _find_vgmstream():
    """Sucht vgmstream-cli.exe neben der laufenden .py-Datei."""
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ('vgmstream-cli.exe', 'vgmstream-cli', 'vgmstream_cli.exe'):
        p = os.path.join(here, name)
        if os.path.isfile(p):
            return p
    return None


def decode_and_write_wav(track, ss0_path, out_path):
    """
    Exportiert SS0-Track als WAV via vgmstream-cli (neben der .py).
    Subsong = section2_idx + 1 (vgmstream zaehlt 1-basiert).
    Faellt auf .ss0_raw zurueck wenn vgmstream-cli nicht gefunden.
    """
    import subprocess

    vgm = _find_vgmstream()
    if not vgm:
        write_ss0_raw(track, ss0_path, out_path)
        return

    sb0_path = track.get('_sb0_path', '')
    subsong  = track.get('_vgm_subsong', 1)

    try:
        result = subprocess.run(
            [vgm, '-s', str(subsong), '-o', out_path, sb0_path],
            capture_output=True, timeout=60
        )
        if result.returncode != 0 or not os.path.isfile(out_path):
            err = result.stderr.decode(errors='replace')[:300]
            raise RuntimeError(err)
    except Exception as e:
        print(f"  vgmstream Fehler ({e}), schreibe .ss0_raw")
        write_ss0_raw(track, ss0_path, out_path)


def write_ss0_raw(track, ss0_path, out_path):
    """Fallback: roher SS0-Chunk als .ss0_raw."""
    raw_path = os.path.splitext(out_path)[0] + '.ss0_raw'
    with open(ss0_path, 'rb') as f:
        f.seek(track['ss0_offset'])
        raw = f.read(track['byte_size'])
    with open(raw_path, 'wb') as f:
        f.write(raw)


# =============================================================================
# Scanner
# =============================================================================

def _find_sb0(base, folder):
    """Findet SB0 – bevorzugt High/-Unterordner."""
    key   = base.lower() + '.sb0'
    found = []
    for dirpath, _, files in os.walk(folder):
        for fn in files:
            if fn.lower() == key:
                found.append(os.path.join(dirpath, fn))
    if not found:
        return None
    high = [p for p in found
            if os.path.basename(os.path.dirname(p)).lower() == 'high']
    return high[0] if high else found[0]


def scan_sounds_folder(folder):
    """
    UAX liegt immer direkt im sounds/-Ordner (Anker).
    SB0 liegt entweder:
      1) gleicher Ordner wie UAX        (Ambiences, Musik, SFX, Foley)
      2) high/-Unterordner              (Waffen-HQ)
      3) ger/- ODER int/-Unterordner    (Voices – nie beide gleichzeitig)
    SS0 liegt immer im gleichen Ordner wie die UAX.
    """
    # UAX-Dateien als Anker sammeln — NUR im Root und direkten Unterordnern
    # (UAX liegen laut Spielstruktur immer im sounds/-Stammordner)
    uax_files = {}  # base_low -> path
    # Erst Root-Ordner, dann max. eine Ebene tiefer
    for search_dir in [folder] + [
        os.path.join(folder, d) for d in os.listdir(folder)
        if os.path.isdir(os.path.join(folder, d))
    ]:
        try:
            for fn in os.listdir(search_dir):
                if fn.lower().endswith('.uax'):
                    base_low = os.path.splitext(fn)[0].lower()
                    if base_low not in uax_files:
                        uax_files[base_low] = os.path.join(search_dir, fn)
        except PermissionError:
            pass

    categories = []

    for base_low, uax_path in sorted(uax_files.items()):
        uax_dir  = os.path.dirname(uax_path)
        fn_sb0   = base_low + '.sb0'
        sb0_path = None

        # Suchreihenfolge: ger/ -> int/ -> gleicher Ordner -> high/
        # Voices-SB0s liegen in ger/ oder int/, Waffen in high/, Rest direkt neben UAX
        for candidate_dir in (
            os.path.join(uax_dir, 'ger'),
            os.path.join(uax_dir, 'int'),
            uax_dir,
            os.path.join(uax_dir, 'high'),
        ):
            candidate = os.path.join(candidate_dir, fn_sb0)
            if os.path.isfile(candidate):
                sb0_path = candidate
                break

        if not sb0_path:
            continue

        try:
            tracks = parse_sb0(sb0_path)
        except Exception as e:
            print(f'parse_sb0 Fehler {sb0_path}: {e}')
            continue

        if not tracks:
            continue

        # Baue rid_map via Section1-Tabelle: UAX-rid -> Section1 -> s2_companion -> STREAM-s2idx
        rid_map = {}
        try:
            with open(sb0_path, 'rb') as _f:
                _d = _f.read()
            _s1_num = int.from_bytes(_d[0x04:0x08], 'little')
            _s2_num = int.from_bytes(_d[0x0C:0x10], 'little')
            _s2_off = 0x20 + _s1_num * 0x5C
            _S1 = 0x5C; _S2 = 0x7C

            # Section2 etype map
            _s2_etype = {}
            for _i in range(_s2_num):
                _base = _s2_off + _i * _S2
                _s2_etype[_i] = int.from_bytes(_d[_base+4:_base+8], 'little')

            # Section1: rid -> (s1_idx, s2_companion_idx)
            for _i in range(_s1_num):
                _base = 0x20 + _i * _S1
                _s1_rid  = int.from_bytes(_d[_base:_base+4], 'little')
                _s2_comp = int.from_bytes(_d[_base+8:_base+12], 'little')
                # STREAM-Track ist s2_comp +1 oder -1
                for _nb in (_s2_comp + 1, _s2_comp - 1):
                    if 0 <= _nb < _s2_num and _s2_etype.get(_nb) == TYPE_AUDIO:
                        rid_map[_s1_rid] = _nb
                        break
        except Exception:
            # Fallback: direkte resource_id der Tracks
            for t in tracks:
                rid = t.get('_resource_id', 0)
                if rid:
                    rid_map[rid] = t['section2_idx']

        uax_result = parse_uax(uax_path, rid_map) if uax_path else ({}, [])
        _apply_uax_names(tracks, uax_result, sb0_path)

        for rank, t in enumerate(tracks, start=1):
            t['_sb0_path']    = sb0_path
            t['_ss0_dir']     = uax_dir
            t['_vgm_subsong'] = rank  # vgmstream zaehlt Subsongs sequenziell ab 1

        rel = os.path.relpath(sb0_path, folder)
        categories.append({
            'name':   rel,
            'sb0':    sb0_path,
            'tracks': tracks,
        })

    return categories


# =============================================================================
# GUI
# =============================================================================

class RVSExtractor:
    def __init__(self, root):
        self.root = root
        root.title("Ravenshield Sound Extractor")
        root.geometry("960x680")
        root.resizable(True, True)
        self.categories = []
        self.check_vars = {}
        self._build_ui()

    def _build_ui(self):
        tb = tk.Frame(self.root, pady=4, padx=6)
        tb.pack(fill='x')
        tk.Button(tb, text="Ordner waehlen...", command=self._choose_folder,
                  width=16).pack(side='left', padx=2)
        tk.Button(tb, text="Alle auswaehlen",  command=self._select_all,
                  width=14).pack(side='left', padx=2)
        tk.Button(tb, text="Keine auswaehlen", command=self._select_none,
                  width=14).pack(side='left', padx=2)
        tk.Button(tb, text="Exportieren", command=self._export,
                  width=12, bg='#2E7D32', fg='white').pack(side='left', padx=8)
        self.lbl_folder = tk.Label(tb, text="Kein Ordner gewaehlt",
                                   fg='gray', anchor='w')
        self.lbl_folder.pack(side='left', fill='x', expand=True, padx=4)

        fbar = tk.Frame(self.root, padx=6)
        fbar.pack(fill='x')
        tk.Label(fbar, text="Filter:").pack(side='left')
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add('write', lambda *_: self._apply_filter())
        tk.Entry(fbar, textvariable=self.filter_var,
                 width=30).pack(side='left', padx=4)
        tk.Label(fbar, text="  Typ:").pack(side='left')
        self.type_var = tk.StringVar(value='Alle')
        tk.OptionMenu(fbar, self.type_var,
                      'Alle', 'PCM', 'SS0 (Musik/Ambience)',
                      command=lambda _: self._apply_filter()
                      ).pack(side='left')

        frame = tk.Frame(self.root)
        frame.pack(fill='both', expand=True, padx=6, pady=4)
        cols = ('typ', 'name', 'dauer', 'hz', 'ch')
        self.tree = ttk.Treeview(frame, columns=cols,
                                  show='tree headings', selectmode='none')
        self.tree.heading('#0',    text='  Kategorie / Asset')
        self.tree.heading('typ',   text='Typ')
        self.tree.heading('name',  text='Asset-Name')
        self.tree.heading('dauer', text='Dauer')
        self.tree.heading('hz',    text='Hz')
        self.tree.heading('ch',    text='Ch')
        self.tree.column('#0',    width=340, stretch=True)
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
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.tree.bind('<Button-1>', self._on_click)

        self.status = tk.Label(self.root, text="Bereit.", anchor='w',
                               relief='sunken', padx=4)
        self.status.pack(fill='x', side='bottom')
        self.progress = ttk.Progressbar(self.root, mode='determinate')

    def _choose_folder(self):
        folder = filedialog.askdirectory(title="sounds/-Ordner waehlen")
        if not folder:
            return
        self.lbl_folder.config(text=folder, fg='black')
        self.status.config(text="Scanne...")
        self.tree.delete(*self.tree.get_children())
        self.check_vars.clear()
        threading.Thread(target=self._scan_thread, args=(folder,),
                         daemon=True).start()

    def _scan_thread(self, folder):
        cats = scan_sounds_folder(folder)
        self.categories = cats
        self.root.after(0, self._populate_tree)

    def _populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.check_vars.clear()
        total = 0
        for cat in self.categories:
            tracks = cat['tracks']
            if not tracks:
                continue
            cat_var = tk.BooleanVar(value=False)
            cat_iid = self.tree.insert('', 'end',
                text=f'  {cat["name"]}  ({len(tracks)} Tracks)',
                values=('', '', '', '', ''), tags=('cat',))
            self.check_vars[cat_iid] = (cat_var, 'cat', cat)
            for t in tracks:
                dur   = self._fmt_dur(t)
                typ   = 'SS0' if t['type'] == 'ss0' else 'PCM'
                t_var = tk.BooleanVar(value=False)
                t_iid = self.tree.insert(cat_iid, 'end',
                    text=f'  {t["internal_name"]}',
                    values=(typ, t['name'], dur,
                            t['sample_rate'], t['channels']))
                self.check_vars[t_iid] = (t_var, 'track', t)
                total += 1
        self.tree.tag_configure('cat', background='#E8EAF6')
        self.status.config(
            text=f"{total} Tracks in {len(self.categories)} Kategorien gefunden.")

    @staticmethod
    def _set_sym(cur, sym):
        """Ersetzt das Präfix eines Tree-Eintrags durch sym ('[X]' oder '[ ]')."""
        if cur[:3] in ('[X]', '[ ]'):
            return sym + cur[3:]
        # Initialer Text hat 2 Leerzeichen als Präfix
        return sym + cur[2:]

    def _on_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid or iid not in self.check_vars:
            return
        var, kind, obj = self.check_vars[iid]
        new_val = not var.get()
        var.set(new_val)
        sym = '[X]' if new_val else '[ ]'
        cur = self.tree.item(iid, 'text')
        self.tree.item(iid, text=self._set_sym(cur, sym))
        if kind == 'cat':
            for child in self.tree.get_children(iid):
                if child in self.check_vars:
                    cv, ck, co = self.check_vars[child]
                    cv.set(new_val)
                    ct = self.tree.item(child, 'text')
                    self.tree.item(child, text=self._set_sym(ct, sym))
        self._update_status_count()

    def _update_status_count(self):
        sel = sum(1 for _, (v, k, _) in self.check_vars.items()
                  if k == 'track' and v.get())
        self.status.config(text=f"{sel} Tracks ausgewaehlt.")

    def _select_all(self):  self._set_all(True)
    def _select_none(self): self._set_all(False)

    def _set_all(self, val):
        sym = '[X]' if val else '[ ]'
        for iid, (v, k, _) in self.check_vars.items():
            v.set(val)
            t = self.tree.item(iid, 'text')
            self.tree.item(iid, text=self._set_sym(t, sym))
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
                if typ == 'PCM' and t['type'] != 'pcm':
                    continue
                if typ == 'SS0 (Musik/Ambience)' and t['type'] != 'ss0':
                    continue
                if txt and txt not in t['name'].lower() \
                       and txt not in t['internal_name'].lower() \
                       and txt not in cat_lower:
                    continue
                filtered.append(t)
            if not filtered:
                continue
            cat_var = tk.BooleanVar(value=False)
            cat_iid = self.tree.insert('', 'end',
                text=f'  {cat["name"]}  ({len(filtered)} Tracks)',
                values=('', '', '', '', ''), tags=('cat',))
            self.check_vars[cat_iid] = (cat_var, 'cat', cat)
            for t in filtered:
                t_var = tk.BooleanVar(value=False)
                typ_s = 'SS0' if t['type'] == 'ss0' else 'PCM'
                t_iid = self.tree.insert(cat_iid, 'end',
                    text=f'  {t["internal_name"]}',
                    values=(typ_s, t['name'], self._fmt_dur(t),
                            t['sample_rate'], t['channels']))
                self.check_vars[t_iid] = (t_var, 'track', t)
        self.tree.tag_configure('cat', background='#E8EAF6')

    def _export(self):
        selected = [(iid, obj) for iid, (v, k, obj) in self.check_vars.items()
                    if k == 'track' and v.get()]
        if not selected:
            messagebox.showinfo("Export", "Keine Tracks ausgewaehlt.")
            return
        out_dir = filedialog.askdirectory(title="Ausgabeordner waehlen")
        if not out_dir:
            return
        self.progress['maximum'] = len(selected)
        self.progress['value']   = 0
        self.progress.pack(fill='x', side='bottom', before=self.status)
        threading.Thread(target=self._export_thread,
                         args=(selected, out_dir), daemon=True).start()

    def _export_thread(self, selected, out_dir):
        # Pruefe vgmstream-cli einmalig am Anfang
        vgm = _find_vgmstream()
        has_ss0 = any(t['type'] == 'ss0' for _, t in selected)
        if has_ss0 and not vgm:
            self.root.after(0, lambda: messagebox.showwarning(
                "vgmstream nicht gefunden",
                "SS0-Tracks (Musik/Ambiences) koennen nicht exportiert werden.\n\n"
                "Bitte vgmstream-cli.exe neben die .py-Datei legen.\n"
                "Download: https://github.com/vgmstream/vgmstream/releases\n\n"
                "PCM-Tracks werden normal exportiert."
            ))
        ok = err = 0
        for i, (iid, t) in enumerate(selected):
            try:
                cat_name = os.path.splitext(
                    os.path.basename(t['_sb0_path']))[0]
                cat_dir  = os.path.join(out_dir, cat_name)
                os.makedirs(cat_dir, exist_ok=True)
                safe = re.sub(r'[\\/:*?"<>|]', '_',
                              t['name'] or t['internal_name'])
                base_path = os.path.join(cat_dir,
                                          os.path.splitext(safe)[0] + '.wav')
                if t['type'] == 'pcm':
                    write_pcm_wav(t, base_path)
                else:
                    ss0_path = os.path.join(t['_ss0_dir'], t['ss0_file'])
                    if not os.path.isfile(ss0_path):
                        raise FileNotFoundError(
                            f"SS0 nicht gefunden: {ss0_path}")
                    decode_and_write_wav(t, ss0_path, base_path)
                ok += 1
            except Exception as e:
                err += 1
                print(f"Fehler {t.get('name','?')}: {e}")
            self.root.after(0, self._progress_update, i + 1, ok, err)
        self.root.after(0, self._export_done, ok, err, out_dir)

    def _progress_update(self, val, ok, err):
        self.progress['value'] = val
        self.status.config(text=f"Exportiere... {ok} OK, {err} Fehler")

    def _export_done(self, ok, err, out_dir):
        self.progress.pack_forget()
        self.status.config(
            text=f"Export: {ok} OK, {err} Fehler  ->  {out_dir}")
        messagebox.showinfo("Export",
            f"{ok} Track(s) exportiert.\n{err} Fehler.\n\nAusgabe: {out_dir}")

    @staticmethod
    def _fmt_dur(t):
        sr = t['sample_rate']
        if not sr:
            return '?'
        if t['type'] == 'pcm':
            ch  = t['channels']
            ba  = ch * (t['bits'] // 8)
            secs = t['byte_size'] / (sr * ba)
        else:
            ns = t.get('num_samples', 0)
            if ns:
                secs = ns / sr
            else:
                return '?'
        if secs >= 60:
            return f"{int(secs)//60}m{int(secs)%60:02d}s"
        return f"{secs:.1f}s"


# =============================================================================

def main():
    root = tk.Tk()
    RVSExtractor(root)
    root.mainloop()


if __name__ == '__main__':
    main()
