#!/usr/bin/env python3
# -*- coding: utf‑8 -*-

import csv
import math
import random
import time
from dataclasses import dataclass, field
from typing import List

# ───────────────────────────  Constants  ────────────────────────────

HYPER_PERIOD = 5                                           # CAN hyper‑period (h)
ECU_IDS            = [417, 451, 707, 977]                  # Ascending priority
ECU_PERIODICITIES  = [0.025, 0.025, 0.05, 0.1]
CTRL_SKIP_LIMIT    = [3, 2, 2, 1]                          # Consecutive‑skip cap
ECU_COUNT          = len(ECU_IDS)
MIN_ATK_WIN_LEN    = 111
MIN_DLC            = 1
BUS_SPEED_KBPS     = 500.0
TEST_ID            = 461                                   # For verbose debug

MAX_IDLE_SEC = (MIN_DLC * 8 + 47) / (BUS_SPEED_KBPS * 1_000)  # Smallest gap

# ────────────────────────  Data structures  ─────────────────────────


@dataclass
class Instance:
    index: int
    atk_win_len: int = 0                      # bits
    atk_win_count: int = 0
    attackable: bool = False
    atk_win: List[int] = field(default_factory=list)  # IDs in attack window
    ins_win: List[int] = field(default_factory=list)  # Their instance numbers


@dataclass
class Message:
    ID: int = 0
    periodicity: float = 0.0
    count: int = 0                     # instances per hyper‑period
    DLC: int = 0
    tx_time: float = 0.0               # populated only for raw CAN traffic rows
    # Aggregates over all instances
    atk_win_len: int = 0
    # Temporary “current” attack window while scanning the log
    t_atk_win_len: int = 0
    t_atk_win_count: int = 0
    t_atk_win: List[int] = field(default_factory=list)
    t_ins_win: List[int] = field(default_factory=list)
    read_count: int = 0
    # Per‑instance bookkeeping
    instances: List[Instance] = field(default_factory=list)
    sortedASP: List[int] = field(default_factory=list)  # not used in Python
    pattern: List[int] = field(default_factory=list)    # 1 = execute, 0 = skip
    skip_limit: int = 0


@dataclass
class TrafficMsg:
    ID: int
    DLC: int
    tx_time: float


# ─────────────────────────  Initialization  ─────────────────────────


def initialize_ecu() -> List[Message]:
    """Create the in‑memory representation of the four target ECUs."""
    messages: List[Message] = []
    for idx in range(ECU_COUNT):
        inst_count = math.ceil(HYPER_PERIOD / ECU_PERIODICITIES[idx])
        instances = [Instance(index=i) for i in range(inst_count)]
        pattern = [1] * inst_count
        msg = Message(
            ID=ECU_IDS[idx],
            periodicity=ECU_PERIODICITIES[idx],
            count=inst_count,
            instances=instances,
            pattern=pattern,
            skip_limit=CTRL_SKIP_LIMIT[idx],
        )
        messages.append(msg)
    return messages


def initialize_can_traffic(csv_path: str = "SampleTwo.csv") -> List[TrafficMsg]:
    """
    Read SampleTwo.csv and keep only fields actually used by the algorithm:
    hexadecimal ID (column 1), DLC (column 2) and Tx time (column 11).
    """
    traffic: List[TrafficMsg] = []

    with open(csv_path, newline="", encoding="utf‑8") as f:
        reader = csv.reader(f)
        # Skip header row; file uses 0‑based indexing in C version
        next(reader, None)
        for row in reader:
            if not row or row[0] in {"Chn", "Logging"}:
                continue
            try:
                can_id = int(row[1], 16)    # hex → int
                dlc    = int(row[2])
                tx_t   = float(row[11])
            except (ValueError, IndexError):
                continue
            traffic.append(TrafficMsg(can_id, dlc, tx_t))

    return traffic


# ───────────────────────  Small helper routines  ────────────────────

def get_current_instance(candidates: List[Message], can_id: int) -> int:
    """Return the read_count of the candidate with <can_id> (or −1)."""
    for msg in candidates:
        if msg.ID == can_id:
            return msg.read_count
    return -1


def common_messages(a: List[int], a_ins: List[int],
                    b: List[int], b_ins: List[int]) -> tuple[List[int], List[int]]:
    """Intersection of two attack windows, keeping instance numbers aligned."""
    inter, inter_ins = [], []
    # choose shorter list to hash
    shorter = (a, a_ins) if len(a) <= len(b) else (b, b_ins)
    longer  = (b, b_ins) if len(a) <= len(b) else (a, a_ins)
    lookup  = {val: i for i, val in enumerate(shorter[0])}
    for j, val in enumerate(longer[0]):
        if val in lookup:
            inter.append(val)
            inter_ins.append(longer[1][j])
    return inter, inter_ins


def if_skip_possible(pattern: List[int], skip_limit: int,
                     new_skip_pos: int) -> bool:
    """
    Check CLF criterion: can we safely introduce a skip at <new_skip_pos>?
    """
    pattern[new_skip_pos] = 0
    consec = 0
    for i in range(len(pattern) * 2):          # wrap‑around check
        if pattern[i % len(pattern)] == 0:
            consec += 1
            if consec >= skip_limit:
                pattern[new_skip_pos] = 1      # revert
                return False
        else:
            consec = 0
    return True


def check_membership(atk_win: List[int], item: int) -> int:
    """Return index of <item> in atk_win or −1."""
    try:
        return atk_win.index(item)
    except ValueError:
        return -1


# ───────────────────  Core CAN‑analysis algorithm  ──────────────────

def analyse_can_traffic(traffic: List[TrafficMsg], candidates: List[Message]) -> None:
    """
    Port of the long C function AnalyseCANTraffic.
    Mutates <candidates> in place, filling every instance’s attack window.
    """
    for j in range(len(traffic) - 1):
        pkt       = traffic[j]
        tx_start  = pkt.tx_time
        tx_ends   = ((pkt.DLC * 8) + 47) / (BUS_SPEED_KBPS * 1_000)
        next_start = traffic[j + 1].tx_time
        idle_gap   = next_start - (tx_start + tx_ends)

        for cand in candidates:
            # k = number of *future* skips before the next executed instance
            k = sum(1 for idx in range(cand.read_count, cand.count)
                    if cand.pattern[idx] == 0)

            # Case 1 – message is lower‑priority or separated by an idle gap
            if (pkt.ID > cand.ID) or (idle_gap > MAX_IDLE_SEC and pkt.ID != cand.ID):
                cand.t_atk_win_len = cand.t_atk_win_count = 0
                cand.t_atk_win.clear()
                cand.t_ins_win.clear()
                continue

            # Case 2 – message belongs to the attack window (higher priority)
            if pkt.ID < cand.ID:
                ins_no = get_current_instance(candidates, pkt.ID)
                cand.t_atk_win_len   += (pkt.DLC * 8 + 47)
                cand.t_atk_win_count += 1
                cand.t_atk_win.append(pkt.ID)
                cand.t_ins_win.append(ins_no)
                continue

            # Case 3 – message is *this* candidate’s own frame
            idx = (cand.read_count + k) % cand.count
            inst = cand.instances[idx]

            if cand.read_count >= cand.count:          # ≥2nd hyper‑period
                # Take the min attack‑window length observed so far
                inst.atk_win_len = min(
                    inst.atk_win_len or float("inf"), cand.t_atk_win_len
                )
                if inst.atk_win_len == 0:
                    inst.atk_win = inst.ins_win = []
                else:
                    inter, inter_ins = common_messages(inst.atk_win, inst.ins_win,
                                                       cand.t_atk_win, cand.t_ins_win)
                    inst.atk_win, inst.ins_win = inter, inter_ins
                    inst.atk_win_count = len(inter)
            else:                                      # 1st hyper‑period
                inst.atk_win_len   = cand.t_atk_win_len
                inst.atk_win_count = cand.t_atk_win_count
                inst.atk_win       = cand.t_atk_win.copy()
                inst.ins_win       = cand.t_ins_win.copy()

            # reset temp window & advance read_count
            cand.t_atk_win_len = cand.t_atk_win_count = 0
            cand.t_atk_win.clear()
            cand.t_ins_win.clear()
            cand.read_count += k + 1


# ───────────────────────  CSV output (final report)  ─────────────────

def save_final_candidates_csv(candidates: List[Message],
                              out_path: str = "final_candidates.csv") -> None:
    with open(out_path, "w", newline="", encoding="utf‑8") as fp:
        writer = csv.writer(fp)
        writer.writerow([
            "CandidateID", "Periodicity", "InstanceIndex", "Attackable",
            "AtkWinLen", "AtkWinCount", "AtkWinMessages", "InsWinMessages"
        ])

        for cand in candidates:
            for inst in cand.instances:
                atk_ids  = ";".join(map(str, inst.atk_win)) or ""
                ins_nums = ";".join(map(str, inst.ins_win)) or ""
                writer.writerow([
                    cand.ID, f"{cand.periodicity:.3f}", inst.index,
                    int(inst.attackable), inst.atk_win_len,
                    inst.atk_win_count, atk_ids, ins_nums
                ])

    print(f"[+]  Final candidates written to {out_path}")


# ───────────────────────────────  main  ─────────────────────────────

def main() -> None:
    random.seed(time.time_ns())
    traffic = initialize_can_traffic()
    candidates = initialize_ecu()

    # Run the original “while (l <= 10)” loop 10 times
    for _ in range(11):
        analyse_can_traffic(traffic, candidates)

        # Compute per‑instance flags + per‑candidate average
        for cand in candidates:
            total_len = 0
            for inst in cand.instances:
                inst.attackable = inst.atk_win_len >= MIN_ATK_WIN_LEN
                total_len += inst.atk_win_len
            cand.atk_win_len = total_len // cand.count

            # Sort instances: descending attack‑window length
            cand.instances.sort(key=lambda x: x.atk_win_len, reverse=True)

        # ─────  Obfuscation policies (Obf‑1/2/3)  ─────
        # Direct literal translation from C.  Feel free to re‑structure!
        for i, cand in enumerate(candidates):
            # Obf‑1
            j = 0
            while j < cand.count and (not cand.instances[j].attackable
                                      or not cand.pattern[cand.instances[j].index]):
                j += 1
            if j >= cand.count:               # nothing attackable
                continue
            ins_to_skip_1 = cand.instances[j].index
            if if_skip_possible(cand.pattern, cand.skip_limit, ins_to_skip_1):
                continue                      # done – Obf‑1 inserted

            # Obf‑2
            inserted = False
            for hp in range(i):               # higher‑priority msgs
                idx = check_membership(
                    cand.instances[ins_to_skip_1].atk_win,
                    candidates[hp].ID
                )
                if idx >= 0 and if_skip_possible(
                        candidates[hp].pattern,
                        CTRL_SKIP_LIMIT[hp],
                        idx):
                    inserted = True
                    break
            if inserted:
                continue

            # Obf‑3
            k = i - 1
            while k >= 0 and candidates[k].periodicity == cand.periodicity:
                k -= 1
            k += 1
            if k != i and check_membership(
                    cand.instances[ins_to_skip_1].atk_win,
                    candidates[k].ID) >= 0:
                # swap
                candidates[k], candidates[i] = candidates[i], candidates[k]

    # End‑of‑loop – write CSV
    save_final_candidates_csv(candidates)


if __name__ == "__main__":
    main()
