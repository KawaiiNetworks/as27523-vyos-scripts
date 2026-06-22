#!/usr/bin/env python3
"""vpptop - real-time per-interface VPP stats from the stats segment.

Shows, per interface, RX/TX bandwidth and pps, plus drop rate split into
hardware drops and software drops.

  software drops = /if/drops              (dropped inside VPP's node graph)
  hardware drops = /if/rx-miss            (NIC ring/FIFO overflow, imissed)
                 + /if/rx-no-buf          (no vlib buffer, rx_nombuf)
                 + /if/rx-error           (hardware rx errors)
                 + /if/tx-error           (driver tx drops)

Requires VPP's python API: `vpp_papi` (ships with VPP, or `pip install vpp-papi`).
Reads the stats segment (default /run/vpp/stats.sock); interface names are
resolved once via `vppctl show interface`.
"""

import argparse
import curses
import errno
import shlex
import subprocess
import sys
import time
from collections import namedtuple

VPPStats = None
VPP_IMPORT_ERROR = None
try:
    from vpp_papi import VPPStats
except Exception as e:
    try:
        from vpp_papi.vpp_stats import VPPStats
    except Exception as e2:
        VPP_IMPORT_ERROR = e2 or e

# ---- counter names in the stats segment ------------------------------------
RX = "/if/rx"
TX = "/if/tx"
C_DROPS = "/if/drops"          # software drops
HW_DROP_COUNTERS = [
    "/if/rx-miss",
    "/if/rx-no-buf",
    "/if/rx-error",
    "/if/tx-error",
]
SIMPLE_NEEDED = [C_DROPS] + HW_DROP_COUNTERS
# Hardware drops split by direction; software /if/drops is its own (rx-attributed).
RX_DROP_COUNTERS = ["/if/rx-miss", "/if/rx-no-buf", "/if/rx-error"]
TX_DROP_COUNTERS = ["/if/tx-error"]
SW_DROP_COUNTERS = [C_DROPS]

Snap = namedtuple("Snap", "mono rx tx simples")
Row = namedtuple(
    "Row",
    "idx name rx_bps rx_pps tx_bps tx_pps "
    "rx_drop_pps tx_drop_pps sw_drop_pps "
    "rx_drop_cum tx_drop_cum sw_drop_cum",
)


class StartupError(Exception):
    def __init__(self, title, detail, hints=()):
        super().__init__(detail)
        self.title = title
        self.detail = detail
        self.hints = tuple(hints)


def write_startup_error(err):
    lines = [
        "vpptop: %s" % err.title,
        err.detail,
    ]
    if err.hints:
        lines.append("")
        lines.append("Try:")
        lines.extend("  %s" % hint for hint in err.hints)
    width = max(len(line) for line in lines)
    border = "+-%s-+" % ("-" * width)
    sys.stderr.write(border + "\n")
    for line in lines:
        sys.stderr.write("| %-*s |\n" % (width, line))
    sys.stderr.write(border + "\n")


def raise_stats_socket_error(socket, err):
    if isinstance(err, FileNotFoundError):
        raise StartupError(
            "VPP stats socket was not found",
            "Cannot open %s: %s." % (socket, err),
            (
                "start VPP and wait for the stats socket to appear",
                "pass the correct stats socket with --socket PATH",
                "inside containers, mount /run/vpp from the host if VPP runs outside",
            )) from err
    if isinstance(err, PermissionError):
        raise StartupError(
            "VPP stats socket is not readable",
            "Cannot open %s: %s." % (socket, err),
            (
                "run vpptop as a user with permission to read the stats socket",
                "try running as root",
            )) from err
    if isinstance(err, OSError):
        hints = [
            "make sure VPP is running",
            "pass the correct stats socket with --socket PATH",
        ]
        if err.errno in (errno.ECONNREFUSED, errno.ENOTCONN, errno.ECONNRESET):
            hints.insert(0, "restart VPP if the stats socket is stale")
        raise StartupError(
            "cannot connect to VPP stats socket",
            "Cannot open %s: %s." % (socket, err),
            hints) from err
    raise err


def nz(x):
    """Clamp negative deltas to 0 (handles counter resets / 'clear interfaces')."""
    return x if x > 0 else 0


def is_vlan(name):
    """Heuristic: VPP sub-interfaces / VLANs are named 'parent.<subid>'.
    DPDK device names use '/' for bus paths, so a trailing '.<digits>' is
    reliably a sub-interface (e.g. 'eth1.100', 'Gig0/8/0.4094')."""
    return "." in name and name.rsplit(".", 1)[1].isdigit()


def _pb(c):
    """Extract (packets, bytes) from a combined-counter leaf, tolerating
    namedtuple / record / tuple representations across vpp_papi versions."""
    try:
        return int(c.packets), int(c.bytes)
    except AttributeError:
        pass
    try:
        return int(c["packets"]), int(c["bytes"])
    except Exception:
        pass
    try:
        return int(c[0]), int(c[1])
    except Exception:
        return 0, 0


class Collector:
    def __init__(self, socket):
        self.socket = socket
        self._connect()

    def _connect(self):
        if VPPStats is None:
            raise StartupError(
                "VPP Python API is not available",
                "Cannot import vpp_papi%s." % (
                    ": %s" % VPP_IMPORT_ERROR if VPP_IMPORT_ERROR else ""),
                (
                    "install the VPP packaged API, for example: apt install python3-vpp-api",
                    "or install the PyPI package: pip3 install vpp-papi",
                    "run vpptop on a host/container that has VPP's Python API installed",
                ))
        try:
            self.s = VPPStats(self.socket)
        except TypeError:
            try:
                self.s = VPPStats(socketname=self.socket)
            except Exception as e:
                raise_stats_socket_error(self.socket, e)
        except Exception as e:
            raise_stats_socket_error(self.socket, e)
        try:
            self.s.connect()
        except Exception as e:
            raise_stats_socket_error(self.socket, e)

    def reconnect(self):
        try:
            self.s.disconnect()
        except Exception:
            pass
        self._connect()

    # The stats layout for /if/* counters is data[thread_index][sw_if_index];
    # we sum over the thread (worker) dimension to get a per-interface total.
    def _combined(self, name, optional=False):
        out = {}
        try:
            data = self.s[name]
        except KeyError:
            if optional:
                return out
            raise
        if data is None:
            if optional:
                return out
            raise KeyError(name)
        for thread in data:
            for idx, c in enumerate(thread):
                p, b = _pb(c)
                op, ob = out.get(idx, (0, 0))
                out[idx] = (op + p, ob + b)
        return out

    def _simple(self, name, optional=False):
        out = {}
        try:
            data = self.s[name]
        except KeyError:
            if optional:
                return out
            raise
        if data is None:
            if optional:
                return out
            raise KeyError(name)
        for thread in data:
            for idx, v in enumerate(thread):
                out[idx] = out.get(idx, 0) + int(v)
        return out

    def _simple_counters(self):
        return {n: self._simple(n, optional=True) for n in SIMPLE_NEEDED}

    def snapshot(self):
        try:
            rx = self._combined(RX)
            tx = self._combined(TX)
            simples = self._simple_counters()
        except Exception:
            # stats segment may have been re-mmap'd (vpp restart); retry once.
            self.reconnect()
            rx = self._combined(RX)
            tx = self._combined(TX)
            simples = self._simple_counters()
        return Snap(time.monotonic(), rx, tx, simples)


def resolve_names(vppctl_cmd):
    """Build sw_if_index -> name map by parsing `vppctl show interface`."""
    names = {}
    try:
        out = subprocess.run(
            shlex.split(vppctl_cmd) + ["show", "interface"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            if not line or line[0].isspace():
                continue  # skip header-less counter detail lines (indented)
            toks = line.split()
            if len(toks) >= 2 and toks[1].isdigit():
                names[int(toks[1])] = toks[0]
    except Exception:
        pass
    return names


def compute(prev, cur, names, wire):
    dt = cur.mono - prev.mono
    if dt <= 0:
        dt = 1e-9
    # Ethernet wire overhead per packet not counted in VPP byte counters:
    # 7B preamble + 1B SFD + 12B IFG + 4B FCS = 24B.
    oh = 24 if wire else 0
    rows = []
    for idx in set(cur.rx) | set(cur.tx):
        rxp, rxb = cur.rx.get(idx, (0, 0))
        prxp, prxb = prev.rx.get(idx, (0, 0))
        txp, txb = cur.tx.get(idx, (0, 0))
        ptxp, ptxb = prev.tx.get(idx, (0, 0))

        d_rxp, d_rxb = nz(rxp - prxp), nz(rxb - prxb)
        d_txp, d_txb = nz(txp - ptxp), nz(txb - ptxb)

        rx_bps = (d_rxb + oh * d_rxp) * 8 / dt
        tx_bps = (d_txb + oh * d_txp) * 8 / dt
        rx_pps = d_rxp / dt
        tx_pps = d_txp / dt

        def cum(counters):
            return sum(cur.simples.get(n, {}).get(idx, 0) for n in counters)

        def prv(counters):
            return sum(prev.simples.get(n, {}).get(idx, 0) for n in counters)

        rx_drop_cum = cum(RX_DROP_COUNTERS)
        tx_drop_cum = cum(TX_DROP_COUNTERS)
        sw_drop_cum = cum(SW_DROP_COUNTERS)
        rx_drop_pps = nz(rx_drop_cum - prv(RX_DROP_COUNTERS)) / dt
        tx_drop_pps = nz(tx_drop_cum - prv(TX_DROP_COUNTERS)) / dt
        sw_drop_pps = nz(sw_drop_cum - prv(SW_DROP_COUNTERS)) / dt

        rows.append(Row(idx, names.get(idx, "if%d" % idx),
                        rx_bps, rx_pps, tx_bps, tx_pps,
                        rx_drop_pps, tx_drop_pps, sw_drop_pps,
                        rx_drop_cum, tx_drop_cum, sw_drop_cum))
    return rows, dt


def sort_rows(rows, mode):
    key = {
        "bw": lambda r: -(r.rx_bps + r.tx_bps),
        "pps": lambda r: -(r.rx_pps + r.tx_pps),
        "rxdrop": lambda r: -r.rx_drop_pps,
        "txdrop": lambda r: -r.tx_drop_pps,
        "idx": lambda r: r.idx,
        "name": lambda r: r.name,
    }.get(mode, lambda r: r.idx)
    return sorted(rows, key=key)


SEV_WORDS = {"error", "warn", "warning", "info", "fatal", "disabled"}


def read_show_errors(vppctl_cmd):
    """Parse `vppctl show errors` -> {(node, reason): count}. This runs natively
    in VPP (C), aggregates across workers, and lists only nonzero counters, so
    it is far faster than dumping every /err/* counter through vpp_papi. The
    'no error' counters (per-node throughput) are excluded."""
    out = {}
    try:
        res = subprocess.run(shlex.split(vppctl_cmd) + ["show", "errors"],
                             capture_output=True, text=True, timeout=5)
    except Exception:
        return out
    for ln in res.stdout.splitlines():
        toks = ln.split()
        if len(toks) < 3 or not toks[0].isdigit():
            continue  # skip header / blank lines
        count = int(toks[0])
        node = toks[1]
        # reason is between the node and a trailing severity word (if any);
        # scan from the right so a reason ending in 'error' isn't mistaken.
        k = len(toks)
        for i in range(len(toks) - 1, 1, -1):
            if toks[i].lower() in SEV_WORDS:
                k = i
                break
        reason = " ".join(toks[2:k])
        if not reason or reason.lower() == "no error":
            continue
        out[(node, reason)] = out.get((node, reason), 0) + count
    return out


def rank_show_errors(prev, cur, dt, n):
    """Rank (pps, node, reason) by growth between two show-errors snapshots.
    Counters absent from the previous snapshot are baselined (skipped) this
    frame so a newly-appearing counter doesn't spike to its cumulative value."""
    if not prev or n <= 0:
        return []
    errs = []
    for key, c in cur.items():
        if key not in prev:
            continue
        d = c - prev[key]
        if d <= 0:
            continue
        node, reason = key
        errs.append((d / dt, node, reason))
    errs.sort(reverse=True)
    return errs[:n]


# ---- formatting ------------------------------------------------------------
def hbits(v):
    for u in ("bps", "Kbps", "Mbps", "Gbps", "Tbps"):
        if v < 1000:
            return "%6.2f %s" % (v, u)
        v /= 1000.0
    return "%6.2f Pbps" % v


def hpps(v):
    for u in ("pps", "Kpps", "Mpps", "Gpps"):
        if v < 1000:
            return "%6.2f %s" % (v, u)
        v /= 1000.0
    return "%6.2f Tpps" % v


def hcount(v):
    for u in ("", "K", "M", "G", "T"):
        if abs(v) < 1000:
            return "%d%s" % (v, u) if u == "" else "%.2f%s" % (v, u)
        v /= 1000.0
    return "%.2fP" % v


# ---- column system ---------------------------------------------------------
# Interface columns: RX drop = hardware rx (rx-miss/no-buf/error), TX drop =
# hardware tx (tx-error). Software /if/drops shows as an extra SW column under
# detail ('d').
def iface_columns(detail):
    # Software /if/drops is a single, input(rx)-attributed counter in VPP, so in
    # detail mode it shows as an RX-group column. There is no per-egress software
    # drop counter, so no TX sw column exists.
    cols = [
        ("",   "IFACE",     -16, lambda r: r.name),
        ("RX", "RX bw",      13, lambda r: hbits(r.rx_bps)),
        ("RX", "RX pps",     12, lambda r: hpps(r.rx_pps)),
        ("RX", "RX hwdrop/s", 12, lambda r: hpps(r.rx_drop_pps)),
    ]
    if detail:
        cols.append(("RX", "RX swdrop/s", 12, lambda r: hpps(r.sw_drop_pps)))
    cols += [
        ("TX", "TX bw",      13, lambda r: hbits(r.tx_bps)),
        ("TX", "TX pps",     12, lambda r: hpps(r.tx_pps)),
        ("TX", "TX hwdrop/s", 12, lambda r: hpps(r.tx_drop_pps)),
    ]
    return cols


def _cell(text, width):
    return ("%-*.*s" if width < 0 else "%*.*s") % (abs(width), abs(width), text)


def fmt_row(r, cols):
    return " ".join(_cell(fn(r), w) for _, _, w, fn in cols)


def fmt_header(cols):
    return " ".join(_cell(title, w) for _, title, w, _ in cols)


def _group_label(grp, span):
    """Pick the widest decorated form of a group label that fits the span."""
    for cand in ("--- %s ---" % grp, " %s " % grp, grp):
        if len(cand) <= span:
            return cand.center(span)
    return grp[:span]


def fmt_group(cols):
    """Build the super-header, merging consecutive same-group columns into one
    centered label spanning their combined width (+ internal separators)."""
    out, i = [], 0
    while i < len(cols):
        grp = cols[i][0]
        span, cnt, j = 0, 0, i
        while j < len(cols) and cols[j][0] == grp:
            span += abs(cols[j][2])
            cnt += 1
            j += 1
        span += cnt - 1  # spaces between merged columns
        out.append(_group_label(grp, span) if grp else " " * span)
        i = j
    return " ".join(out)


# ---- ranking columns (global, displayed beside interface rows) -------------
# Two side blocks: top drop reasons and top VPP errors. Each block is one
# ranked entry per interface row (rate + node:reason). They are GLOBAL values
# (no per-interface meaning); they share rows with interfaces only for layout.
RANK_RATE_W = 11
RANK_REASON_W = 44
RANK_BLOCK_W = RANK_RATE_W + 1 + RANK_REASON_W
RANK_SEP = "  "
RANK_CAP = 256  # max ranked entries computed per sample (sliced to row count)


def fmt_rank_cell(item):
    if not item:
        return " " * RANK_BLOCK_W
    rate, node, reason = item
    return "%*s %-*.*s" % (RANK_RATE_W, hpps(rate),
                           RANK_REASON_W, RANK_REASON_W,
                           "%s: %s" % (node, reason))


def rank_header():
    return "%*s %-*s" % (RANK_RATE_W, "rate", RANK_REASON_W, "vpp error")


def rank_group():
    return _group_label("TOP VPP ERRORS", RANK_BLOCK_W)


def totals_row(rows):
    return Row(-1, "TOTAL",
               sum(r.rx_bps for r in rows), sum(r.rx_pps for r in rows),
               sum(r.tx_bps for r in rows), sum(r.tx_pps for r in rows),
               sum(r.rx_drop_pps for r in rows), sum(r.tx_drop_pps for r in rows),
               sum(r.sw_drop_pps for r in rows),
               sum(r.rx_drop_cum for r in rows), sum(r.tx_drop_cum for r in rows),
               sum(r.sw_drop_cum for r in rows))


# ---- CSV logging -----------------------------------------------------------
class CsvLogger:
    def __init__(self, path):
        self.f = open(path, "a", buffering=1)
        if self.f.tell() == 0:
            self.f.write("epoch,iface,rx_bps,rx_pps,tx_bps,tx_pps,"
                         "rx_drop_pps,tx_drop_pps,sw_drop_pps,"
                         "rx_drop_cum,tx_drop_cum,sw_drop_cum\n")

    def log(self, rows):
        ts = time.time()
        for r in rows:
            self.f.write("%.3f,%s,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%d,%d,%d\n" % (
                ts, r.name, r.rx_bps, r.rx_pps, r.tx_bps, r.tx_pps,
                r.rx_drop_pps, r.tx_drop_pps, r.sw_drop_pps,
                r.rx_drop_cum, r.tx_drop_cum, r.sw_drop_cum))

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


# ---- curses UI -------------------------------------------------------------
def safe_addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y >= h or x >= w:
        return
    try:
        win.addnstr(y, x, text, max(0, w - x - 1), attr)
    except curses.error:
        pass


def run_curses(stdscr, args, coll, names, csv):
    curses.curs_set(0)
    curses.use_default_colors()
    has_color = curses.has_colors()
    if has_color:
        curses.init_pair(1, curses.COLOR_YELLOW, -1)  # hw drops
        curses.init_pair(3, curses.COLOR_CYAN, -1)    # header / totals
    C_DROP = curses.color_pair(1) if has_color else curses.A_BOLD
    C_HD = curses.color_pair(3) | curses.A_BOLD if has_color else curses.A_BOLD

    stdscr.keypad(True)
    detail = args.detail   # 'd' -> SW drop/s column
    rank = args.rank       # 'e' -> TOP VPP ERRORS ranking (via `show errors`)

    rates = [1.0, 2.0, 5.0, 10.0]   # 'r' cycles refresh interval through these
    interval = args.interval
    rate_idx = rates.index(interval) if interval in rates else 0
    stdscr.timeout(int(interval * 1000))
    prev = coll.snapshot()
    wire, hide_zero, paused = args.wire, args.no_zero, False
    show_vlan = args.show_vlan
    sort_mode = args.sort
    hscroll = 0
    vscroll = 0
    last_rows, last_dt = [], 0.0
    last_errs = []
    prev_err, prev_err_t = {}, time.monotonic()
    next_sample = time.monotonic()

    while True:
        ch = stdscr.getch()
        if ch in (ord("q"), ord("Q")):
            break
        elif ch in (ord("p"), ord("P"), ord(" ")):
            paused = not paused
        elif ch in (ord("w"), ord("W")):
            wire = not wire
        elif ch in (ord("z"), ord("Z")):
            hide_zero = not hide_zero
        elif ch in (ord("r"), ord("R")):
            rate_idx = (rate_idx + 1) % len(rates)
            interval = rates[rate_idx]
            stdscr.timeout(int(interval * 1000))
            next_sample = time.monotonic() + interval
        elif ch in (ord("s"), ord("S")):
            sort_mode = "bw" if sort_mode != "bw" else "name"
        elif ch in (ord("v"), ord("V")):
            show_vlan = not show_vlan
        elif ch in (ord("d"), ord("D")):
            detail = not detail
        elif ch in (ord("e"), ord("E")):
            rank = not rank
            if not rank:
                prev_err = {}
        elif ch == curses.KEY_RIGHT:
            hscroll += 16
        elif ch == curses.KEY_LEFT:
            hscroll = max(0, hscroll - 16)
        elif ch == curses.KEY_DOWN:
            vscroll += 1
        elif ch == curses.KEY_UP:
            vscroll = max(0, vscroll - 1)

        # Sample on the interval only - NOT on every key. Otherwise any keypress
        # (incl. unhandled ones like arrow-key autorepeat) makes getch return
        # early, shrinking dt and making the rates jump around.
        if not paused and time.monotonic() >= next_sample:
            cur = coll.snapshot()
            rows, last_dt = compute(prev, cur, names, wire)
            prev = cur
            last_rows = rows
            if csv:
                csv.log(rows)
            if rank:
                cur_err = read_show_errors(args.vppctl)
                now = time.monotonic()
                last_errs = rank_show_errors(prev_err, cur_err,
                                             max(1e-9, now - prev_err_t), RANK_CAP)
                prev_err, prev_err_t = cur_err, now
            next_sample = time.monotonic() + interval

        cols = iface_columns(detail)
        header = fmt_header(cols)
        group = fmt_group(cols)
        if rank:
            header += RANK_SEP + rank_header()
            group += RANK_SEP + rank_group()
        iface_w = len(fmt_header(cols))

        visible = last_rows
        if not show_vlan:
            visible = [r for r in visible if not is_vlan(r.name)]
        display = visible
        if hide_zero:
            display = [r for r in display
                       if r.rx_pps or r.tx_pps or r.rx_drop_pps
                       or r.tx_drop_pps or r.sw_drop_pps]
        display = sort_rows(display, sort_mode)

        # Fixed header lines (column labels, always visible).
        head_lines = [(group, C_HD), (header, curses.A_BOLD)]
        # Scrollable data rows.
        data_lines = []
        for i, r in enumerate(display):
            line = fmt_row(r, cols)
            if rank:
                ei = last_errs[i] if i < len(last_errs) else None
                line += RANK_SEP + fmt_rank_cell(ei)
            attr = C_DROP if (r.rx_drop_pps or r.tx_drop_pps) else 0
            data_lines.append((line, attr))
        # Footer (separator + totals), shown after the data rows.
        foot_lines = []
        if display:
            foot_lines.append(("-" * iface_w, 0))
            foot_lines.append((fmt_row(totals_row(visible), cols), C_HD))
        foot_lines.append((
            "keys: q quit  p pause  s sort  d details  e errors  "
            "v vlan  w wire  z hide-idle  r rate",
            curses.A_DIM))

        H, W = stdscr.getmaxyx()
        top = 1 + len(head_lines)              # title + group + header
        avail = max(0, H - top - len(foot_lines))
        max_v = max(0, len(data_lines) - avail)
        vscroll = max(0, min(vscroll, max_v))
        shown = data_lines[vscroll:vscroll + avail]

        all_lines = head_lines + data_lines + foot_lines
        maxw = max((len(t) for t, _ in all_lines), default=0)
        hscroll = max(0, min(hscroll, max(0, maxw - max(1, W - 1))))

        stdscr.erase()
        title = ("vpptop  socket=%s  iv=%.2fs  dt=%.3fs  sort=%s"
                 "%s%s%s%s%s%s%s" % (
                     coll.socket, interval, last_dt, sort_mode,
                     "  WIRE" if wire else "  L2-only",
                     "  DETAILS" if detail else "",
                     "  RANK" if rank else "",
                     "  +VLAN" if show_vlan else "",
                     "  [PAUSED]" if paused else "",
                     "  >>%d" % hscroll if hscroll else "",
                     "  v%d/%d" % (vscroll, max_v) if max_v else ""))
        safe_addstr(stdscr, 0, 0, title, C_HD)
        y = 1
        for text, attr in head_lines:
            safe_addstr(stdscr, y, 0, text[hscroll:], attr)
            y += 1
        for text, attr in shown:
            safe_addstr(stdscr, y, 0, text[hscroll:], attr)
            y += 1
        for text, attr in foot_lines:
            safe_addstr(stdscr, y, 0, text[hscroll:], attr)
            y += 1
        stdscr.refresh()


# ---- plain (non-curses) mode ----------------------------------------------
def run_plain(args, coll, names, csv):
    detail = args.detail   # SW drop/s column
    rank = args.rank       # TOP VPP ERRORS ranking (via `show errors`)
    prev = coll.snapshot()
    prev_err, prev_err_t = {}, time.monotonic()
    next_t = time.monotonic() + args.interval
    while True:
        time.sleep(max(0, next_t - time.monotonic()))
        next_t += args.interval
        cur = coll.snapshot()
        rows, dt = compute(prev, cur, names, args.wire)
        prev = cur
        errs = []
        if rank:
            cur_err = read_show_errors(args.vppctl)
            now = time.monotonic()
            errs = rank_show_errors(prev_err, cur_err,
                                    max(1e-9, now - prev_err_t), RANK_CAP)
            prev_err, prev_err_t = cur_err, now
        if csv:
            csv.log(rows)  # CSV keeps every interface (incl. VLANs)
        cols = iface_columns(detail)
        header = fmt_header(cols)
        group = fmt_group(cols)
        if rank:
            header += RANK_SEP + rank_header()
            group += RANK_SEP + rank_group()
        visible = rows
        if not args.show_vlan:
            visible = [r for r in visible if not is_vlan(r.name)]
        display = visible
        if args.no_zero:
            display = [r for r in display
                       if r.rx_pps or r.tx_pps or r.rx_drop_pps
                       or r.tx_drop_pps or r.sw_drop_pps]
        display = sort_rows(display, args.sort)
        ts = time.strftime("%H:%M:%S")
        print("=== %s  dt=%.3fs  %s%s%s ===" % (
            ts, dt, "WIRE" if args.wire else "L2-only",
            "  DETAILS" if detail else "", "  RANK" if rank else ""))
        print(group)
        print(header)
        for i, r in enumerate(display):
            line = fmt_row(r, cols)
            if rank:
                ei = errs[i] if i < len(errs) else None
                line += RANK_SEP + fmt_rank_cell(ei)
            print(line)
        if visible:
            print(fmt_row(totals_row(visible), cols))
        print()


def main():
    ap = argparse.ArgumentParser(
        description="Real-time VPP per-interface bandwidth / pps / drop monitor.")
    ap.add_argument("-s", "--socket", default="/run/vpp/stats.sock",
                    help="VPP stats segment socket (default: %(default)s)")
    ap.add_argument("-i", "--interval", type=float, default=1.0,
                    help="sample interval in seconds (default: 1.0; sub-second OK)")
    ap.add_argument("--vppctl", default="vppctl",
                    help="vppctl command for name resolution, e.g. "
                         "'sudo vppctl' or 'vppctl -s /run/vpp/cli.sock'")
    ap.add_argument("--no-wire", dest="wire", action="store_false",
                    help="show L2 throughput only; do NOT add the 24B/pkt "
                         "Ethernet wire overhead (wire-rate is on by default)")
    ap.set_defaults(wire=True)
    ap.add_argument("--detail", action="store_true",
                    help="show detail columns (currently the SW drop/s column, "
                         "software /if/drops); 'd' toggles")
    ap.add_argument("--rank", action="store_true",
                    help="show the TOP VPP ERRORS ranking column (parsed from "
                         "`vppctl show errors`); 'e' toggles")
    ap.add_argument("--no-zero", action="store_true",
                    help="hide interfaces with no current traffic or drops")
    ap.add_argument("--sort", default="name",
                    choices=["bw", "pps", "rxdrop", "txdrop", "idx", "name"],
                    help="initial sort order (default: name; 's' toggles name/rate)")
    ap.add_argument("--show-vlan", action="store_true",
                    help="show VLAN sub-interfaces (hidden by default; 'v' toggles)")
    ap.add_argument("--plain", action="store_true",
                    help="plain streaming output instead of the curses UI")
    ap.add_argument("--csv", metavar="FILE",
                    help="append per-sample rows to a CSV file (works in either mode)")
    args = ap.parse_args()
    if args.interval <= 0:
        ap.error("--interval must be greater than 0")

    try:
        coll = Collector(args.socket)
    except StartupError as e:
        write_startup_error(e)
        raise SystemExit(1)
    except Exception as e:
        write_startup_error(StartupError(
            "cannot initialize VPP stats collector",
            "Cannot open %s: %s." % (args.socket, e),
            (
                "make sure VPP is running",
                "pass the correct stats socket with --socket PATH",
                "run vpptop as a user with permission to read the stats socket",
            )))
        raise SystemExit(1)

    names = resolve_names(args.vppctl)
    csv = CsvLogger(args.csv) if args.csv else None
    exit_code = 0
    try:
        if args.plain:
            run_plain(args, coll, names, csv)
        else:
            curses.wrapper(run_curses, args, coll, names, csv)
    except KeyboardInterrupt:
        pass  # clean exit on Ctrl+C (curses.wrapper has already restored the tty)
    except curses.error as e:
        sys.stderr.write("curses error: %s\n"
                         "(try --plain if the terminal is too small or not a tty)\n"
                         % e)
        exit_code = 1
    except Exception as e:
        sys.stderr.write("vpptop exited: %s\n" % e)
        exit_code = 1
    finally:
        if csv:
            csv.close()
    raise SystemExit(exit_code)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
