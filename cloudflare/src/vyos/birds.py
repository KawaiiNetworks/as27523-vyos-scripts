#!/usr/bin/env python3
"""birds — a compact, human-friendly `birdc show protocols all` view.

Parses BIRD's `show protocols all` output into an aligned table with one row
per protocol (name, proto, table/VRF, neighbor IP, state, info, uptime, and
exported/imported/filtered route counts). Reads from stdin when piped, otherwise
runs `birdc` itself. In a terminal it colours the State and Info columns by
state and pages long output through `less`, auto-closing the pager when the
window is enlarged enough to fit the whole table.
"""
import os
import re
import shutil
import signal
import subprocess
import sys
from datetime import datetime, timedelta

# ANSI colours for the State column, only emitted to a real terminal
# (less -R renders them).
RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"

# State of the pager, shared with the SIGWINCH handler.
pager_process = None
content_req_lines = 0
content_req_width = 0


def get_bird_output():
    """Run `birdc show protocols all` and return its output as a list of lines."""
    try:
        result = subprocess.run(
            ["birdc", "-r", "show", "protocols", "all"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            print(f"birdc failed: {result.stderr.strip()}")
            sys.exit(1)
        return result.stdout.splitlines()
    except FileNotFoundError:
        print("error: 'birdc' not found — is BIRD installed and on PATH?")
        sys.exit(1)


def calculate_uptime(since_str):
    """Convert BIRD's `Since` timestamp into an uptime duration (e.g. '3d 04:05:06')."""
    if since_str == "-" or not since_str:
        return "-"

    now = datetime.now()
    try:
        if " " in since_str:
            date_part, time_part = since_str.split(" ", 1)
            if len(time_part.split(":")) == 2:
                time_part += ":00"
            since_time = datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S")
        elif "-" in since_str:
            since_time = datetime.strptime(since_str, "%Y-%m-%d")
        elif ":" in since_str:
            time_part = since_str
            if len(time_part.split(":")) == 2:
                time_part += ":00"
            t = datetime.strptime(time_part, "%H:%M:%S").time()
            since_time = datetime.combine(now.date(), t)
            # A bare time later than now must belong to yesterday.
            if since_time > now:
                since_time -= timedelta(days=1)
        else:
            return since_str

        diff = now - since_time
        total_seconds = int(diff.total_seconds())
        if total_seconds < 0:
            return since_str

        days, remainder = divmod(total_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)

        if days > 0:
            return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    except Exception:
        return since_str


def parse_bird_output(lines):
    """Parse `show protocols all` into a list of per-protocol dicts."""
    protocols = []
    current_proto = None
    header_regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$")

    for line in lines:
        if not line.strip():
            continue
        if line.startswith("BIRD ") and "ready" in line:
            continue
        if line.startswith("Name ") and "Proto " in line:
            continue

        if not line[0].isspace():
            match = header_regex.match(line)
            if match:
                if current_proto:
                    protocols.append(current_proto)

                name, proto, table, state, since, info = match.groups()
                info = info.strip() if info else ""

                # BIRD sometimes folds a `HH:MM:SS` time into the Info column
                # when Since is just a date; split it back out.
                time_match = re.match(r"^(\d{2}:\d{2}:\d{2}|\d{2}:\d{2})\s*(.*)$", info)
                if re.match(r"^\d{4}-\d{2}-\d{2}$", since) and time_match:
                    since = f"{since} {time_match.group(1)}"
                    info = time_match.group(2)

                # The Info column is a single token (e.g. 'Established', 'Idle');
                # some protocols (BMP) append free-form detail after it — the
                # real message is the `Last error:` detail line, so keep only the
                # leading token here.
                info_parts = info.split()
                info = info_parts[0] if info_parts else ""

                current_proto = {
                    "Name": name,
                    "Proto": proto,
                    "VRF": table,
                    "NeighborIP": "-",
                    "State": state,
                    "Info": info if info else "-",
                    "Last error": "-",
                    "Uptime": calculate_uptime(since),
                    "Exported": "-",
                    "Imported": "-",
                    "ImportLimit": "-",
                    "Filtered": "-",
                }
        else:
            if not current_proto:
                continue

            line_stripped = line.strip()

            if line_stripped.startswith("Neighbor address:"):
                current_proto["NeighborIP"] = line_stripped.split(":", 1)[1].strip()
            elif line_stripped.startswith("Last error:"):
                current_proto["Last error"] = line_stripped.split(":", 1)[1].strip()
            elif line_stripped.startswith("Import limit:"):
                current_proto["ImportLimit"] = line_stripped.split(":", 1)[1].strip()
            # Multi-channel protocols show '---' in the Table column; pull the
            # real table name from the first channel detail line instead.
            elif line_stripped.startswith("Table:") and current_proto["VRF"] == "---":
                current_proto["VRF"] = line_stripped.split(":", 1)[1].strip()
            elif line_stripped.startswith("Routes:"):
                routes_str = line_stripped.split(":", 1)[1]

                exp_m = re.search(r"(\d+)\s+exported", routes_str)
                if exp_m:
                    current_proto["Exported"] = exp_m.group(1)

                imp_m = re.search(r"(\d+)\s+imported", routes_str)
                if imp_m:
                    current_proto["Imported"] = imp_m.group(1)

                filt_m = re.search(r"(\d+)\s+filtered", routes_str)
                current_proto["Filtered"] = filt_m.group(1) if filt_m else "-"

    if current_proto:
        protocols.append(current_proto)

    return protocols


def _name_sort_key(name):
    """Natural sort key for protocol names so e.g. 'peer2' sorts before 'peer10'."""
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", name)]


# Order of BGP neighbour types, keyed by the type letter that prefixes the
# protocol name (e.g. 'u_as12345_nid1_v4', or 'vrf_3_u_as...' inside a VRF):
# IBGP, Upstream, RouteServer, Peer, Downstream.
BGP_TYPE_ORDER = {"i": 0, "u": 1, "r": 2, "p": 3, "d": 4}


def _sort_key(p):
    """Sort by Proto (bgp always last), then by Name.

    Within bgp, group by neighbour-type letter (i < u < r < p < d) first.
    """
    proto = p["Proto"].lower()
    is_bgp = proto == "bgp"
    bgp_type = 99
    if is_bgp:
        m = re.match(r"(?:vrf_\d+_)?([a-z])_as", p["Name"])
        if m:
            bgp_type = BGP_TYPE_ORDER.get(m.group(1), 98)
    return (1 if is_bgp else 0, proto, bgp_type, _name_sort_key(p["Name"]))


def _state_color(state):
    """BIRD-style colour for a protocol state."""
    state = state.lower()
    if state == "up":
        return GREEN
    if state == "start":
        return YELLOW
    return RED  # down / disabled / anything else


# Columns coloured (by state) in a terminal.
COLOR_COLS = ("State", "Info")


def generate_table_text(protocols, use_color):
    """Build the aligned table text (with a count footer)."""
    if not protocols:
        return "No protocols found.\n"

    protocols = sorted(protocols, key=_sort_key)

    # Combine imported count and import limit into one cell, e.g. '155/1000'
    # (or '155/-' when the channel has no import limit).
    for p in protocols:
        p["Import/Limit"] = f"{p['Imported']}/{p['ImportLimit']}" if p["Imported"] != "-" else "-"

    cols = ["Name", "Proto", "VRF", "NeighborIP", "State", "Info", "Last error",
            "Uptime", "Import/Limit", "Exported", "Filtered"]

    widths = {col: len(col) for col in cols}
    widths["NeighborIP"] = max(widths["NeighborIP"], 15)
    widths["Info"] = max(widths["Info"], 12)
    for p in protocols:
        for col in cols:
            widths[col] = max(widths[col], len(str(p[col])))

    format_str = "  ".join([f"{{:<{widths[col]}}}" for col in cols])

    header = format_str.format(*cols)
    out = [header, "-" * len(header)]

    up = down = 0
    for p in protocols:
        if p["State"].lower() == "up":
            up += 1
        else:
            down += 1
        if use_color:
            # Pad every cell, then wrap the padded coloured cells so column
            # alignment is preserved (ANSI codes add no visible width).
            color = _state_color(p["State"])
            cells = [f"{str(p[col]):<{widths[col]}}" for col in cols]
            for cc in COLOR_COLS:
                idx = cols.index(cc)
                cells[idx] = f"{color}{cells[idx]}{RESET}"
            row = "  ".join(cells)
        else:
            row = format_str.format(*[p[col] for col in cols])
        out.append(row)

    out.append("-" * len(header))
    footer = f"{len(protocols)} protocols  ({up} up, {down} down)"
    out.append(footer)

    return "\n".join(out) + "\n"


def sigwinch_handler(signum, frame):
    """On terminal resize, quit the pager once the window can hold the whole table."""
    global pager_process, content_req_lines, content_req_width
    if pager_process is not None and pager_process.poll() is None:
        term_size = shutil.get_terminal_size(fallback=(80, 24))
        if content_req_lines < (term_size.lines - 3) and content_req_width <= term_size.columns:
            pager_process.terminate()


def display_output(text):
    """Print directly if it fits, else page through `less` (auto-quit on resize)."""
    global pager_process, content_req_lines, content_req_width

    if not sys.stdout.isatty():
        print(text, end="")  # piped: emit plain text
        return

    lines = text.splitlines()
    content_req_lines = len(lines)
    # Strip ANSI when measuring width so colours don't inflate the count.
    content_req_width = max((len(re.sub(r"\033\[[0-9;]*m", "", ln)) for ln in lines), default=0)

    term_size = shutil.get_terminal_size(fallback=(80, 24))
    if content_req_lines < (term_size.lines - 3) and content_req_width <= term_size.columns:
        print(text, end="")
        return

    try:
        signal.signal(signal.SIGWINCH, sigwinch_handler)
    except AttributeError:
        pass  # non-Unix: no SIGWINCH

    try:
        env = os.environ.copy()
        env["LESS"] = "-SRXF"
        pager_process = subprocess.Popen(["less"], stdin=subprocess.PIPE, text=True, env=env)
        pager_process.communicate(input=text)
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    except FileNotFoundError:
        print(text, end="")


if __name__ == "__main__":
    if not sys.stdin.isatty():
        lines = sys.stdin.read().splitlines()
    else:
        lines = get_bird_output()

    protocols = parse_bird_output(lines)
    table_text = generate_table_text(protocols, use_color=sys.stdout.isatty())
    display_output(table_text)
