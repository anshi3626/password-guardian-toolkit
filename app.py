"""
Password Guardian
==================
A college-project-friendly GUI application that:
  1. Analyzes password strength (entropy, patterns, estimated crack time)
  2. Checks whether a password has appeared in known public data breaches
     using the k-anonymity method (only the first 5 characters of the
     SHA-1 hash are ever sent over the network — the real password or
     its full hash never leaves the machine).

This project is intentionally DEFENSIVE: it helps users understand and
improve password security, rather than attacking or cracking passwords.

Author: (your name here)
Course: (your course/subject here)
"""

import hashlib
import math
import re
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ----------------------------------------------------------------------
# 1. PASSWORD STRENGTH ANALYSIS
# ----------------------------------------------------------------------

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein",
    "welcome", "monkey", "login", "iloveyou", "qwerty123", "dragon",
    "football", "1234567", "123321", "000000", "sunshine", "princess",
}


def calculate_entropy(password: str) -> float:
    """Shannon-style entropy estimate based on character pool size."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # approx. printable symbol space

    if pool == 0 or len(password) == 0:
        return 0.0

    return len(password) * math.log2(pool)


def estimate_crack_time(entropy_bits: float, guesses_per_second: float = 1e10) -> str:
    """
    Rough offline-attack crack time estimate assuming an attacker with a
    modern GPU rig doing ~10 billion guesses/sec against a fast hash.
    This is for EDUCATIONAL illustration only.
    """
    if entropy_bits <= 0:
        return "instantly"

    seconds = (2 ** entropy_bits) / guesses_per_second / 2  # average case

    units = [
        ("seconds", 60),
        ("minutes", 60),
        ("hours", 24),
        ("days", 365),
        ("years", 100),
        ("centuries", float("inf")),
    ]

    value = seconds
    unit_name = "seconds"
    for name, factor in units:
        unit_name = name
        if value < factor:
            break
        value /= factor

    return f"~{value:,.1f} {unit_name}"


def analyze_password(password: str) -> dict:
    result = {
        "length": len(password),
        "entropy": 0.0,
        "crack_time": "instantly",
        "score": 0,
        "label": "Very Weak",
        "issues": [],
    }

    if not password:
        result["issues"].append("Password is empty.")
        return result

    if password.lower() in COMMON_PASSWORDS:
        result["issues"].append("This is one of the most common passwords in the world.")

    if len(password) < 8:
        result["issues"].append("Too short — use at least 12 characters.")

    if not re.search(r"[A-Z]", password):
        result["issues"].append("Add at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        result["issues"].append("Add at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        result["issues"].append("Add at least one digit.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        result["issues"].append("Add at least one special character (!@#$...).")

    if re.search(r"(.)\1\1", password):
        result["issues"].append("Avoid repeating the same character 3+ times in a row.")

    if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde)", password.lower()):
        result["issues"].append("Avoid simple sequences like '123' or 'abc'.")

    entropy = calculate_entropy(password)
    result["entropy"] = entropy
    result["crack_time"] = estimate_crack_time(entropy)

    # Composite score 0-100
    score = min(100, int(entropy / 128 * 100))
    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 5)
    result["score"] = score

    if score < 20:
        result["label"] = "Very Weak"
    elif score < 40:
        result["label"] = "Weak"
    elif score < 60:
        result["label"] = "Fair"
    elif score < 80:
        result["label"] = "Strong"
    else:
        result["label"] = "Very Strong"

    return result


# ----------------------------------------------------------------------
# 2. BREACH CHECK (k-ANONYMITY MODEL — Have I Been Pwned API)
# ----------------------------------------------------------------------

def check_breach(password: str):
    """
    Implements the k-anonymity range search used by the real-world
    "Have I Been Pwned" Pwned Passwords API.

    How it works (this IS the concept to explain in your viva):
      1. SHA-1 hash the password locally.
      2. Send ONLY the first 5 hex characters of the hash to the API.
      3. The API returns ALL hash suffixes that share that 5-char prefix
         (thousands of them), along with how many times each has been
         seen in breaches.
      4. We check locally whether our full hash's suffix is in that list.

    This means the server never learns the real password or even the
    full hash — only a 5-character prefix shared by thousands of other
    hashes. That's the "anonymity set" — hence k-anonymity.

    Returns: (is_breached: bool, count: int, error: str or None)
    """
    if not REQUESTS_AVAILABLE:
        return None, 0, "The 'requests' library is not installed. Run: pip install requests"

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=8,
            headers={"User-Agent": "PasswordGuardian-CollegeProject"},
        )
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        return None, 0, f"Network error: {exc}"

    for line in resp.text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        hash_suffix, count = line.split(":", 1)
        if hash_suffix.strip().upper() == suffix:
            return True, int(count.strip()), None

    return False, 0, None


# ----------------------------------------------------------------------
# 3. HASH ALGORITHM VISUALIZER / COMPARATOR
# ----------------------------------------------------------------------

HASH_ALGORITHMS = [
    ("MD5", hashlib.md5, 128, "Broken — collisions found in 2004. Never use for security."),
    ("SHA-1", hashlib.sha1, 160, "Deprecated — collision attacks demonstrated in 2017 (SHAttered)."),
    ("SHA-256", hashlib.sha256, 256, "Secure & widely used, but FAST — unsuitable alone for passwords."),
    ("SHA-512", hashlib.sha512, 512, "Secure & widely used, but FAST — unsuitable alone for passwords."),
]

# How many times to hash in a loop to get a measurable, comparable timing.
BENCHMARK_ITERATIONS = 200_000


def compare_hashes(text: str) -> list:
    """
    Returns a list of dicts, one per algorithm, with the digest and a
    rough relative speed benchmark (hashes/sec for this machine).

    Teaching point: ALL of these general-purpose hashes are deliberately
    FAST — great for checksums, terrible for password storage, because
    an attacker can try billions of guesses per second. That's why
    bcrypt/scrypt/Argon2 (which are deliberately SLOW and memory-hard)
    exist for password hashing instead.
    """
    data = text.encode("utf-8")
    results = []
    for name, func, bits, note in HASH_ALGORITHMS:
        digest = func(data).hexdigest()

        start = time.perf_counter()
        for _ in range(BENCHMARK_ITERATIONS):
            func(data).hexdigest()
        elapsed = time.perf_counter() - start
        hashes_per_sec = BENCHMARK_ITERATIONS / elapsed if elapsed > 0 else 0

        results.append({
            "name": name,
            "digest": digest,
            "bits": bits,
            "hashes_per_sec": hashes_per_sec,
            "note": note,
        })
    return results


# ----------------------------------------------------------------------
# 4. GUI
# ----------------------------------------------------------------------


# ----------------------------------------------------------------------
# 4. THEME
# ----------------------------------------------------------------------

class Theme:
    BG = "#111827"          # app background (slate-900)
    SURFACE = "#1a2234"      # card background
    SURFACE_ALT = "#222c42"  # input / nested surface
    BORDER = "#2d3b55"
    HEADER_BG = "#0d1420"
    ACCENT = "#3b82f6"       # blue-500
    ACCENT_DARK = "#2563eb"
    TEXT = "#e5e9f0"
    TEXT_MUTED = "#8b96ad"
    SUCCESS = "#22c55e"
    WARNING = "#eab308"
    DANGER = "#ef4444"
    INFO = "#38bdf8"

    FONT_FAMILY = "Segoe UI"


# ----------------------------------------------------------------------
# 5. GUI
# ----------------------------------------------------------------------

class PasswordGuardianApp:
    def __init__(self, root):
        self.root = root
        root.title("Password Guardian  |  Password Security Toolkit")
        root.geometry("700x780")
        root.minsize(620, 500)
        root.configure(bg=Theme.BG)

        self._build_styles()
        self._build_menu()
        self._build_header()
        self._build_body()
        self._build_statusbar()

    # ------------------------------------------------------------------
    # Chrome: styles, menu, header, status bar
    # ------------------------------------------------------------------

    def _build_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TFrame", background=Theme.BG)
        style.configure("Surface.TFrame", background=Theme.SURFACE)
        style.configure("Header.TFrame", background=Theme.HEADER_BG)
        style.configure("Status.TFrame", background=Theme.HEADER_BG)

        style.configure("TLabel", background=Theme.BG, foreground=Theme.TEXT,
                         font=(Theme.FONT_FAMILY, 10))
        style.configure("Surface.TLabel", background=Theme.SURFACE, foreground=Theme.TEXT,
                         font=(Theme.FONT_FAMILY, 10))
        style.configure("Muted.Surface.TLabel", background=Theme.SURFACE, foreground=Theme.TEXT_MUTED,
                         font=(Theme.FONT_FAMILY, 8))
        style.configure("Muted.TLabel", background=Theme.BG, foreground=Theme.TEXT_MUTED,
                         font=(Theme.FONT_FAMILY, 8))

        style.configure("AppTitle.TLabel", background=Theme.HEADER_BG, foreground="#ffffff",
                         font=(Theme.FONT_FAMILY, 15, "bold"))
        style.configure("AppSubtitle.TLabel", background=Theme.HEADER_BG, foreground=Theme.TEXT_MUTED,
                         font=(Theme.FONT_FAMILY, 9))
        style.configure("SectionTitle.Surface.TLabel", background=Theme.SURFACE, foreground=Theme.TEXT,
                         font=(Theme.FONT_FAMILY, 11, "bold"))
        style.configure("Score.Surface.TLabel", background=Theme.SURFACE, font=(Theme.FONT_FAMILY, 15, "bold"))
        style.configure("Status.TLabel", background=Theme.HEADER_BG, foreground=Theme.TEXT_MUTED,
                         font=(Theme.FONT_FAMILY, 8))

        style.configure("TButton", font=(Theme.FONT_FAMILY, 10, "bold"), padding=8,
                         background=Theme.ACCENT, foreground="#ffffff", borderwidth=0)
        style.map("TButton",
                  background=[("active", Theme.ACCENT_DARK), ("disabled", Theme.BORDER)],
                  foreground=[("disabled", Theme.TEXT_MUTED)])

        style.configure("TCheckbutton", background=Theme.SURFACE, foreground=Theme.TEXT,
                         font=(Theme.FONT_FAMILY, 9))
        style.map("TCheckbutton", background=[("active", Theme.SURFACE)])

        style.configure("TEntry", fieldbackground=Theme.SURFACE_ALT, foreground=Theme.TEXT,
                         insertcolor=Theme.TEXT, borderwidth=1, padding=8)
        style.map("TEntry", bordercolor=[("focus", Theme.ACCENT)])

        style.configure("TSeparator", background=Theme.BORDER)

        style.configure("Horizontal.TProgressbar", thickness=10, background=Theme.ACCENT,
                         troughcolor=Theme.SURFACE_ALT, borderwidth=0)

        style.configure("TNotebook", background=Theme.BG, borderwidth=0, tabmargins=(0, 8, 0, 0))
        style.configure("TNotebook.Tab", background=Theme.SURFACE, foreground=Theme.TEXT_MUTED,
                         font=(Theme.FONT_FAMILY, 10, "bold"), padding=(18, 10), borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", Theme.ACCENT)],
                  foreground=[("selected", "#ffffff")])

    def _build_menu(self):
        menubar = tk.Menu(self.root)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About Password Guardian", command=self._show_about)
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    def _show_about(self):
        messagebox.showinfo(
            "About Password Guardian",
            "Password Guardian v1.0\n\n"
            "A defensive password-security toolkit built for academic\n"
            "demonstration of hashing, entropy, and k-anonymity.\n\n"
            "Modules: Strength Analyzer · Breach Checker · Hash Visualizer"
        )

    def _build_header(self):
        header = ttk.Frame(self.root, style="Header.TFrame")
        header.pack(fill="x", side="top")

        inner = ttk.Frame(header, style="Header.TFrame", padding=(24, 18, 24, 18))
        inner.pack(fill="x")

        badge = tk.Label(inner, text="🔐", font=(Theme.FONT_FAMILY, 22), bg=Theme.HEADER_BG, fg="#ffffff")
        badge.pack(side="left", padx=(0, 14))

        text_col = ttk.Frame(inner, style="Header.TFrame")
        text_col.pack(side="left", fill="x", expand=True)
        ttk.Label(text_col, text="Password Guardian", style="AppTitle.TLabel").pack(anchor="w")
        ttk.Label(text_col, text="Strength Analysis  •  Breach Detection  •  Hash Comparison",
                  style="AppSubtitle.TLabel").pack(anchor="w", pady=(2, 0))

        version = ttk.Label(inner, text="v1.0", style="AppSubtitle.TLabel")
        version.pack(side="right", anchor="n")

        accent_bar = tk.Frame(self.root, bg=Theme.ACCENT, height=3)
        accent_bar.pack(fill="x", side="top")

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, style="Status.TFrame", padding=(16, 6))
        bar.pack(fill="x", side="bottom")

        network_text = "● Network: requests library loaded" if REQUESTS_AVAILABLE else "● Network: requests NOT installed"
        network_color = Theme.SUCCESS if REQUESTS_AVAILABLE else Theme.DANGER
        self.network_status = tk.Label(bar, text=network_text, bg=Theme.HEADER_BG, fg=network_color,
                                        font=(Theme.FONT_FAMILY, 8))
        self.network_status.pack(side="left")

        ttk.Label(bar, text="Educational / Defensive Security Tool", style="Status.TLabel").pack(side="right")

    def _build_body(self):
        container = ttk.Frame(self.root, padding=(16, 16, 16, 8))
        container.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill="both", expand=True)

        tab1 = ttk.Frame(self.notebook, padding=0)
        tab2 = ttk.Frame(self.notebook, padding=0)
        self.notebook.add(tab1, text="  🛡  Strength & Breach Check  ")
        self.notebook.add(tab2, text="  🧮  Hash Visualizer  ")

        self.tab_canvases = {}
        scroll1 = self._build_scrollable(tab1, tab_index=0)
        scroll2 = self._build_scrollable(tab2, tab_index=1)

        self._build_strength_tab(scroll1)
        self._build_hash_tab(scroll2)

        self.root.bind_all("<MouseWheel>", self._on_mousewheel)   # Windows / macOS
        self.root.bind_all("<Button-4>", self._on_mousewheel)     # Linux scroll up
        self.root.bind_all("<Button-5>", self._on_mousewheel)     # Linux scroll down

    def _build_scrollable(self, parent, tab_index):
        """
        Wraps a tab's content in a Canvas + Scrollbar so that content taller
        than the window is still fully reachable (fixes content being cut
        off at the bottom on smaller screens/windows).
        """
        canvas = tk.Canvas(parent, bg=Theme.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas, padding=(4, 16, 10, 16))

        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        def _update_scrollregion(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _sync_width(event):
            canvas.itemconfig(window_id, width=event.width)

        inner.bind("<Configure>", _update_scrollregion)
        canvas.bind("<Configure>", _sync_width)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tab_canvases[tab_index] = canvas
        return inner

    def _on_mousewheel(self, event):
        canvas = self.tab_canvases.get(self.notebook.index(self.notebook.select()))
        if not canvas:
            return
        if event.num == 4:
            canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            canvas.yview_scroll(1, "units")
        else:
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _card(self, parent, title=None, pady_outer=(0, 14)):
        """A bordered 'card' container with an optional title row."""
        outer = tk.Frame(parent, bg=Theme.BORDER)
        outer.pack(fill="x", pady=pady_outer)

        inner = ttk.Frame(outer, style="Surface.TFrame", padding=18)
        inner.pack(fill="both", expand=True, padx=1, pady=1)

        if title:
            ttk.Label(inner, text=title, style="SectionTitle.Surface.TLabel").pack(anchor="w", pady=(0, 12))

        return inner

    # ------------------------------------------------------------------
    # Tab 1: Strength & Breach Check
    # ------------------------------------------------------------------

    def _build_strength_tab(self, parent):
        wrapper = ttk.Frame(parent, padding=(4, 16, 4, 4))
        wrapper.pack(fill="both", expand=True)

        card = self._card(wrapper, title="Password Strength Analysis")

        ttk.Label(card, text="Enter a password to test", style="Surface.TLabel").pack(anchor="w", pady=(0, 6))

        entry_row = ttk.Frame(card, style="Surface.TFrame")
        entry_row.pack(fill="x", pady=(0, 14))

        self.password_var = tk.StringVar()
        self.entry = ttk.Entry(entry_row, textvariable=self.password_var, show="●",
                                font=(Theme.FONT_FAMILY, 13))
        self.entry.pack(side="left", fill="x", expand=True, ipady=3)
        self.password_var.trace_add("write", lambda *a: self.on_password_change())

        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(entry_row, text="Show", variable=self.show_var,
                         command=self.toggle_show).pack(side="left", padx=(10, 0))

        # Strength meter row
        meter_row = ttk.Frame(card, style="Surface.TFrame")
        meter_row.pack(fill="x", pady=(0, 4))
        self.score_label = ttk.Label(meter_row, text="Strength: —", style="Score.Surface.TLabel")
        self.score_label.pack(side="left")

        self.progress = ttk.Progressbar(card, orient="horizontal", mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(6, 10))

        self.details_label = ttk.Label(card, text="Length: —   |   Entropy: —   |   Est. crack time: —",
                                        style="Muted.Surface.TLabel", wraplength=560, justify="left")
        self.details_label.pack(anchor="w", pady=(0, 12))

        ttk.Label(card, text="Checklist", style="Surface.TLabel").pack(anchor="w", pady=(0, 4))
        self.issues_text = tk.Text(card, height=6, font=(Theme.FONT_FAMILY, 9),
                                    bg=Theme.SURFACE_ALT, fg=Theme.TEXT, relief="flat",
                                    padx=10, pady=8, highlightthickness=1,
                                    highlightbackground=Theme.BORDER, highlightcolor=Theme.ACCENT)
        self.issues_text.pack(fill="x")
        self.issues_text.configure(state="disabled")

        # Breach check card
        breach_card = self._card(wrapper, title="Data Breach Check")

        ttk.Label(breach_card,
                  text="Checks this password against known public breach databases "
                       "using the k-anonymity method (privacy-preserving lookup).",
                  style="Muted.Surface.TLabel", wraplength=560, justify="left").pack(anchor="w", pady=(0, 12))

        self.breach_btn = ttk.Button(breach_card, text="🌐  Check for Breaches", command=self.on_breach_check)
        self.breach_btn.pack(fill="x")

        self.breach_result = tk.Label(breach_card, text="", font=(Theme.FONT_FAMILY, 10, "bold"),
                                       bg=Theme.SURFACE, anchor="w", justify="left", wraplength=560)
        self.breach_result.pack(fill="x", pady=(12, 0))

    def toggle_show(self):
        self.entry.configure(show="" if self.show_var.get() else "●")

    def on_password_change(self):
        pw = self.password_var.get()
        result = analyze_password(pw)

        self.progress["value"] = result["score"]
        color = self._score_color(result["score"])
        self.score_label.configure(text=f"Strength: {result['label']}  ({result['score']}/100)",
                                    foreground=color)

        self.details_label.configure(
            text=f"Length: {result['length']}   |   Entropy: {result['entropy']:.1f} bits   |   "
                 f"Est. offline crack time: {result['crack_time']}"
        )

        self.issues_text.configure(state="normal")
        self.issues_text.delete("1.0", tk.END)
        if result["issues"]:
            self.issues_text.insert(tk.END, "\n".join(f"•  {i}" for i in result["issues"]))
        else:
            self.issues_text.insert(tk.END, "✓  No obvious weaknesses detected.")
        self.issues_text.configure(state="disabled")

        self.breach_result.configure(text="")

    @staticmethod
    def _score_color(score):
        if score < 20:
            return Theme.DANGER
        if score < 40:
            return "#f97316"  # orange
        if score < 60:
            return Theme.WARNING
        if score < 80:
            return Theme.SUCCESS
        return Theme.INFO

    def on_breach_check(self):
        pw = self.password_var.get()
        if not pw:
            messagebox.showinfo("Password Guardian", "Please type a password first.")
            return

        self.breach_result.configure(text="Checking…", fg=Theme.TEXT_MUTED)
        self.breach_btn.configure(state="disabled")
        threading.Thread(target=self._run_breach_check, args=(pw,), daemon=True).start()

    def _run_breach_check(self, pw):
        try:
            is_breached, count, error = check_breach(pw)
        except Exception as exc:  # noqa: BLE001 — never let the background thread die silently
            import traceback
            traceback.print_exc()
            is_breached, count, error = None, 0, f"Unexpected error: {exc}"
        self.root.after(0, self._show_breach_result, is_breached, count, error)

    def _show_breach_result(self, is_breached, count, error):
        self.breach_btn.configure(state="normal")
        if error:
            self.breach_result.configure(text=f"⚠  {error}", fg=Theme.WARNING)
        elif is_breached:
            self.breach_result.configure(
                text=f"⚠  Found in {count:,} known data breaches. Do not use this password.",
                fg=Theme.DANGER)
        else:
            self.breach_result.configure(
                text="✓  Not found in known breach databases.", fg=Theme.SUCCESS)

    # ------------------------------------------------------------------
    # Tab 2: Hash Visualizer
    # ------------------------------------------------------------------

    def _build_hash_tab(self, parent):
        wrapper = ttk.Frame(parent, padding=(4, 16, 4, 4))
        wrapper.pack(fill="both", expand=True)

        card = self._card(wrapper, title="Hash Algorithm Comparator")

        ttk.Label(card, text="Enter text to hash (e.g. a sample password)",
                  style="Surface.TLabel").pack(anchor="w", pady=(0, 6))

        row = ttk.Frame(card, style="Surface.TFrame")
        row.pack(fill="x", pady=(0, 4))

        self.hash_input_var = tk.StringVar()
        self.hash_entry = ttk.Entry(row, textvariable=self.hash_input_var, font=(Theme.FONT_FAMILY, 12))
        self.hash_entry.pack(side="left", fill="x", expand=True, ipady=3)

        self.hash_btn = ttk.Button(row, text="Compare", command=self.on_compare_hashes)
        self.hash_btn.pack(side="left", padx=(10, 0))

        self.hash_results_frame = ttk.Frame(wrapper, style="Surface.TFrame")

        ttk.Label(
            wrapper,
            text=f"Each algorithm is timed over {BENCHMARK_ITERATIONS:,} hashes on this machine. "
                 "All of them are deliberately fast — ideal for checksums, unsafe for storing "
                 "passwords directly, since an attacker gets the same speed. Use bcrypt / scrypt / "
                 "Argon2 for real password storage instead.",
            style="Muted.TLabel", wraplength=580, justify="left"
        ).pack(anchor="w", pady=(10, 0))

    def on_compare_hashes(self):
        text = self.hash_input_var.get()
        if not text:
            messagebox.showinfo("Password Guardian", "Please type something to hash first.")
            return

        self.hash_btn.configure(state="disabled")
        for widget in self.hash_results_frame.winfo_children():
            widget.destroy()
        self.hash_results_frame.pack(fill="both", expand=True, pady=(14, 0))
        ttk.Label(self.hash_results_frame, text="Benchmarking…", style="Surface.TLabel").pack(anchor="w")

        threading.Thread(target=self._run_hash_compare, args=(text,), daemon=True).start()

    def _run_hash_compare(self, text):
        try:
            results = compare_hashes(text)
        except Exception as exc:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            self.root.after(0, lambda: messagebox.showerror("Password Guardian", f"Hash comparison failed: {exc}"))
            self.root.after(0, lambda: self.hash_btn.configure(state="normal"))
            return
        self.root.after(0, self._show_hash_results, results)

    def _show_hash_results(self, results):
        self.hash_btn.configure(state="normal")
        for widget in self.hash_results_frame.winfo_children():
            widget.destroy()

        fastest = max(r["hashes_per_sec"] for r in results) if results else 1

        for i, r in enumerate(results):
            card = self._card(self.hash_results_frame, pady_outer=(0, 10) if i < len(results) - 1 else (0, 0))

            header = ttk.Frame(card, style="Surface.TFrame")
            header.pack(fill="x")
            ttk.Label(header, text=f"{r['name']}", style="SectionTitle.Surface.TLabel").pack(side="left")
            ttk.Label(header, text=f" ({r['bits']}-bit)", style="Muted.Surface.TLabel").pack(side="left")
            ttk.Label(header, text=f"{r['hashes_per_sec']:,.0f} hashes/sec",
                      foreground=Theme.ACCENT, background=Theme.SURFACE,
                      font=(Theme.FONT_FAMILY, 8, "bold")).pack(side="right")

            digest_box = tk.Text(card, height=1, font=("Consolas", 9), bg=Theme.SURFACE_ALT,
                                  fg=Theme.SUCCESS, relief="flat", wrap="none",
                                  padx=8, pady=6, highlightthickness=1,
                                  highlightbackground=Theme.BORDER)
            digest_box.insert("1.0", r["digest"])
            digest_box.configure(state="disabled")
            digest_box.pack(fill="x", pady=(8, 8))

            speed_bar = ttk.Progressbar(card, maximum=fastest, value=r["hashes_per_sec"])
            speed_bar.pack(fill="x", pady=(0, 8))

            ttk.Label(card, text=r["note"], style="Muted.Surface.TLabel",
                      wraplength=560, justify="left").pack(anchor="w")


def main():
    root = tk.Tk()
    PasswordGuardianApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
