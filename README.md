# 🔐 Password Guardian

A desktop GUI application (Python + Tkinter) built as a **defensive password
security** college project. It has three tabs:

1. **Password Strength Analyzer** — scores a password in real time using
   entropy calculation, pattern detection (sequences, repeats, common
   passwords), and gives an estimated offline brute-force crack time.
2. **Breach Checker** — checks whether a password has appeared in known
   public data breaches, using the same **k-anonymity** technique as the
   real-world "Have I Been Pwned" Pwned Passwords API.
3. **Hash Visualizer** — hashes your input with MD5, SHA-1, SHA-256 and
   SHA-512 side by side, shows each algorithm's digest, and benchmarks
   how many hashes/sec this machine can compute for each — visually
   demonstrating why fast general-purpose hashes are unsafe for storing
   passwords.

This is the opposite of a password *cracker*: it helps users understand
and improve their own password security.

---

## 🖥️ How to Run

### 1. Install Python
Python 3.8+ is required. Check with:
```bash
python --version
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```
(`tkinter` ships with most Python installations. On Linux, if missing:
`sudo apt install python3-tk`)

### 3. Run the app
```bash
python app.py
```

A window will open where you can type a password and see its strength
analyzed live, plus an optional breach check (requires internet access).

---

## 🧠 Concepts Used (good for your project report / viva)

### Entropy-based strength scoring
Password strength is estimated using **Shannon entropy**:

```
entropy (bits) = length × log2(character_pool_size)
```

A larger character pool (lowercase + uppercase + digits + symbols) and
greater length both increase entropy, which roughly measures how many
guesses an attacker would need on average.

### Pattern / weakness detection
The analyzer flags:
- Membership in a common-password list
- Missing character classes (no uppercase, no digits, etc.)
- Repeated characters (`aaa`)
- Simple sequences (`123`, `abc`)
- Length below recommended minimums

### k-Anonymity breach checking
Instead of sending your full password (or even its full hash) to a
server, the app:
1. Computes the **SHA-1** hash of the password locally.
2. Sends only the **first 5 hex characters** of that hash to the
   Pwned Passwords API.
3. The API returns every hash suffix sharing that prefix (typically
   hundreds to thousands of entries) along with breach counts.
4. The match against the full hash suffix is done **locally** — the
   server never sees the real password or the complete hash.

This is the same privacy-preserving design Troy Hunt's
[Have I Been Pwned](https://haveibeenpwned.com/Passwords) service uses
in production, and it's an excellent real-world example of applied
cryptographic hashing + anonymity sets — great material to explain in
a viva.

### Hash algorithm comparison (MD5 / SHA-1 / SHA-256 / SHA-512)
The Hash Visualizer tab computes all four digests for the same input and
benchmarks each one over 200,000 iterations to show hashes/sec on your
machine. The key takeaway for your report: **all four are deliberately
fast** — great for checksums, terrible for passwords, because an
attacker with the same speed can try billions of guesses per second
offline. MD5 is also cryptographically broken (collisions since 2004)
and SHA-1 was broken in practice in 2017 (the "SHAttered" attack), so
neither should be used for anything security-critical, including the
breach-check feature — which only uses SHA-1 because that's the format
the public Pwned Passwords API requires for lookups, not because SHA-1
is recommended.

### Why MD5/SHA-1/SHA-256 are unsuitable for *storing* passwords
In real systems, passwords should never be stored with fast general-
purpose hashes like MD5/SHA-1/SHA-256/SHA-512 — slow, salted KDFs such
as **bcrypt**, **scrypt**, or **Argon2** should be used instead,
specifically because they're expensive (in time and/or memory) to
brute-force, unlike the hashes compared in this tool.

---

## 🎨 UI
The interface uses a dark, modern "card" layout with a branded header bar,
a two-tab navigation (Strength & Breach Check / Hash Visualizer), a
status bar showing library availability, and a Help → About menu. All
colors, spacing and fonts are centralized in the `Theme` class near the
top of the GUI section, so re-theming (e.g. light mode, different accent
color) only requires editing those constants.

## 📂 Project Structure
```
PasswordGuardian/
├── app.py            # Main GUI application
├── requirements.txt  # Python dependencies
└── README.md          # This file
```

## 🚀 Possible Extensions (for bonus marks)
- Add a password **generator** (cryptographically secure, via `secrets` module)
- Store analysis history locally (SQLite) to show strength trends
- Add a "copy to clipboard" button for generated passwords
- Package as a standalone `.exe` using PyInstaller
- Add dark/light theme toggle
- Localize UI into Hindi/English

## ⚠️ Note on Network Access
The breach-check feature calls `api.pwnedpasswords.com` over HTTPS, so it
needs internet access. The strength analyzer works fully offline.
