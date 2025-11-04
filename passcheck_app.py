import os
import sys
import math
import hashlib
import threading
import string
from typing import Tuple, List

# Ensure local imports work when running directly
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import tkinter as tk
from tkinter import ttk
try:
    import customtkinter as ctk  # Modern Tk wrapper
    HAS_CTK = True
except Exception:
    ctk = None  # type: ignore
    HAS_CTK = False

# Simple widget factories to unify CTk and Tk
def ui_frame(parent):
    if HAS_CTK and hasattr(ctk, "CTkFrame"):
        return ctk.CTkFrame(parent)
    return tk.Frame(parent)

def ui_label(parent, **kwargs):
    if HAS_CTK and hasattr(ctk, "CTkLabel"):
        return ctk.CTkLabel(parent, **kwargs)
    return tk.Label(parent, **kwargs)

def ui_entry(parent, **kwargs):
    if HAS_CTK and hasattr(ctk, "CTkEntry"):
        return ctk.CTkEntry(parent, **kwargs)
    return tk.Entry(parent, **kwargs)

def ui_checkbutton(parent, **kwargs):
    if HAS_CTK and hasattr(ctk, "CTkCheckBox"):
        # map text/variable/command
        text = kwargs.pop("text", None)
        variable = kwargs.pop("variable", None)
        command = kwargs.pop("command", None)
        return ctk.CTkCheckBox(parent, text=text, variable=variable, command=command)
    return tk.Checkbutton(parent, **kwargs)

def ui_button(parent, **kwargs):
    if HAS_CTK and hasattr(ctk, "CTkButton"):
        return ctk.CTkButton(parent, **kwargs)
    return tk.Button(parent, **kwargs)

try:
    from Passcheck import password_strength  # your existing checker
except Exception:
    # Minimal fallback if import path differs
    def password_strength(password: str) -> Tuple[str, int, List[str]]:
        score = 0
        suggestions: List[str] = []
        if len(password) >= 8:
            score += 2
        else:
            suggestions.append("Use at least 8 characters.")
        if any(c.isupper() for c in password):
            score += 1
        else:
            suggestions.append("Add uppercase letters.")
        if any(c.islower() for c in password):
            score += 1
        else:
            suggestions.append("Add lowercase letters.")
        if any(c.isdigit() for c in password):
            score += 1
        else:
            suggestions.append("Include numbers.")
        if any(c in "@$!%*?&#" for c in password):
            score += 1
        else:
            suggestions.append("Include special characters like @, #, $, etc.")
        common_passwords = ['password', '123456', 'qwerty', 'abc123']
        if password.lower() not in common_passwords:
            score += 2
        else:
            suggestions.append("Avoid common passwords.")
        if score <= 3:
            rating = "Weak"
        elif score <= 6:
            rating = "Medium"
        else:
            rating = "Strong"
        return rating, score, suggestions


# Optional advanced checker (zxcvbn)
try:
    from zxcvbn import zxcvbn  # type: ignore
except Exception:
    zxcvbn = None  # type: ignore

try:
    import requests  # type: ignore
except Exception:
    requests = None  # type: ignore


def estimate_entropy_bits(password: str) -> float:
    if not password:
        return 0.0
    charset = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    symbols = set(ch for ch in password if ch in string.punctuation)
    if has_lower:
        charset += 26
    if has_upper:
        charset += 26
    if has_digits:
        charset += 10
    if symbols:
        charset += len(set(string.punctuation))
    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)


def advanced_strength(password: str) -> Tuple[int, List[str]]:
    """
    Returns a normalized percentage (0-100) and extra suggestions
    using entropy estimate and optional zxcvbn.
    """
    suggestions: List[str] = []
    entropy_bits = estimate_entropy_bits(password)

    # Map entropy to 0..70 points (approx thresholds)
    # <28 bits: weak; 28-50: medium; >50: strong; >75: excellent
    if entropy_bits <= 0:
        entropy_score = 0
    elif entropy_bits < 28:
        entropy_score = 15
    elif entropy_bits < 50:
        entropy_score = 35
    elif entropy_bits < 75:
        entropy_score = 55
    elif entropy_bits < 100:
        entropy_score = 70
    else:
        entropy_score = 75  # cap a bit

    zxcvbn_score_pct = 0
    if zxcvbn is not None and password:
        try:
            res = zxcvbn(password)
            # zxcvbn score 0-4 => 0..25 points
            zxcvbn_score_pct = int((res.get('score', 0) / 4) * 25)
            crack_time_str = res.get('crack_times_display', {}).get('offline_slow_hashing_1e4_per_second')
            if crack_time_str and res.get('score', 0) < 3:
                suggestions.append(f"Estimated crack time: {crack_time_str} (improve length/complexity)")
            for warn in [res.get('feedback', {}).get('warning')]:
                if warn:
                    suggestions.append(str(warn))
            for sug in res.get('feedback', {}).get('suggestions', []):
                suggestions.append(str(sug))
        except Exception:
            pass

    # Penalize obvious patterns
    penalties = 0
    if password and password.lower() in {"password", "qwerty", "abc123", "letmein", "admin"}:
        penalties += 20
        suggestions.append("Avoid common passwords.")
    if password and password.isnumeric() and len(password) >= 6:
        penalties += 10
        suggestions.append("Avoid using only numbers.")
    if password and len(set(password)) <= max(1, len(password) // 6):
        penalties += 10
        suggestions.append("Too many repeating characters; add variety.")

    total = max(0, min(100, entropy_score + zxcvbn_score_pct - penalties))
    return total, suggestions


def hibp_pwned_count(password: str) -> int:
    """Return number of breaches from HIBP (k-anonymity). 0 if not found or unavailable."""
    if not password or requests is None:
        return 0
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=8)
        if resp.status_code != 200:
            return 0
        for line in resp.text.splitlines():
            parts = line.split(':')
            if len(parts) == 2 and parts[0] == suffix:
                return int(parts[1])
    except Exception:
        return 0
    return 0


class PasswordApp:
    def __init__(self) -> None:
        # Initialize UI framework
        if HAS_CTK and hasattr(ctk, "CTk"):
            ctk.set_appearance_mode("system")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
        else:
            self.root = tk.Tk()

        self.root.title("Password Strength Checker")
        try:
            self.root.geometry("720x520")
        except Exception:
            pass

        # Top frame: input and actions
        container = ui_frame(self.root)
        container.pack(fill="both", expand=True, padx=16, pady=16)

        # Input row
        row = ui_frame(container)
        row.pack(fill="x", pady=6)

        lbl = ui_label(row, text="Password")
        lbl.pack(side="left")

        self.password_var = tk.StringVar()
        self.entry = ui_entry(row, textvariable=self.password_var, show="•", width=40)
        self.entry.pack(side="left", padx=8, fill="x", expand=True)
        self.entry.bind("<KeyRelease>", self.on_change)

        self.show_var = tk.BooleanVar(value=False)
        self.show_btn = ui_checkbutton(row, text="Show", variable=self.show_var, command=self.toggle_visibility)
        self.show_btn.pack(side="left", padx=6)

        self.copy_btn = ui_button(row, text="Copy", command=self.copy_password)
        self.copy_btn.pack(side="left", padx=6)

        self.clear_btn = ui_button(row, text="Clear", command=self.clear_password)
        self.clear_btn.pack(side="left", padx=6)

        # Strength meter
        meter = ui_frame(container)
        meter.pack(fill="x", pady=6)

        self.score_label = ui_label(meter, text="Strength: 0% (Weak)")
        self.score_label.pack(side="left")

        # Progress bar: use CTkProgressBar if available
        if hasattr(ctk, "CTkProgressBar"):
            self.progress = ctk.CTkProgressBar(meter, width=250)
            self.progress.pack(side="left", padx=12)
            self.progress.set(0)
        else:
            try:
                self.progress = ttk.Progressbar(meter, length=250, mode='determinate', maximum=100)
                self.progress.pack(side="left", padx=12)
                self.progress['value'] = 0
            except Exception:
                self.progress = None

        # Suggestions box
        sugg_frame = ui_frame(container)
        sugg_frame.pack(fill="both", expand=True, pady=8)
        sugg_lbl = ui_label(sugg_frame, text="Suggestions")
        sugg_lbl.pack(anchor="w")
        if hasattr(ctk, "CTkTextbox"):
            self.suggestions = ctk.CTkTextbox(sugg_frame, height=140)
            self.suggestions.pack(fill="both", expand=True)
        else:
            from tkinter import Text  # type: ignore
            self.suggestions = Text(sugg_frame, height=8)
            self.suggestions.pack(fill="both", expand=True)

        # Generator controls
        gen_frame = ui_frame(container)
        gen_frame.pack(fill="x", pady=8)
        gen_lbl = ui_label(gen_frame, text="Password Generator")
        gen_lbl.pack(anchor="w")

        controls = ui_frame(gen_frame)
        controls.pack(fill="x")

        self.len_var = tk.IntVar(value=16)
        len_lbl = ui_label(controls, text="Length")
        len_lbl.grid(row=0, column=0, padx=4, pady=4, sticky="w")
        if hasattr(ctk, "CTkSlider"):
            self.len_slider = ctk.CTkSlider(controls, from_=8, to=64, number_of_steps=56, command=self.on_len_slide)
            self.len_slider.set(self.len_var.get())
            self.len_slider.grid(row=0, column=1, sticky="ew", padx=6)
        else:
            from tkinter import Scale, HORIZONTAL  # type: ignore
            self.len_slider = Scale(controls, from_=8, to=64, orient=HORIZONTAL, command=lambda v: self.len_var.set(int(float(v))))
            self.len_slider.set(self.len_var.get())
            self.len_slider.grid(row=0, column=1, sticky="ew", padx=6)
        self.len_val = ui_label(controls, text=str(self.len_var.get()))
        self.len_val.grid(row=0, column=2, padx=4)

        self.use_lower = tk.BooleanVar(value=True)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)

        ui_checkbutton(controls, text="Lower", variable=self.use_lower).grid(row=1, column=0, sticky="w", padx=4)
        ui_checkbutton(controls, text="Upper", variable=self.use_upper).grid(row=1, column=1, sticky="w", padx=4)
        ui_checkbutton(controls, text="Digits", variable=self.use_digits).grid(row=1, column=2, sticky="w", padx=4)
        ui_checkbutton(controls, text="Symbols", variable=self.use_symbols).grid(row=1, column=3, sticky="w", padx=4)

        gen_btns = ui_frame(gen_frame)
        gen_btns.pack(fill="x", pady=4)
        ui_button(gen_btns, text="Generate", command=self.generate_password).pack(side="left")
        ui_button(gen_btns, text="Use Generated", command=self.use_generated).pack(side="left", padx=6)

        # Breach check
        breach_frame = ui_frame(container)
        breach_frame.pack(fill="x", pady=8)
        self.breach_label = ui_label(breach_frame, text="Breach check: not checked")
        self.breach_label.pack(side="left")
        self.breach_btn = ui_button(breach_frame, text="Check if breached", command=self.check_breach)
        self.breach_btn.pack(side="left", padx=8)
        if requests is None:
            self.breach_btn.configure(state="disabled")

        # Generated value holder
        self.generated_value: str = ""

    def on_len_slide(self, value: float) -> None:
        try:
            self.len_var.set(int(float(value)))
        except Exception:
            pass
        self.len_val.configure(text=str(self.len_var.get()))

    def toggle_visibility(self) -> None:
        self.entry.configure(show="" if self.show_var.get() else "•")

    def copy_password(self) -> None:
        value = self.password_var.get()
        if not value:
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
        except Exception:
            pass

    def clear_password(self) -> None:
        self.password_var.set("")
        self.update_feedback()

    def on_change(self, _event=None) -> None:
        self.update_feedback()

    def update_feedback(self) -> None:
        pwd = self.password_var.get()
        base_rating, base_score, base_suggestions = password_strength(pwd)

        adv_percent, adv_suggestions = advanced_strength(pwd)
        # Combine: base score is out of 8 → map to 0..60; adv_percent contributes remaining up to 40
        base_pct = int((base_score / 8) * 60)
        combined = max(0, min(100, int(0.6 * base_pct + 0.4 * adv_percent)))

        rating = "Weak"
        if combined >= 80:
            rating = "Strong"
        elif combined >= 50:
            rating = "Medium"

        self.score_label.configure(text=f"Strength: {combined}% ({rating})")
        if hasattr(self, "progress") and self.progress is not None:
            try:
                if hasattr(self.progress, "set"):
                    self.progress.set(combined / 100)
                else:
                    self.progress['value'] = combined
            except Exception:
                pass

        # Suggestions
        all_sug = []  # type: List[str]
        seen = set()
        for s in base_suggestions + adv_suggestions:
            if s and s not in seen:
                seen.add(s)
                all_sug.append(s)
        if not all_sug and pwd:
            all_sug = ["Looks good. Consider using a unique password for each site."]
        self._set_suggestions(all_sug)

        # Reset breach label when typing
        self.breach_label.configure(text="Breach check: not checked")

    def _set_suggestions(self, lines: List[str]) -> None:
        try:
            if hasattr(self.suggestions, "delete"):
                self.suggestions.delete("1.0", "end")
            for s in lines:
                self.suggestions.insert("end", f"• {s}\n")
        except Exception:
            pass

    def build_charset(self) -> str:
        chars = ""
        if self.use_lower.get():
            chars += string.ascii_lowercase
        if self.use_upper.get():
            chars += string.ascii_uppercase
        if self.use_digits.get():
            chars += string.digits
        if self.use_symbols.get():
            chars += "@$!%*?&#"  # curated safe set
        return chars

    def generate_password(self) -> None:
        import secrets
        length = max(8, min(256, int(self.len_var.get())))
        chars = self.build_charset()
        if not chars:
            chars = string.ascii_letters + string.digits
        # Ensure at least one from each selected class
        buckets = []
        if self.use_lower.get():
            buckets.append(secrets.choice(string.ascii_lowercase))
        if self.use_upper.get():
            buckets.append(secrets.choice(string.ascii_uppercase))
        if self.use_digits.get():
            buckets.append(secrets.choice(string.digits))
        if self.use_symbols.get():
            buckets.append(secrets.choice("@$!%*?&#"))
        remaining = [secrets.choice(chars) for _ in range(max(0, length - len(buckets)))]
        pwd_list = buckets + remaining
        # Shuffle
        for i in range(len(pwd_list) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            pwd_list[i], pwd_list[j] = pwd_list[j], pwd_list[i]
        self.generated_value = "".join(pwd_list)
        # Preview in suggestions
        self._set_suggestions([f"Generated: {self.generated_value}", "Click 'Use Generated' to apply."])

    def use_generated(self) -> None:
        if not self.generated_value:
            return
        self.password_var.set(self.generated_value)
        self.update_feedback()

    def check_breach(self) -> None:
        pwd = self.password_var.get()
        if not pwd or requests is None:
            self.breach_label.configure(text="Breach check: unavailable")
            return

        self.breach_label.configure(text="Breach check: checking...")

        def worker() -> None:
            count = hibp_pwned_count(pwd)
            txt = "No breaches found" if count == 0 else f"Found in {count:,} breaches"
            try:
                self.breach_label.configure(text=f"Breach check: {txt}")
            except Exception:
                pass

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def run(self) -> None:
        self.update_feedback()
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    app = PasswordApp()
    app.run()


