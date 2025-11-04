# PassCheck

A modern password strength checker for Windows with live feedback, suggestions, password generator, and optional breached-password lookup via Have I Been Pwned (k-anonymity).

## Features
- Live strength meter and rating
- Actionable suggestions
- Password generator (length + charset toggles)
- Show/Hide, Copy, Clear
- Optional: Have I Been Pwned leaked password check
- Optional: zxcvbn-based analysis

## Run from source
```bash
pip install -r requirements.txt
python passcheck_app.py
```

Notes:
- If you skip `customtkinter`, the UI falls back to standard tkinter.
- If you skip `requests`, the breach check button is disabled.
- If you skip `zxcvbn`, you still get entropy-based scoring.

## Build a Windows executable
```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --name PassCheck passcheck_app.py
```
- Output: `dist/PassCheck.exe`
- Optional icon: add `--icon assets/icon.ico` (provide your own ICO file)

## Privacy
The breach check uses the HIBP range API and sends only the first 5 characters of the password's SHA-1 hash (k‑anonymity). The full password never leaves the app.

## License
Add your preferred license (e.g., MIT) here.


