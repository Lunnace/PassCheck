# PassCheck

A modern password strength checker for Windows with live feedback, suggestions, password generator, and optional breached-password lookup.

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






