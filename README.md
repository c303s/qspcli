# QSPCLI

Command-line uploader for CrowdStrike QuickScan Pro.

Not an official CrowdStrike tool.

## Requirements

- Python 3.8+
- A CrowdStrike Falcon API client with Quick Scan Pro `read` and `write` scope

## Mac/Linux

Install and launch from the directory where you want the files to live:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/c303s/qspcli/main/install.sh)"
```

After install, run:

```bash
./qspcli
```

## Windows

1. Install [Python 3](https://www.python.org/downloads/windows/) and enable `Add python.exe to PATH`.
2. Open PowerShell in the folder where you want the tool.
3. Download the script:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/c303s/qspcli/main/qspcli.py" -OutFile "qspcli.py"
```

4. Run it:

```powershell
python qspcli.py
```

## First Run

QSPCLI will:

- validate saved credentials from `.env`, if present
- optionally let you update credentials
- let you choose and persist a working directory
- list files in that directory for scan selection

Saved values in `.env`:

- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- `FALCON_BASE_URL`
- `QSPCLI_WORK_DIR`

## Output

For each scan, QSPCLI:

- prints the verdict and verdict reasons
- writes a timestamped text report
- appends a row to `verdicts.csv`

Example:

```text
[info] Using saved credentials
FALCON_CLIENT_ID: abcdef1234567890
[✓] Running pre-flight access check... done
[✓] API client has access to CrowdStrike QuickScan Pro.
Using saved directory:
/Users/name/samples
Files in /Users/name/samples:
1. suspicious.exe
2. invoice.pdf
Select file from list or enter file name (or 'q' to quit): 1
[•] File : /Users/name/samples/suspicious.exe  (1.6 MB)
[✓] Uploading file to QuickScan Pro (scan=True)... done
[•] SHA256 : 1234567890abcdef...
[•] Waiting for scan result... /  (3s elapsed)

SCAN RESULT
File      : suspicious.exe
SHA256    : 1234567890abcdef...
File Type : 64-bit exe
File Size : 1.6 MB
Status    : done

VERDICT   : CLEAN
Verdict Reasons:
	• File has very high prevalence
	• Machine learning models identified file or subfile as 'clean'
[•] Report  : suspicious_exe_20260531160000_clean.txt
[•] Updated : verdicts.csv
```

## Options

- `--file PATH` scan a specific file
- `--setup` re-run credential setup
- `--version` print the version
