# RepoProof Windows release

## Download and run

On Windows 10/11 x64, download both
`repoproof-<version>-windows-x86_64.exe` and its matching `.sha256` file from
the release assets. In PowerShell, run:

```powershell
.\repoproof-<version>-windows-x86_64.exe version
.\repoproof-<version>-windows-x86_64.exe audit . --offline
```

## Verify the checksum

Run this in the directory containing both downloaded files. The two hashes
must match.

```powershell
$asset = "repoproof-<version>-windows-x86_64.exe"
$expected = (Get-Content -LiteralPath "$asset.sha256").Split()[0]
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $asset).Hash.ToLowerInvariant()
$expected -eq $actual
```

## Security and limitations

The Windows binary is unsigned. Windows SmartScreen may show a warning before
you run it; verify the `.sha256` file before deciding whether to continue.

`audit --offline` makes no network request and is the recommended default.
Optional online GitHub evidence requires network access and a GitHub token
stored in the operating system keyring. Keyring availability varies by OS and
desktop environment; RepoProof does not fall back to plaintext credential
storage.

## Install from source

With Python 3.12 or newer, clone the repository and install the development
dependencies:

```powershell
python -m pip install -e ".[dev]"
repoproof version
repoproof audit . --offline
```
