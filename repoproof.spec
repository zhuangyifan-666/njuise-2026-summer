from PyInstaller.utils.hooks import collect_data_files, collect_submodules


hiddenimports = collect_submodules("keyring.backends")
datas = collect_data_files("repoproof.profile")

a = Analysis(
    ["src/repoproof/__main__.py"],
    pathex=["src"],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="repoproof",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
