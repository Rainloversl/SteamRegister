# Steam 注册工具打包脚本（PyInstaller）
# 用法: pyinstaller build.spec
name = "SteamRegister-GUI"

a = Analysis(
    ["RegistrationGUI.py"],
    pathex=[],
    binaries=[],
    datas=[("config.example.json", "."), ("README.md", ".")],
    hiddenimports=["bs4", "requests"],
    hookspath=[],
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
    name=name,
    debug=False,
    strip=False,
    upx=True,
    console=False,          # GUI 程序不显示控制台；打包 steamrg.py 时改为 True 并替换入口脚本
    icon=None,
)
