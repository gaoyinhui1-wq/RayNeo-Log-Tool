"""Build and verify a portable Windows x64 bundle using the active Python."""

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
NAME = "RayNeo_Log_Tool"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if sys.platform != "win32" or platform.machine().lower() not in {"amd64", "x86_64"}:
        parser.error("This build must run on 64-bit Windows with 64-bit Python.")
    if platform.architecture()[0] != "64bit":
        parser.error("64-bit Python is required for the Windows x64 build.")
    os.chdir(ROOT)
    # Fail before packaging if a partial update omitted the new UI modules.
    subprocess.run(
        [
            sys.executable,
            "-c",
            "from rayneo.window import AppWindow; from rayneo.analysis_worker import WorkerThread",
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onedir",
            "--windowed",
            "--name",
            NAME,
            "--icon",
            "assets/app.ico",
            "--add-data",
            f"assets{os.pathsep}assets",
            "--paths",
            str(ROOT),
            "--collect-submodules",
            "rayneo",
            "--hidden-import",
            "ahocorasick",
            "--collect-submodules",
            "lz4",
            "--collect-submodules",
            "cryptography",
            "--add-data",
            f"异常判定规则.json{os.pathsep}.",
            "RayNeo_Log_Tool.py",
        ],
        check=True,
    )
    bundle = ROOT / "dist" / NAME
    executable = bundle / f"{NAME}.exe"
    if not executable.is_file():
        raise RuntimeError(f"PyInstaller did not create {executable}")
    shutil.copy2(ROOT / "异常判定规则.json", bundle / "异常判定规则.json")
    (bundle / "使用说明.txt").write_text(
        "双击 RayNeo_Log_Tool.exe 启动，无需安装 Python。\n"
        "请完整解压并保留所有文件及 _internal 文件夹。\n"
        "异常判定规则.json 可以编辑，保存后重新分析生效。\n"
        "项目：https://github.com/gaoyinhui1-wq/RayNeo-Log-Tool\n",
        encoding="utf-8",
    )
    report = ROOT / "dist" / "build-smoke-test.json"
    report.unlink(missing_ok=True)
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    subprocess.run(
        [str(executable), "--smoke-test", "--smoke-test-output", str(report)],
        check=True,
        timeout=120,
        env=env,
    )
    result = json.loads(report.read_text(encoding="utf-8"))
    if result.get("status") != "passed":
        raise RuntimeError(f"Packaged smoke test failed: {result}")
    print("Packaged EXE checks passed:", ", ".join(result["checks"]))
    archive = shutil.make_archive(
        str(ROOT / "dist" / "RayNeo-Log-Tool-Windows-x64"),
        "zip",
        root_dir=ROOT / "dist",
        base_dir=NAME,
    )
    print(f"Executable: {executable}")
    print(f"Portable ZIP: {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
