#!/usr/bin/env python3
"""Run with Python 3.10+; install requirements.txt first."""

import sys


def main():
    try:
        if "--smoke-test" in sys.argv[1:]:
            from rayneo.smoke_test import main as run_check

            return run_check()
        from rayneo.app import main as run_app

        return run_app()
    except ModuleNotFoundError as exc:
        name = exc.name or ""
        if name != "rayneo" and not name.startswith("rayneo."):
            raise
        missing = name.replace(".", "/") + (".py" if name != "rayneo" else "/")
        print(
            "程序文件不完整，无法启动。\n"
            f"缺少项目模块：{missing}\n"
            "请重新下载完整项目 ZIP，解压到新目录后运行，不要只替换个别 .py 文件。\n"
            "请保留你修改过的‘异常判定规则.json’；使用 EXE 时请完整更新发布目录。\n"
            "下载：https://github.com/gaoyinhui1-wq/RayNeo-Log-Tool/archive/refs/heads/main.zip",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
