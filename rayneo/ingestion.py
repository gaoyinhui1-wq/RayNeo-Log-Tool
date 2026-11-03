import gzip
import bz2
import lzma

# -*- coding: utf-8 -*-
import os
import re
import io
import base64
import struct
import zipfile
import tarfile
import tempfile
import hashlib
import shutil
from pathlib import Path, PurePosixPath


VLOG_MAGIC = b"VLOGA1\n"


VLOG_AAD = b"venus-app-log:v1"


VLOG_DEFAULT_KEY_BASE64 = "4y5RLBRsivwz+xForfATCw=="


VLOG_MAX_CHUNK = 64 * 1024


MAX_ARCHIVE_DEPTH = 10


MAX_TEXT_BYTES = 80 * 1024 * 1024


MAX_WORKERS = 2  # 减少后台 Python 正则线程争抢 GIL，优先保障界面响应


_AESGCM = None


_LZ4_FRAME = None


def _ensure_crypto():
    global _AESGCM
    if _AESGCM is not None:
        return _AESGCM
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        _AESGCM = AESGCM
        return _AESGCM
    except Exception:
        pass
    raise RuntimeError(
        "缺少 cryptography，请先运行：python -m pip install cryptography"
    )


def _ensure_lz4():
    global _LZ4_FRAME
    if _LZ4_FRAME is not None:
        return _LZ4_FRAME
    try:
        import lz4.frame as lz4_frame

        _LZ4_FRAME = lz4_frame
        return _LZ4_FRAME
    except Exception:
        pass
    raise RuntimeError("缺少 lz4，请先运行：python -m pip install lz4")


def _decompress_lz4_all(data: bytes) -> bytes:

    lz4_frame = _ensure_lz4()
    try:
        with lz4_frame.open(io.BytesIO(data), mode="rb") as fp:
            return fp.read()
    except Exception:
        return lz4_frame.decompress(data)


def decrypt_vloga1_bytes(data: bytes, key_b64: str = VLOG_DEFAULT_KEY_BASE64) -> bytes:
    if not data.startswith(VLOG_MAGIC):
        return data
    key = base64.b64decode(key_b64, validate=True)
    if len(key) != 16:
        raise ValueError(f"AES-128-GCM key 长度异常：{len(key)}")
    if len(data) < len(VLOG_MAGIC) + 8:
        raise ValueError("VLOGA1 文件头不完整")

    nonce_prefix = data[len(VLOG_MAGIC) : len(VLOG_MAGIC) + 8]
    pos = len(VLOG_MAGIC) + 8
    expected_counter = 0
    output = bytearray()
    AESGCM = _ensure_crypto()
    aes = AESGCM(key)

    while pos < len(data):
        if len(data) - pos < 8:
            raise ValueError("VLOGA1 记录头不完整")
        counter, plain_len = struct.unpack(">II", data[pos : pos + 8])
        pos += 8
        if counter != expected_counter:
            raise ValueError(
                f"VLOGA1 counter 异常：expected={expected_counter}, actual={counter}"
            )
        if plain_len > VLOG_MAX_CHUNK:
            raise ValueError(f"VLOGA1 单块长度异常：{plain_len}")

        encrypted_len = plain_len + 16
        if len(data) - pos < encrypted_len:
            raise ValueError("VLOGA1 密文/Tag 不完整")
        encrypted = data[pos : pos + encrypted_len]
        nonce = nonce_prefix + struct.pack(">I", counter)
        try:
            plain = aes.decrypt(nonce, encrypted, VLOG_AAD)
        except Exception as exc:
            raise ValueError("VLOGA1 解密认证失败，请确认日志版本/密钥") from exc
        output.extend(plain)
        pos += encrypted_len
        expected_counter += 1
    return bytes(output)


def _is_lz4_bytes(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == b"\x04\x22\x4d\x18"


def _is_zip_bytes(data: bytes) -> bool:
    try:
        return zipfile.is_zipfile(io.BytesIO(data))
    except Exception:
        return False


def _is_tar_bytes(data: bytes) -> bool:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*"):
            return True
    except Exception:
        return False


def _safe_member_path(name: str):
    p = PurePosixPath(name.replace("\\", "/"))
    if (
        p.is_absolute()
        or ".." in p.parts
        or any(":" in x or "\0" in x for x in p.parts)
    ):
        return None
    parts = [x for x in p.parts if x not in ("", ".")]
    return Path(*parts) if parts else None


def _strip_container_suffixes(name: str) -> str:
    out = name
    while True:
        low = out.lower()
        changed = False
        for suffix in (
            ".decrypted.lz4",
            ".zip.log",
            ".tar.lz4",
            ".lz4",
            ".zip",
            ".tar",
            ".log",
            ".decrypted",
        ):
            if low.endswith(suffix):
                out = out[: -len(suffix)]
                changed = True
                break
        if not changed:
            break
    return out or "decoded"


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    i = 1
    while True:
        p = Path(f"{path}_{i}")
        if not p.exists():
            return p
        i += 1


def _decode_blob_to_files(data: bytes, name: str, out_dir: Path, depth=0, notes=None):
    if notes is None:
        notes = []
    if depth > MAX_ARCHIVE_DEPTH:
        notes.append(f"跳过：归档嵌套超过 {MAX_ARCHIVE_DEPTH} 层 - {name}")
        return []

    current = data
    current_name = name

    for _ in range(8):
        if current.startswith(VLOG_MAGIC):
            current = decrypt_vloga1_bytes(current)
            notes.append(f"解密 VLOGA1：{name}")
            if current_name.lower().endswith(".log"):
                current_name = current_name[:-4]
            current_name += ".decrypted"
            continue

        if _is_lz4_bytes(current):
            current = _decompress_lz4_all(current)
            notes.append(f"解压 LZ4：{name}")
            if current_name.lower().endswith(".lz4"):
                current_name = current_name[:-4]
            continue

        if _is_zip_bytes(current):
            subdir = out_dir / (
                _strip_container_suffixes(Path(current_name).name) + "_zip"
            )
            subdir.mkdir(parents=True, exist_ok=True)
            result = []
            with zipfile.ZipFile(io.BytesIO(current)) as zf:
                if sum(info.file_size for info in zf.infolist()) > 2 * 1024**3:
                    raise RuntimeError("压缩包解压后超过 2 GB 安全限制")
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    if info.file_size > 512 * 1024**2:
                        raise RuntimeError(f"单个 ZIP 成员超过 512 MB：{info.filename}")
                    rel = _safe_member_path(info.filename)
                    if rel is None:
                        continue
                    member_dir = subdir / rel.parent
                    member_dir.mkdir(parents=True, exist_ok=True)
                    result.extend(
                        _decode_blob_to_files(
                            zf.read(info), rel.name, member_dir, depth + 1, notes
                        )
                    )
            notes.append(f"解压 ZIP：{name}")
            return result

        if _is_tar_bytes(current):
            subdir = out_dir / (
                _strip_container_suffixes(Path(current_name).name) + "_tar"
            )
            subdir.mkdir(parents=True, exist_ok=True)
            result = []
            with tarfile.open(fileobj=io.BytesIO(current), mode="r:*") as tf:
                members = tf.getmembers()
                if (
                    sum(member.size for member in members if member.isfile())
                    > 2 * 1024**3
                ):
                    raise RuntimeError("TAR 解压后超过 2 GB 安全限制")
                for member in members:
                    if not member.isfile():
                        continue
                    if member.size > 512 * 1024**2:
                        raise RuntimeError(f"单个 TAR 成员超过 512 MB：{member.name}")
                    rel = _safe_member_path(member.name)
                    if rel is None:
                        continue
                    fp = tf.extractfile(member)
                    if fp is None:
                        continue
                    member_dir = subdir / rel.parent
                    member_dir.mkdir(parents=True, exist_ok=True)
                    result.extend(
                        _decode_blob_to_files(
                            fp.read(), rel.name, member_dir, depth + 1, notes
                        )
                    )
            notes.append(f"解压 TAR：{name}")
            return result
        break

    target = _unique_path(out_dir / (Path(current_name).name or "decoded.log"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(current)
    return [str(target)]


STREAM_CHUNK = 1024 * 1024


DECODE_SINGLE_LIMIT = 1024**3


DECODE_TOTAL_LIMIT = 4 * 1024**3


class _DecodeBudget:
    def __init__(self):
        self.total = 0

    def add(self, amount):
        self.total += amount
        if self.total > DECODE_TOTAL_LIMIT:
            raise RuntimeError("解压总量超过 4 GB 安全限制")


def _decode_copy(reader, writer, budget, cancel=None, limit=DECODE_SINGLE_LIMIT):
    written = 0
    while True:
        if cancel is not None and cancel():
            raise InterruptedError("用户已取消解压")
        chunk = reader.read(STREAM_CHUNK)
        if not chunk:
            break
        written += len(chunk)
        if written > limit:
            raise RuntimeError("解压单文件超过 1 GB 安全限制")
        budget.add(len(chunk))
        writer.write(chunk)
    return written


def _container_type(path):
    path = Path(path)
    with path.open("rb") as f:
        head = f.read(512)
    suffix = path.name.lower()
    if head.startswith(VLOG_MAGIC):
        return "vlog"
    if _is_lz4_bytes(head):
        return "lz4"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "unsupported:7z"
    if head.startswith(b"Rar!"):
        return "unsupported:RAR"
    if head.startswith((b"PK\\x03\\x04", b"PK\\x05\\x06")):
        return "zip"
    # ZIP header must be bytes, not ASCII escapes.
    if head[:4] in (bytes.fromhex("504b0304"), bytes.fromhex("504b0506")):
        return "zip"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if suffix.endswith((".zip", ".zip.log")):
        return "zip"
    if suffix.endswith((".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz")):
        return "tar"
    if suffix.endswith((".lz4", ".tar.lz4")):
        return "lz4"
    if head.startswith(b"\x1f\x8b") or suffix.endswith(".gz"):
        return "gzip"
    if head.startswith(b"BZh") or suffix.endswith(".bz2"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00") or suffix.endswith(".xz"):
        return "xz"
    return None


def _stream_decode_path(
    source, output_dir, notes=None, depth=0, cancel=None, budget=None, display_name=None
):
    if notes is None:
        notes = []
    if budget is None:
        budget = _DecodeBudget()
    if depth > MAX_ARCHIVE_DEPTH:
        raise RuntimeError("压缩包嵌套超过 10 层")
    source, output_dir = Path(source), Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    name = display_name or source.name
    kind = _container_type(source)
    if kind and kind.startswith("unsupported:"):
        raise ValueError(
            f"暂不支持 {kind.split(':', 1)[1]} 压缩格式，请先解压后导入文件夹"
        )
    if kind is None:
        # 已解包到输出目录的文件直接保留，避免反复复制。
        if source.parent.resolve() == output_dir.resolve():
            return [str(source)]
        dest = _unique_path(output_dir / name)
        with source.open("rb") as fi, dest.open("wb") as fo:
            try:
                _decode_copy(fi, fo, budget, cancel)
            except BaseException:
                dest.unlink(missing_ok=True)
                raise
        return [str(dest)]
    if kind in ("vlog", "lz4", "gzip", "bzip2", "xz"):
        postfix = ".decrypted" if kind == "vlog" else ".unpacked"
        target = _unique_path(output_dir / (name + postfix))
        try:
            with source.open("rb") as fi, target.open("wb") as fo:
                if kind == "vlog":
                    prefix = fi.read(len(VLOG_MAGIC) + 8)
                    if len(prefix) < len(VLOG_MAGIC) + 8:
                        raise ValueError("VLOGA1 文件头不完整")
                    nonce_prefix = prefix[len(VLOG_MAGIC) :]
                    aes = _ensure_crypto()(base64.b64decode(VLOG_DEFAULT_KEY_BASE64))
                    counter_expected = 0
                    written = 0
                    while True:
                        if cancel and cancel():
                            raise InterruptedError("用户已取消解密")
                        rec = fi.read(8)
                        if not rec:
                            break
                        if len(rec) < 8:
                            raise ValueError("VLOGA1 记录头不完整")
                        counter, plain_len = struct.unpack(">II", rec)
                        if counter != counter_expected or plain_len > VLOG_MAX_CHUNK:
                            raise ValueError("VLOGA1 counter 或长度异常")
                        ciphertext = fi.read(plain_len + 16)
                        if len(ciphertext) != plain_len + 16:
                            raise ValueError("VLOGA1 密文/Tag 不完整")
                        plain = aes.decrypt(
                            nonce_prefix + struct.pack(">I", counter),
                            ciphertext,
                            VLOG_AAD,
                        )
                        written += len(plain)
                        if written > DECODE_SINGLE_LIMIT:
                            raise RuntimeError("解密单文件超过 1 GB 安全限制")
                        budget.add(len(plain))
                        fo.write(plain)
                        counter_expected += 1
                else:
                    opener = (
                        _ensure_lz4().open
                        if kind == "lz4"
                        else {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}[
                            kind
                        ]
                    )
                    with opener(fi, "rb") as li:
                        _decode_copy(li, fo, budget, cancel)
            # 如果解密产物还是容器，继续展开并去掉中间文件。
            if _container_type(target):
                result = _stream_decode_path(
                    target,
                    output_dir,
                    notes,
                    depth + 1,
                    cancel,
                    budget,
                    _strip_container_suffixes(name),
                )
                target.unlink(missing_ok=True)
                return result
            notes.append(f"解密/解压完成：{name}")
            # 如果输入是在输出目录内的中间加密产物，删除它。
            return [str(target)]
        except BaseException:
            target.unlink(missing_ok=True)
            raise
    # Archive members extracted one by one and each nested container gets processed immediately.
    root = output_dir / (
        _strip_container_suffixes(name) + ("_zip" if kind == "zip" else "_tar")
    )
    root = _unique_path(root)
    root.mkdir(parents=True, exist_ok=True)
    outputs = []
    if kind == "zip":
        with zipfile.ZipFile(source) as zf:
            items = zf.infolist()
            if sum(i.file_size for i in items) > DECODE_TOTAL_LIMIT:
                raise RuntimeError("ZIP 文件展开总量超过 4 GB")
            for info in items:
                if cancel and cancel():
                    raise InterruptedError("用户已取消解压")
                if info.is_dir():
                    continue
                if info.file_size > DECODE_SINGLE_LIMIT:
                    raise RuntimeError(f"ZIP 文件过大：{info.filename}")
                rel = _safe_member_path(info.filename)
                if not rel:
                    continue
                folder = root / rel.parent
                folder.mkdir(parents=True, exist_ok=True)
                target = _unique_path(folder / rel.name)
                with zf.open(info, "r") as fi, target.open("wb") as fo:
                    try:
                        _decode_copy(fi, fo, budget, cancel)
                    except BaseException:
                        target.unlink(missing_ok=True)
                        raise
                if _container_type(target):
                    child = _stream_decode_path(
                        target, folder, notes, depth + 1, cancel, budget, rel.name
                    )
                    target.unlink(missing_ok=True)
                    outputs.extend(child)
                else:
                    outputs.append(str(target))
    else:
        with tarfile.open(source, mode="r:*") as tf:
            for info in tf:
                if cancel and cancel():
                    raise InterruptedError("用户已取消解压")
                if not info.isfile():
                    continue
                if info.size > DECODE_SINGLE_LIMIT:
                    raise RuntimeError(f"TAR 文件过大：{info.name}")
                rel = _safe_member_path(info.name)
                if not rel:
                    continue
                reader = tf.extractfile(info)
                if reader is None:
                    continue
                folder = root / rel.parent
                folder.mkdir(parents=True, exist_ok=True)
                target = _unique_path(folder / rel.name)
                with reader as fi, target.open("wb") as fo:
                    try:
                        _decode_copy(fi, fo, budget, cancel)
                    except BaseException:
                        target.unlink(missing_ok=True)
                        raise
                if _container_type(target):
                    child = _stream_decode_path(
                        target, folder, notes, depth + 1, cancel, budget, rel.name
                    )
                    target.unlink(missing_ok=True)
                    outputs.extend(child)
                else:
                    outputs.append(str(target))
    notes.append(f"展开 {kind.upper()}：{name}（{len(outputs)} 文件）")
    return outputs


def _fast_file_fingerprint(path: str):

    try:
        p = Path(path)
        size = p.stat().st_size
        h = hashlib.blake2b(digest_size=16)
        h.update(str(size).encode())
        with open(p, "rb") as f:
            h.update(f.read(65536))
            if size > 65536:
                f.seek(max(0, size - 65536))
                h.update(f.read(65536))
        return size, h.digest()
    except Exception:
        return None


def _dedupe_output_files(paths):
    """Sampling selects candidates; full hashes alone establish equality."""
    out, groups, hashes = [], {}, {}

    def full_hash(path):
        if path not in hashes:
            h = hashlib.blake2b(digest_size=32)
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(STREAM_CHUNK), b""):
                    h.update(chunk)
            hashes[path] = h.digest()
        return hashes[path]

    for path in paths:
        fp = _fast_file_fingerprint(path)
        if fp is None:
            if path not in out:
                out.append(path)
            continue
        candidates = groups.setdefault(fp, [])
        try:
            duplicate = any(full_hash(path) == full_hash(other) for other in candidates)
        except OSError:
            duplicate = False
        if not duplicate:
            candidates.append(path)
            out.append(path)
    return out


def _is_glasses_metadata_only(path: str) -> bool:
    """这些眼镜文件只用于拿版本/元数据，不进入 BLE 全量时序分析。"""
    name = Path(path).name.lower()
    return (
        name.startswith("otatransfer")
        or name.startswith("otainstalllog")
        or name.endswith(".rel")
        or name in {"versions.rev", "versions.rev.bak"}
        or name.endswith(".rni")
        or name.endswith(".red")
        or name.startswith("system_stats_")
        or name.startswith("rnlink_trace_")
    )


def _is_glasses_side_path(path: str) -> bool:
    low = str(path).lower()
    name = Path(path).name.lower()
    return any(
        k in low for k in ("glasses_log", "venus_", "rnevents")
    ) or name.startswith(("syslog", "otatransfer", "otainstalllog", "rnlink_trace_"))


def _is_phone_app_log(path: str) -> bool:
    name = Path(path).name.lower()
    low = str(path).lower()
    if _is_glasses_side_path(path):
        return False
    return (
        name.endswith((".log", ".decrypted"))
        or "applog" in low
        or "native_ios" in name
        or "hilog" in name
        or "logcat" in name
    )


def collect_input_files(paths, cancel_callback=None):
    """Expand mixed sources, deduplicating paths without following symlinks."""
    sources = [paths] if isinstance(paths, (str, os.PathLike)) else paths
    files, seen = [], set()
    for raw in sources:
        source = Path(raw).expanduser()
        if not source.exists():
            raise FileNotFoundError(f"找不到路径：{source}")
        candidates = source.rglob("*") if source.is_dir() else (source,)
        for path in candidates:
            if cancel_callback and cancel_callback():
                raise InterruptedError("日志打开任务已取消")
            if path.is_symlink() or not path.is_file() or path.name.startswith("."):
                continue
            resolved = str(path.resolve())
            if resolved not in seen:
                seen.add(resolved)
                files.append(resolved)
    return sorted(files)


def prepare_log_inputs(
    paths, is_file_list=False, progress_callback=None, cancel_callback=None
):
    # Legacy argument kept; all routes now accept mixed files and folders.
    source_files = collect_input_files(paths, cancel_callback)
    notes, output_files, work_dir = [], [], None
    budget = _DecodeBudget()
    try:
        for i, raw_path in enumerate(source_files):
            if cancel_callback and cancel_callback():
                raise InterruptedError("日志打开任务已取消")
            path = Path(raw_path)
            if progress_callback:
                progress_callback(
                    int(i / max(1, len(source_files)) * 18), f"导入：{path.name}"
                )
            try:
                if _container_type(path) is None:
                    output_files.append(str(path))
                    continue
                if work_dir is None:
                    work_dir = Path(tempfile.mkdtemp(prefix="rayneo_bt_analyzer_"))
                decoded = _stream_decode_path(
                    path, work_dir, notes, cancel=cancel_callback, budget=budget
                )
                output_files.extend(decoded)
            except InterruptedError:
                raise
            except Exception as exc:
                # A failed archive is NOT plaintext, and must not enter analysis.
                notes.append(f"处理失败 {path.name}：{exc}")
        final = _dedupe_output_files(output_files)
        removed = len(output_files) - len(final)
        if removed:
            notes.append(f"已去除内容完全相同的日志：{removed} 个")
        return final, notes, str(work_dir) if work_dir else None
    except BaseException:
        if work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)
        raise


BINARY_META_MAX_BYTES = 32 * 1024 * 1024


def _extract_glasses_binary_metadata(path: str):

    try:
        p = Path(path)
        name = p.name.lower()

        if not (name.endswith(".rel") or name in {"versions.rev", "versions.rev.bak"}):
            return None
        with open(path, "rb") as f:
            data = f.read(BINARY_META_MAX_BYTES)
        if not data:
            return None

        chunks = []
        seen = set()

        for raw in re.findall(rb"[\x20-\x7e]{4,240}", data):
            try:
                text = raw.decode("utf-8", errors="ignore").strip()
            except Exception:
                continue
            if not text:
                continue
            low = text.lower()
            if not any(
                k in low
                for k in (
                    "small_core",
                    "strix os",
                    "os_version",
                    "firmware",
                    "version",
                    "rnlink",
                    "ble ",
                    "gatt",
                    "bond",
                    "mfi",
                )
            ):
                continue
            if text in seen:
                continue
            seen.add(text)
            chunks.append(text)
            if len(chunks) >= 300:
                break

        if not chunks:
            return None
        return "\n".join(chunks)
    except Exception:
        return None


def read_text_file(path: str):
    """同时识别 UTF-8/UTF-16/GB18030；不要把 UTF-16 的 NUL 误当固件二进制。"""
    try:
        with open(path, "rb") as f:
            head = f.read(8192)
        if not head:
            return ""
        if head.startswith((b"\xff\xfe", b"\xfe\xff")):
            return Path(path).read_text(encoding="utf-16", errors="replace")
        if b"\0" in head:
            even = head[0::2].count(0)
            odd = head[1::2].count(0)
            if odd >= len(head) // 8 and even <= len(head) // 50:
                return Path(path).read_text(encoding="utf-16-le", errors="replace")
            if even >= len(head) // 8 and odd <= len(head) // 50:
                return Path(path).read_text(encoding="utf-16-be", errors="replace")
            return _extract_glasses_binary_metadata(path)
        # UTF-8 first; GB18030 fallback if original bytes are not UTF-8.
        try:
            with open(path, "r", encoding="utf-8-sig", errors="strict") as f:
                return f.read()
        except UnicodeDecodeError:
            with open(path, "r", encoding="gb18030", errors="replace") as f:
                return f.read()
    except (OSError, UnicodeError):
        return None
