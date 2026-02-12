import argparse
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def iter_files(root: Path, pattern: str, recursive: bool):
    if root.is_file():
        yield root
        return
    if pattern:
        glob_pattern = f"**/{pattern}" if recursive else pattern
        iterator = root.glob(glob_pattern)
    else:
        iterator = root.rglob("*") if recursive else root.glob("*")
    for path in sorted(iterator):
        if path.is_file():
            yield path


def format_bytes(value: int):
    size = float(value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)}{unit}"
            return f"{size:.1f}{unit}"
        size /= 1024


def format_seconds(value: float):
    value = int(value)
    hours = value // 3600
    minutes = (value % 3600) // 60
    seconds = value % 60
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


def load_patterns(path: Path):
    domains = []
    ips = []
    ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            if value.startswith("@"):
                value = value[1:]
            value = value.strip()
            if not value:
                continue
            if ip_re.match(value):
                ips.append(value)
            else:
                domains.append(value.lower())
    return domains, ips


def extract_host(token: str):
    if not token:
        return ""
    if "://" in token:
        token = token.split("://", 1)[1]
    if token.startswith("//"):
        token = token[2:]
    token = token.split("/", 1)[0]
    token = token.split(":", 1)[0]
    return token.strip().strip(".")


def match_domain(candidate: str, domain_set: set):
    if not candidate:
        return None
    candidate = candidate.lower().strip(".")
    if candidate in domain_set:
        return candidate
    parts = candidate.split(".")
    for i in range(1, len(parts)):
        suffix = ".".join(parts[i:])
        if suffix in domain_set:
            return suffix
    return None


def find_email_domain(line: str, domain_set: set):
    idx = 0
    length = len(line)
    while True:
        at = line.find("@", idx)
        if at == -1:
            return None
        end = at + 1
        while end < length and (line[end].isalnum() or line[end] in ".-"):
            end += 1
        candidate = line[at + 1 : end]
        matched = match_domain(candidate, domain_set)
        if matched:
            return matched
        idx = end


def process_file(
    path: Path,
    ip_regex,
    domain_set: set,
    skip_email: bool,
    email_only: bool,
    output,
    output_lock: threading.Lock,
    progress,
    progress_lock: threading.Lock,
):
    processed_bytes = 0
    local_done = 0
    buffer = []
    buffer_limit = 1000
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line_size = len(line)
            processed_bytes += line_size
            local_done += line_size
            line_raw = line.rstrip("\n")
            matched = None
            if ip_regex:
                match = ip_regex.search(line_raw)
                if match:
                    matched = match.group(0)
            if not matched and domain_set and not email_only:
                first_token = line_raw.split(maxsplit=1)[0] if line_raw else ""
                host = extract_host(first_token)
                matched = match_domain(host, domain_set)
            if not matched and domain_set and not skip_email and "@" in line_raw:
                matched = find_email_domain(line_raw, domain_set)
            if matched:
                buffer.append(f"{matched}\t{path}\t{line_raw}\n")
                if len(buffer) >= buffer_limit:
                    with output_lock:
                        output.writelines(buffer)
                    buffer.clear()
            if local_done >= progress["step_local"]:
                with progress_lock:
                    progress["total_done"] += local_done
                    if progress["total_done"] - progress["last_report"] >= progress["report_step"]:
                        elapsed = time.time() - progress["start_time"]
                        speed = progress["total_done"] / elapsed if elapsed > 0 else 0
                        remaining = progress["total_size"] - progress["total_done"]
                        eta = remaining / speed if speed > 0 else 0
                        print(
                            f"  прогресс {format_bytes(progress['total_done'])}/{format_bytes(progress['total_size'])} | скорость {format_bytes(int(speed))}/s | время {format_seconds(elapsed)} | ETA {format_seconds(eta)}",
                            flush=True,
                        )
                        progress["last_report"] = progress["total_done"]
                local_done = 0
    if buffer:
        with output_lock:
            output.writelines(buffer)
    if local_done:
        with progress_lock:
            progress["total_done"] += local_done
            if progress["total_done"] - progress["last_report"] >= progress["report_step"]:
                elapsed = time.time() - progress["start_time"]
                speed = progress["total_done"] / elapsed if elapsed > 0 else 0
                remaining = progress["total_size"] - progress["total_done"]
                eta = remaining / speed if speed > 0 else 0
                print(
                    f"  прогресс {format_bytes(progress['total_done'])}/{format_bytes(progress['total_size'])} | скорость {format_bytes(int(speed))}/s | время {format_seconds(elapsed)} | ETA {format_seconds(eta)}",
                    flush=True,
                )
                progress["last_report"] = progress["total_done"]
    return processed_bytes


def dedup_output(output_path: Path):
    temp_path = output_path.with_suffix(output_path.suffix + ".dedup")
    seen = set()
    with output_path.open("r", encoding="utf-8", errors="ignore") as source, temp_path.open(
        "w", encoding="utf-8"
    ) as target:
        for line in source:
            parts = line.rstrip("\n").split("\t", 2)
            if len(parts) == 3:
                key = f"{parts[0]}\t{parts[2]}"
            else:
                key = line
            if key in seen:
                continue
            seen.add(key)
            target.write(line)
    temp_path.replace(output_path)


def search_files(
    root: Path,
    pattern: str,
    recursive: bool,
    domains,
    ips,
    output_path: Path,
    workers: int,
    skip_email: bool,
    email_only: bool,
):
    files = list(iter_files(root, pattern, recursive))
    files.sort(key=lambda p: p.stat().st_size, reverse=True)
    total_size = sum(path.stat().st_size for path in files)
    total_files = len(files)
    ip_regex = None
    domain_set = set(domains)
    if ips:
        ip_regex = re.compile("|".join(re.escape(ip) for ip in ips))
    with output_path.open("w", encoding="utf-8") as output:
        output_lock = threading.Lock()
        progress_lock = threading.Lock()
        progress = {
            "total_done": 0,
            "total_size": total_size,
            "last_report": 0,
            "report_step": 50 * 1024 * 1024,
            "step_local": 4 * 1024 * 1024,
            "start_time": time.time(),
        }
        print(f"файлов: {total_files} | потоки: {workers} | общий размер: {format_bytes(total_size)}", flush=True)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    process_file,
                    path,
                    ip_regex,
                    domain_set,
                    skip_email,
                    email_only,
                    output,
                    output_lock,
                    progress,
                    progress_lock,
                ): path
                for path in files
            }
            done_files = 0
            for future in as_completed(futures):
                path = futures[future]
                processed_bytes = future.result()
                done_files += 1
                file_size = path.stat().st_size
                print(
                    f"[{done_files}/{total_files}] {path} ({format_bytes(file_size)})",
                    flush=True,
                )
                with progress_lock:
                    total_done_snapshot = progress["total_done"]
                    elapsed = time.time() - progress["start_time"]
                    speed = total_done_snapshot / elapsed if elapsed > 0 else 0
                    remaining = total_size - total_done_snapshot
                    eta = remaining / speed if speed > 0 else 0
                print(
                    f"  прогресс {format_bytes(total_done_snapshot)}/{format_bytes(total_size)} | скорость {format_bytes(int(speed))}/s | время {format_seconds(elapsed)} | ETA {format_seconds(eta)}",
                    flush=True,
                )
    print("дедупликация результата...", flush=True)
    dedup_output(output_path)
    print("дедупликация завершена", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, help="Путь к файлу или директории")
    parser.add_argument("--list", required=True, help="Файл со списком доменов/IP")
    parser.add_argument("--output", required=True, help="Файл для результата")
    parser.add_argument("--pattern", default="", help="Шаблон файлов, если пусто — все")
    parser.add_argument("--recursive", action="store_true", help="Рекурсивно")
    parser.add_argument("--workers", type=int, default=max(1, os.cpu_count() or 1), help="Количество потоков")
    parser.add_argument("--skip-email", action="store_true", help="Не искать домены в email")
    parser.add_argument("--email-only", action="store_true", help="Искать домены только в email, игнорировать URL")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        raise SystemExit(f"Путь не найден: {root}")
    list_path = Path(args.list)
    if not list_path.exists():
        raise SystemExit(f"Файл не найден: {list_path}")

    domains, ips = load_patterns(list_path)
    if not domains and not ips:
        raise SystemExit("Список пуст")

    search_files(
        root,
        args.pattern,
        args.recursive,
        domains,
        ips,
        Path(args.output),
        args.workers,
        args.skip_email,
        args.email_only,
    )


if __name__ == "__main__":
    main()
