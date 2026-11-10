"""Back up/restore ignored local build sources without replacing existing files.

The backup stays inside ignored build output. It excludes application/config
directories, so private Wi-Fi credentials are never copied. This is local
recovery, not a substitute for distributing the project's dependencies.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

GROUPS = {"platform", "third_party", "testing"}
ARCHIVE = Path("build/local-dependencies/pico2-sources.zip")


def permitted(name):
    path = PurePosixPath(name)
    return (not path.is_absolute() and len(path.parts) > 1
            and path.parts[0] in GROUPS and ".." not in path.parts
            and "\\" not in name and ":" not in name
            and not any(word in path.name.lower()
                        for word in ("secret", "wifi_notification_config")))


def backup(root):
    archive = root / ARCHIVE
    archive.parent.mkdir(parents=True, exist_ok=True)
    manifest = {}
    temporary = archive.with_suffix(".tmp")
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as output:
        for group in sorted(GROUPS):
            for path in sorted((root / group).rglob("*")):
                if (not path.is_file() or path.is_symlink()
                        or "__pycache__" in path.parts
                        or path.suffix.lower() in {".exe", ".o", ".obj", ".pyc"}):
                    continue
                name = path.relative_to(root).as_posix()
                if not permitted(name):
                    continue
                data = path.read_bytes()
                manifest[name] = hashlib.sha256(data).hexdigest()
                output.writestr(name, data)
        output.writestr("manifest.json", json.dumps(manifest, indent=2))
    temporary.replace(archive)
    return len(manifest)


def restore(root):
    archive = root / ARCHIVE
    if not archive.exists():
        required = ["platform/kernel_port.c", "third_party/mtkernel/kernel/tkernel/tkinit.c",
                    "testing/host/verify_detection_ram.py"]
        if any(not (root / name).exists() for name in required):
            raise ValueError("Local dependencies and their recovery backup are missing; "
                             "restore the known source bundle before building.")
        return 0
    restored = 0
    with zipfile.ZipFile(archive) as source:
        manifest = json.loads(source.read("manifest.json"))
        pending = []
        # Validate every missing entry before any writes. Existing files always
        # win, including locally modified kernel ports and verification tools.
        for name, digest in manifest.items():
            if not permitted(name):
                raise ValueError("Unsafe path in local dependency backup")
            path = root / name
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("Dependency target escapes this checkout")
            if path.exists():
                continue
            data = source.read(name)
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("Dependency backup checksum mismatch")
            pending.append((path, data))
        for path, data in pending:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive creation also preserves a file created since validation.
            try:
                with path.open("xb") as output:
                    output.write(data)
                restored += 1
            except FileExistsError:
                pass
    return restored


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.backup:
        print(f"Local dependency backup: {backup(root)} files saved (no private configuration).")
    else:
        print(f"Local dependencies: {restore(root)} missing files restored; existing files preserved.")


if __name__ == "__main__":
    main()
