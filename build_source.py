#!/usr/bin/env python3
"""Build an AltStore / SideStore source from every IPA released on a GitHub account.

    GITHUB_TOKEN=... python3 build_source.py

Looks at every public repository of OWNER (default: the account this repository belongs to),
takes each release asset whose name ends in .ipa, and reads the app's name, bundle identifier,
version, minimum iOS version, entitlements, privacy strings and icon from the IPA itself.
Apps are grouped by bundle identifier, newest release first.

Writes apps.json and icons/<bundle id>.png. IPAs already read are remembered in cache.json
(by asset id), so a run only downloads what is new. Standard library only.

config.json may override anything per repository:
    {"source": {"name": ..., "subtitle": ..., "tintColor": ...},
     "repos": {"RepoName": {"name": ..., "subtitle": ..., "description": ..., "tintColor": ...,
                            "category": ..., "skip": true}}}
"""
import datetime
import io
import json
import os
import plistlib
import struct
import sys
import tempfile
import urllib.request
import zipfile
import zlib

ROOT = os.path.dirname(os.path.abspath(__file__))
OWNER = os.environ.get("OWNER") or os.environ.get("GITHUB_REPOSITORY_OWNER") or "sytsu"
SELF = (os.environ.get("GITHUB_REPOSITORY") or f"{OWNER}/source").split("/")[1]
BRANCH = os.environ.get("SOURCE_BRANCH", "main")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
MAX_VERSIONS = 10
RAW = f"https://raw.githubusercontent.com/{OWNER}/{SELF}/{BRANCH}"

# AltStore and SideStore fill these in themselves; listing them is pointless.
IGNORED_ENTITLEMENTS = {"application-identifier", "com.apple.developer.team-identifier"}


def log(*args):
    print(*args, file=sys.stderr, flush=True)


# ---- GitHub ----

def api(path):
    """GET every page of a GitHub API list."""
    out, url = [], f"https://api.github.com{path}{'&' if '?' in path else '?'}per_page=100"
    while url:
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                                   "User-Agent": "altstore-source-builder",
                                                   **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {})})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.load(r)
            out.extend(data if isinstance(data, list) else [data])
            url = None
            for part in r.headers.get("Link", "").split(","):
                if 'rel="next"' in part:
                    url = part[part.index("<") + 1:part.index(">")]
    return out


def download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "altstore-source-builder", "Accept": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=600) as r, open(dest, "wb") as f:
        while chunk := r.read(1 << 20):
            f.write(chunk)


# ---- PNG: Apple's CgBI variant to a normal PNG ----

def png_chunks(data):
    pos = 8
    while pos + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        yield kind, data[pos + 8:pos + 8 + length]
        pos += 12 + length


def png_chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)


def normal_png(data):
    """Xcode stores app icons as CgBI: raw deflate, BGRA, premultiplied alpha. Undo all three."""
    if data[12:16] != b"CgBI":
        return data
    chunks = list(png_chunks(data))
    ihdr = next(body for kind, body in chunks if kind == b"IHDR")
    width, height, depth, color = struct.unpack(">IIBB", ihdr[:10])
    if depth != 8 or color != 6:
        raise ValueError("unexpected CgBI layout")
    raw = zlib.decompress(b"".join(body for kind, body in chunks if kind == b"IDAT"), -15)
    stride = width * 4
    rows, prev, pos = [], bytearray(stride), 0
    for _ in range(height):
        kind, line = raw[pos], bytearray(raw[pos + 1:pos + 1 + stride])
        pos += 1 + stride
        for i in range(stride):  # undo the PNG row filter
            a = line[i - 4] if i >= 4 else 0
            b = prev[i]
            c = prev[i - 4] if i >= 4 else 0
            if kind == 1:
                line[i] = (line[i] + a) & 255
            elif kind == 2:
                line[i] = (line[i] + b) & 255
            elif kind == 3:
                line[i] = (line[i] + ((a + b) >> 1)) & 255
            elif kind == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        prev = line
        out = bytearray(stride)
        for x in range(0, stride, 4):
            bl, g, r, al = line[x], line[x + 1], line[x + 2], line[x + 3]
            if 0 < al < 255:
                r, g, bl = min(255, r * 255 // al), min(255, g * 255 // al), min(255, bl * 255 // al)
            out[x:x + 4] = bytes((r, g, bl, al))
        rows.append(b"\x00" + bytes(out))
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", ihdr)
            + png_chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + png_chunk(b"IEND", b""))


# ---- Mach-O: entitlements from the code signature ----

def entitlements(binary):
    """The entitlements plist embedded in the code signature (arm64 slice of a fat file)."""
    magic = struct.unpack(">I", binary[:4])[0]
    if magic in (0xCAFEBABE, 0xCAFEBABF):  # fat
        n = struct.unpack(">I", binary[4:8])[0]
        wide = magic == 0xCAFEBABF
        for i in range(n):
            if wide:
                cpu, _, off, size = struct.unpack(">iiQQ", binary[8 + i * 32:8 + i * 32 + 24])
            else:
                cpu, _, off, size = struct.unpack(">iiII", binary[8 + i * 20:8 + i * 20 + 16])
            if cpu == 0x0100000C:  # arm64
                return entitlements(binary[off:off + size])
        return {}
    if struct.unpack("<I", binary[:4])[0] != 0xFEEDFACF:
        return {}
    ncmds = struct.unpack("<I", binary[16:20])[0]
    pos = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack("<II", binary[pos:pos + 8])
        if cmd == 0x1D:  # LC_CODE_SIGNATURE
            off = struct.unpack("<I", binary[pos + 8:pos + 12])[0]
            sb = binary[off:]
            count = struct.unpack(">I", sb[8:12])[0]
            for j in range(count):
                _, boff = struct.unpack(">II", sb[12 + j * 8:20 + j * 8])
                bmagic, blen = struct.unpack(">II", sb[boff:boff + 8])
                if bmagic == 0xFADE7171:
                    return plistlib.loads(sb[boff + 8:boff + blen])
            return {}
        pos += size
    return {}


# ---- IPA ----

def read_ipa(path):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        app = next(n.split("/")[1] for n in names if n.startswith("Payload/") and n.count("/") >= 2 and n.split("/")[1].endswith(".app"))
        base = f"Payload/{app}/"
        info = plistlib.loads(z.read(base + "Info.plist"))
        executable = info.get("CFBundleExecutable", app[:-4])
        try:
            ents = entitlements(z.read(base + executable))
        except (KeyError, ValueError, struct.error) as e:
            log(f"  no entitlements read from {executable}: {e}")
            ents = {}

        icon_names = []
        for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
            files = info.get(key, {}).get("CFBundlePrimaryIcon", {}).get("CFBundleIconFiles", [])
            icon_names.extend(files)
        candidates = [n for n in names if n.startswith(base) and n.count("/") == 2 and n.endswith(".png")
                      and any(n[len(base):].startswith(i) for i in icon_names)]
        candidates = candidates or [n for n in names if n.startswith(base) and n.count("/") == 2
                                    and "AppIcon" in n and n.endswith(".png")]
        icon = None
        if candidates:
            best = max(candidates, key=lambda n: z.getinfo(n).file_size)
            try:
                icon = normal_png(z.read(best))
            except (ValueError, zlib.error, struct.error) as e:
                log(f"  icon {best} unreadable: {e}")

    privacy = {k: v for k, v in info.items() if k.startswith("NS") and k.endswith("UsageDescription") and isinstance(v, str)}
    return {
        "name": info.get("CFBundleDisplayName") or info.get("CFBundleName") or app[:-4],
        "bundleIdentifier": info["CFBundleIdentifier"],
        "version": str(info.get("CFBundleShortVersionString", "1.0")),
        "buildVersion": str(info.get("CFBundleVersion", "1")),
        "minOSVersion": str(info.get("MinimumOSVersion", "")),
        "entitlements": sorted(k for k in ents if k not in IGNORED_ENTITLEMENTS),
        "privacy": privacy,
    }, icon


# ---- main ----

def load(name, default):
    try:
        with open(os.path.join(ROOT, name)) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def main():
    config = load("config.json", {})
    overrides = config.get("repos", {})
    cache = load("cache.json", {})
    seen_assets = set()
    asset_meta = {}  # download URL -> what was read from that IPA
    apps = {}  # bundle id -> app entry

    repos = [r for r in api(f"/users/{OWNER}/repos?type=owner&sort=pushed")
             if not r.get("private") and not r.get("archived") and r["name"] != SELF]
    for repo in repos:
        name = repo["name"]
        extra = overrides.get(name, {})
        if extra.get("skip"):
            continue
        releases = [r for r in api(f"/repos/{OWNER}/{name}/releases") if not r.get("draft")]
        for rel in releases:
            for asset in rel.get("assets", []):
                if not asset["name"].lower().endswith(".ipa") or asset.get("state") != "uploaded":
                    continue
                key = str(asset["id"])
                seen_assets.add(key)
                if key not in cache:
                    log(f"reading {name} {rel['tag_name']} {asset['name']}")
                    with tempfile.TemporaryDirectory() as tmp:
                        path = os.path.join(tmp, "app.ipa")
                        download(asset["browser_download_url"], path)
                        try:
                            meta, icon = read_ipa(path)
                        except (zipfile.BadZipFile, KeyError, StopIteration, plistlib.InvalidFileException) as e:
                            log(f"  skipped: {e}")
                            cache[key] = {"invalid": str(e)}
                            continue
                    if icon:
                        meta["icon"] = f"icons/{meta['bundleIdentifier']}-{key}.png"
                        with open(os.path.join(ROOT, meta["icon"]), "wb") as f:
                            f.write(icon)
                    cache[key] = meta
                meta = cache[key]
                if "invalid" in meta:
                    continue
                asset_meta[asset["browser_download_url"]] = meta

                bid = meta["bundleIdentifier"]
                version = {
                    "version": meta["version"],
                    "buildVersion": meta["buildVersion"],
                    "date": asset.get("updated_at") or rel.get("published_at"),
                    "localizedDescription": (rel.get("body") or rel.get("name") or rel["tag_name"]).strip()[:4000],
                    "downloadURL": asset["browser_download_url"],
                    "size": asset["size"],
                }
                if meta.get("minOSVersion"):
                    version["minOSVersion"] = meta["minOSVersion"]

                app = apps.get(bid)
                if app is None:
                    app = apps[bid] = {
                        "name": extra.get("name", meta["name"]),
                        "bundleIdentifier": bid,
                        "developerName": extra.get("developerName", OWNER),
                        "subtitle": extra.get("subtitle", repo.get("description") or ""),
                        "localizedDescription": extra.get("description", repo.get("description") or meta["name"]),
                        "iconURL": f"{RAW}/{meta['icon']}" if meta.get("icon") else "",
                        "tintColor": extra.get("tintColor", config.get("source", {}).get("tintColor", "#8E8E93")),
                        "category": extra.get("category", "utilities"),
                        "website": repo["html_url"],
                        "screenshots": extra.get("screenshots", []),
                        "versions": [],
                        "appPermissions": {"entitlements": meta["entitlements"], "privacy": meta["privacy"]},
                        "_repo": name,
                    }
                elif app["_repo"] != name:
                    log(f"  {bid} is also released by {app['_repo']}; keeping that one")
                    continue
                if any(v["downloadURL"] == version["downloadURL"] for v in app["versions"]):
                    continue
                app["versions"].append(version)

    out_apps = []
    for app in apps.values():
        app["versions"].sort(key=lambda v: v["date"] or "", reverse=True)
        app["versions"] = app["versions"][:MAX_VERSIONS]
        # The permissions and icon of the newest build are the ones AltStore checks against.
        newest_url = app["versions"][0]["downloadURL"]
        newest = asset_meta.get(newest_url)
        if newest:
            app["appPermissions"] = {"entitlements": newest["entitlements"], "privacy": newest["privacy"]}
            if newest.get("icon"):
                app["iconURL"] = f"{RAW}/{newest['icon']}"
        del app["_repo"]
        out_apps.append(app)
    out_apps.sort(key=lambda a: a["versions"][0]["date"] or "", reverse=True)

    src = config.get("source", {})
    source = {
        "name": src.get("name", f"{OWNER}'s apps"),
        "identifier": src.get("identifier", f"io.github.{OWNER.lower()}.source"),
        "subtitle": src.get("subtitle", f"Every app {OWNER} releases on GitHub"),
        "description": src.get("description", f"Built automatically from the IPA files in {OWNER}'s GitHub releases."),
        "website": f"https://github.com/{OWNER}",
        "tintColor": src.get("tintColor", "#8E8E93"),
        "iconURL": out_apps[0]["iconURL"] if out_apps else "",
        "apps": out_apps,
        "news": [],
    }

    # Forget assets that were deleted, and their icons.
    for key in [k for k in cache if k not in seen_assets]:
        icon = cache[key].get("icon") if isinstance(cache[key], dict) else None
        if icon and os.path.exists(os.path.join(ROOT, icon)):
            os.remove(os.path.join(ROOT, icon))
        del cache[key]

    with open(os.path.join(ROOT, "cache.json"), "w") as f:
        json.dump(cache, f, indent=1, sort_keys=True)
        f.write("\n")
    with open(os.path.join(ROOT, "apps.json"), "w") as f:
        json.dump(source, f, indent=2, ensure_ascii=False)
        f.write("\n")
    log(f"{len(out_apps)} apps: " + ", ".join(f"{a['name']} {a['versions'][0]['version']}" for a in out_apps))


if __name__ == "__main__":
    main()
