"""Validate built links, anchors, assets, SEO metadata, and optional external URLs."""
import argparse
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

SITE = Path(__file__).resolve().parents[1]
DIST = SITE / "dist"
ORIGIN = "https://cawalch.github.io"
BASE = "/go-yara/"


class Document(HTMLParser):
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.ids = set()
        self.links = []
        self.canonical = []
        self.description = []
        self.h1 = 0
        self.playgrounds = []
        self.title = ""
        self.in_title = False
        self.feed(path.read_text())

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "playground" in attrs.get("class", "").split() and "data-config" in attrs:
            self.playgrounds.append(json.loads(attrs["data-config"]))
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "h1":
            self.h1 += 1
        if tag == "title":
            self.in_title = True
        if tag == "link" and attrs.get("rel") == "canonical":
            self.canonical.append(attrs.get("href"))
        if tag == "meta" and attrs.get("name") == "description":
            self.description.append(attrs.get("content"))
        for attr in ("href", "src"):
            if attrs.get(attr):
                # The default 404 canonical is not a navigable content route.
                if self.path.name == "404.html" and tag == "link" and attrs.get("rel") == "canonical":
                    continue
                self.links.append(attrs[attr])

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data


def external_check(url):
    # GET is more reliable than HEAD across package docs and GitHub endpoints.
    for attempt in range(3):
        try:
            request = Request(url, headers={"User-Agent": "go-yara-docs-link-check/1.0"})
            with urlopen(request, timeout=30) as response:
                if response.status != 200:
                    return f"{url}: HTTP {response.status}"
            return None
        except (HTTPError, URLError, TimeoutError) as error:
            if attempt == 2:
                return f"{url}: {error}"
            time.sleep(1 + attempt)


def check(external):
    documents = {path: Document(path) for path in DIST.rglob("*.html")}
    pages = {path: doc for path, doc in documents.items() if path.name != "404.html"}
    if len(pages) != 9:
        raise SystemExit(f"Expected nine built pages, got {len(pages)}")
    errors, external_urls, canonicals, titles, descriptions = [], set(), set(), set(), set()
    for path, doc in documents.items():
        relative = path.relative_to(DIST).as_posix()
        page_url = ORIGIN + BASE + (relative.removesuffix("index.html") if relative.endswith("index.html") else relative)
        if path in pages:
            if doc.canonical != [page_url] or doc.h1 != 1 or len(doc.description) != 1 or not doc.title:
                errors.append(f"{relative}: invalid canonical, h1, title, or description")
            canonicals.add(page_url)
            titles.add(doc.title)
            descriptions.update(doc.description)
        for link in doc.links:
            resolved = urlsplit(urljoin(page_url, link))
            if resolved.scheme not in ("http", "https"):
                continue
            if resolved.netloc != urlsplit(ORIGIN).netloc:
                external_urls.add(urlunsplit((resolved.scheme, resolved.netloc, resolved.path, resolved.query, "")))
                continue
            if not resolved.path.startswith(BASE):
                errors.append(f"{relative}: link escapes Pages base: {link}")
                continue
            local = DIST / unquote(resolved.path[len(BASE):])
            if local.is_dir():
                local /= "index.html"
            if not local.is_file():
                errors.append(f"{relative}: missing target {link}")
            elif resolved.fragment and local in documents and unquote(resolved.fragment) not in documents[local].ids:
                errors.append(f"{relative}: missing anchor {link}")
    if len(titles) != 9 or len(descriptions) != 9:
        errors.append("Titles and descriptions must be unique")
    # Worker/shim/Wasm paths live in configuration, not ordinary href/src links.
    metadata = json.loads((SITE / "src/generated/playground.json").read_text())
    release = json.loads((SITE / "src/generated/release.json").read_text())
    configs = [config for doc in pages.values() for config in doc.playgrounds]
    if configs != [metadata] or metadata["version"] != release["version"]:
        errors.append("Playground configuration differs from the documentation release")
    runtime = DIST / metadata["workerURL"].removeprefix(BASE)
    for name in ["worker.js", "wasm_exec.js", "scanner.wasm", "manifest.json"]:
        if not (runtime.parent / name).is_file():
            errors.append(f"Missing playground asset: {name}")
    wasm = runtime.parent / "scanner.wasm"
    if wasm.is_file() and hashlib.sha256(wasm.read_bytes()).hexdigest() != metadata["sha256"]:
        errors.append("Playground binary does not match its manifest")
    sitemap_urls = set()
    for sitemap in DIST.glob("sitemap-*.xml"):
        root = ET.parse(sitemap).getroot()
        if root.tag.endswith("urlset"):
            sitemap_urls.update(element.text for element in root.findall("{*}url/{*}loc"))
    if sitemap_urls != canonicals:
        errors.append(f"Sitemap differs from content routes: {sitemap_urls ^ canonicals}")
    if external:
        with ThreadPoolExecutor(max_workers=4) as pool:
            errors.extend(error for error in pool.map(external_check, sorted(external_urls)) if error)
    if errors:
        raise SystemExit("\n".join(sorted(set(errors))))
    print(f"Built checks passed: {len(pages)} pages, internal links, anchors, assets, metadata, sitemap")
    if external:
        print(f"External checks passed: {len(external_urls)} distinct URLs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--external", action="store_true")
    check(parser.parse_args().external)
