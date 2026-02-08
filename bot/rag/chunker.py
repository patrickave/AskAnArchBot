"""Markdown chunker for knowledge files.

Splits knowledge markdown files at H2 (##) headers, sub-splitting at H3 (###)
when an H2 chunk exceeds 300 lines.  Each chunk carries metadata for logging
and prompt assembly.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path


@dataclasses.dataclass(frozen=True)
class Chunk:
    """A single chunk of knowledge text with provenance metadata."""

    text: str
    source_file: str
    h2_header: str
    h3_header: str  # empty string when the chunk is a full H2 section
    line_start: int
    line_end: int

    @property
    def heading_path(self) -> str:
        if self.h3_header:
            return f"{self.source_file} > {self.h2_header} > {self.h3_header}"
        return f"{self.source_file} > {self.h2_header}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _split_at_header(lines: list[str], prefix: str) -> list[tuple[str, int, list[str]]]:
    """Split *lines* at lines starting with *prefix* (e.g. ``'## '``).

    Returns a list of ``(header_text, start_line_offset, body_lines)`` tuples.
    Content before the first matching header is grouped under header ``""``.
    """
    sections: list[tuple[str, int, list[str]]] = []
    current_header = ""
    current_start = 0
    current_lines: list[str] = []

    for idx, line in enumerate(lines):
        # Must start with the prefix exactly (e.g. "## " but not "### ")
        if line.startswith(prefix) and (
            len(prefix) >= len(line) or not line[len(prefix) - 1] == "#"
        ):
            # flush previous section
            if current_lines or current_header:
                sections.append((current_header, current_start, current_lines))
            current_header = line.strip().lstrip("#").strip()
            current_start = idx
            current_lines = [line]
        else:
            current_lines.append(line)

    # flush last section
    if current_lines or current_header:
        sections.append((current_header, current_start, current_lines))

    return sections


def _is_h2(line: str) -> bool:
    return line.startswith("## ") and not line.startswith("### ")


_MAX_H2_LINES = 300


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def chunk_file(path: Path) -> list[Chunk]:
    """Chunk a single markdown file into retrieval-sized pieces."""
    text = path.read_text()
    lines = text.splitlines(keepends=True)
    source = path.stem

    h2_sections = _split_at_header(lines, "## ")
    chunks: list[Chunk] = []

    for h2_header, h2_start, h2_lines in h2_sections:
        if not h2_header:
            # Preamble before first H2 — skip (title / intro blurb)
            continue

        if len(h2_lines) <= _MAX_H2_LINES:
            body = "".join(h2_lines).strip()
            if body:
                chunks.append(Chunk(
                    text=body,
                    source_file=source,
                    h2_header=h2_header,
                    h3_header="",
                    line_start=h2_start + 1,  # 1-based
                    line_end=h2_start + len(h2_lines),
                ))
        else:
            # Sub-split at H3
            h3_sections = _split_at_header(h2_lines, "### ")
            for h3_header, h3_offset, h3_lines in h3_sections:
                body = "".join(h3_lines).strip()
                if not body:
                    continue
                chunks.append(Chunk(
                    text=body,
                    source_file=source,
                    h2_header=h2_header,
                    h3_header=h3_header,
                    line_start=h2_start + h3_offset + 1,
                    line_end=h2_start + h3_offset + len(h3_lines),
                ))

    return chunks


def chunk_directory(knowledge_dir: Path) -> list[Chunk]:
    """Chunk all ``.md`` files in *knowledge_dir* (skips README.md)."""
    chunks: list[Chunk] = []
    for md_file in sorted(knowledge_dir.glob("*.md")):
        if md_file.name == "README.md":
            continue
        chunks.extend(chunk_file(md_file))
    return chunks
