"""Content-based file identification for Astra."""

from pathlib import Path

import magic

from packages.schemas import FileTypeResult

EXECUTABLE_FAMILIES = {
    "pe",
    "elf",
    "mach-o",
    "dos",
}

GENERIC_EXTENSIONS = {
    "",
    ".bin",
    ".dat",
    ".file",
    ".raw",
    ".sample",
    ".unknown",
}

FAMILY_EXTENSION_MAP: dict[str, set[str]] = {
    "pe": {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"},
    "elf": {"", ".elf", ".so", ".bin", ".out"},
    "mach-o": {"", ".dylib", ".bundle", ".app"},
    "pdf": {".pdf"},
    "office": {
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".rtf",
    },
    "apk": {".apk"},
    "archive": {
        ".zip",
        ".7z",
        ".rar",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".zst",
    },
    "script": {
        ".py",
        ".sh",
        ".bash",
        ".fish",
        ".ps1",
        ".js",
        ".vbs",
        ".bat",
        ".cmd",
    },
    "text": {
        ".txt",
        ".log",
        ".csv",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
    },
}


def _detect_family(
    mime_type: str,
    description: str,
) -> str:
    """Map libmagic output to an Astra file family."""
    normalized_mime = mime_type.lower()
    normalized_description = description.lower()

    if (
        "portable executable" in normalized_description
        or "pe32" in normalized_description
        or "ms-dos executable" in normalized_description
        or normalized_mime
        in {
            "application/vnd.microsoft.portable-executable",
            "application/x-dosexec",
            "application/x-msdownload",
        }
    ):
        return "pe"

    if "elf " in normalized_description or normalized_mime == "application/x-elf":
        return "elf"

    if "mach-o" in normalized_description:
        return "mach-o"

    if normalized_mime == "application/pdf" or "pdf document" in normalized_description:
        return "pdf"

    if normalized_mime in {
        "application/vnd.android.package-archive",
        "application/x-android-package",
    }:
        return "apk"

    if normalized_mime in {
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/rtf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }:
        return "office"

    if normalized_mime.startswith("application/zip") or normalized_mime in {
        "application/x-7z-compressed",
        "application/vnd.rar",
        "application/x-rar",
        "application/x-tar",
        "application/gzip",
        "application/x-bzip2",
        "application/x-xz",
        "application/zstd",
    }:
        return "archive"

    if (
        normalized_mime.startswith("text/x-")
        or "script" in normalized_description
        or "shell commands" in normalized_description
    ):
        return "script"

    if normalized_mime.startswith("text/"):
        return "text"

    if normalized_mime.startswith("image/"):
        return "image"

    if normalized_mime.startswith("audio/"):
        return "audio"

    if normalized_mime.startswith("video/"):
        return "video"

    return "unknown"


def _extension_matches(
    extension: str,
    family: str,
) -> bool | None:
    """Check whether a filename extension agrees with detected content."""
    if extension in GENERIC_EXTENSIONS:
        return None

    allowed_extensions = FAMILY_EXTENSION_MAP.get(family)

    if allowed_extensions is None:
        return None

    return extension in allowed_extensions


def _calculate_confidence(
    family: str,
    extension_matches: bool | None,
) -> int:
    """Calculate confidence in the normalized file-family decision."""
    if family == "unknown":
        return 25

    if extension_matches is True:
        return 100

    if extension_matches is False:
        return 95

    return 85


def identify_file(file_path: Path) -> FileTypeResult:
    """Identify a file using libmagic and extension correlation."""
    resolved_path = file_path.expanduser().resolve()

    if not resolved_path.exists():
        raise FileNotFoundError(resolved_path)

    if not resolved_path.is_file():
        raise ValueError(f"Path is not a regular file: {resolved_path}")

    mime_detector = magic.Magic(mime=True)
    description_detector = magic.Magic(mime=False)

    mime_type = str(mime_detector.from_file(str(resolved_path)))
    magic_description = str(description_detector.from_file(str(resolved_path)))

    extension = resolved_path.suffix.lower()
    detected_family = _detect_family(mime_type, magic_description)
    extension_matches = _extension_matches(extension, detected_family)

    return FileTypeResult(
        file_name=resolved_path.name,
        extension=extension,
        mime_type=mime_type,
        magic_description=magic_description,
        detected_family=detected_family,
        extension_matches=extension_matches,
        is_executable=detected_family in EXECUTABLE_FAMILIES,
        confidence=_calculate_confidence(detected_family, extension_matches),
        source_path=resolved_path,
    )
