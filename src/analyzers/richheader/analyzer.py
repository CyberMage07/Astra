"""PE Rich Header analysis for Astra."""

from __future__ import annotations

import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pefile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    Evidence,
    Finding,
    RichHeaderAnalysisData,
    RichHeaderEntry,
    Severity,
)

DANS_MARKER = 0x536E6144
RICH_MARKER = b"Rich"

PRODUCT_MAP: dict[int, tuple[str, str]] = {
    0x0001: ("Import0", "Microsoft toolchain"),
    0x0002: ("Linker510", "Visual Studio 97"),
    0x0003: ("Cvtomf510", "Visual Studio 97"),
    0x0004: ("Linker600", "Visual Studio 6.0"),
    0x0005: ("Cvtomf600", "Visual Studio 6.0"),
    0x0006: ("Cvtres500", "Visual Studio 6.0"),
    0x0007: ("Utc11_Basic", "Visual Studio 6.0"),
    0x0008: ("Utc11_C", "Visual Studio 6.0"),
    0x0009: ("Utc12_Basic", "Visual Studio .NET 2002"),
    0x000A: ("Utc12_C", "Visual Studio .NET 2002"),
    0x000B: ("Utc12_CPP", "Visual Studio .NET 2002"),
    0x000C: ("AliasObj60", "Visual Studio 6.0"),
    0x000D: ("VisualBasic60", "Visual Studio 6.0"),
    0x000E: ("Masm613", "Visual Studio 6.0"),
    0x000F: ("Masm710", "Visual Studio .NET 2003"),
    0x0010: ("Linker511", "Visual Studio 97"),
    0x0011: ("Cvtomf511", "Visual Studio 97"),
    0x0012: ("Masm614", "Visual Studio 6.0"),
    0x0013: ("Linker512", "Visual Studio 97"),
    0x0014: ("Cvtomf512", "Visual Studio 97"),
    0x0015: ("Utc12_CVTCIL_C", "Visual Studio .NET"),
    0x0016: ("Utc12_CVTCIL_CPP", "Visual Studio .NET"),
    0x0017: ("Cvtres501", "Visual Studio 6.0"),
    0x0018: ("Utc13_Basic", "Visual Studio .NET 2003"),
    0x0019: ("Utc13_C", "Visual Studio .NET 2003"),
    0x001A: ("Utc13_CPP", "Visual Studio .NET 2003"),
    0x001B: ("Linker610", "Visual Studio 6.0"),
    0x001C: ("Cvtomf610", "Visual Studio 6.0"),
    0x001D: ("Linker601", "Visual Studio 6.0"),
    0x001E: ("Cvtomf601", "Visual Studio 6.0"),
    0x001F: ("Utc12_1_Basic", "Visual Studio .NET 2002"),
    0x0020: ("Utc12_1_C", "Visual Studio .NET 2002"),
    0x0021: ("Utc12_1_CPP", "Visual Studio .NET 2002"),
    0x0022: ("Linker620", "Visual Studio 6.0"),
    0x0023: ("Cvtomf620", "Visual Studio 6.0"),
    0x0024: ("AliasObj70", "Visual Studio .NET"),
    0x0025: ("Linker621", "Visual Studio 6.0"),
    0x0026: ("Cvtomf621", "Visual Studio 6.0"),
    0x0027: ("Masm615", "Visual Studio 6.0"),
    0x0028: ("Utc13_LTCG_C", "Visual Studio .NET 2003"),
    0x0029: ("Utc13_LTCG_CPP", "Visual Studio .NET 2003"),
    0x002A: ("Masm620", "Visual Studio 6.0"),
    0x002B: ("ILAsm100", ".NET Framework"),
    0x002C: ("Utc12_2_Basic", "Visual Studio .NET 2002"),
    0x002D: ("Utc12_2_C", "Visual Studio .NET 2002"),
    0x002E: ("Utc12_2_CPP", "Visual Studio .NET 2002"),
    0x002F: ("Utc12_2_CVTCIL_C", "Visual Studio .NET 2002"),
    0x0030: ("Utc12_2_CVTCIL_CPP", "Visual Studio .NET 2002"),
    0x0031: ("Cvtres700", "Visual Studio .NET"),
    0x0032: ("Cvtres710", "Visual Studio .NET 2003"),
    0x0033: ("Linker700", "Visual Studio .NET 2002"),
    0x0034: ("Cvtomf700", "Visual Studio .NET 2002"),
    0x0035: ("Linker710", "Visual Studio .NET 2003"),
    0x0036: ("Cvtomf710", "Visual Studio .NET 2003"),
    0x0037: ("Masm700", "Visual Studio .NET 2002"),
    0x0038: ("Masm710", "Visual Studio .NET 2003"),
    0x0039: ("Utc13_CVTCIL_C", "Visual Studio .NET 2003"),
    0x003A: ("Utc13_CVTCIL_CPP", "Visual Studio .NET 2003"),
    0x003B: ("Masm800", "Visual Studio 2005"),
    0x003C: ("Utc14_C", "Visual Studio 2005"),
    0x003D: ("Utc14_CPP", "Visual Studio 2005"),
    0x003E: ("Utc14_CVTCIL_C", "Visual Studio 2005"),
    0x003F: ("Utc14_CVTCIL_CPP", "Visual Studio 2005"),
    0x0040: ("Utc14_LTCG_C", "Visual Studio 2005"),
    0x0041: ("Utc14_LTCG_CPP", "Visual Studio 2005"),
    0x0042: ("Cvtres800", "Visual Studio 2005"),
    0x0043: ("Linker800", "Visual Studio 2005"),
    0x0044: ("Cvtomf800", "Visual Studio 2005"),
    0x0045: ("AliasObj80", "Visual Studio 2005"),
    0x0046: ("PhoenixPrerelease", "Microsoft Phoenix"),
    0x0047: ("Utc14_POGO_I_C", "Visual Studio 2005"),
    0x0048: ("Utc14_POGO_I_CPP", "Visual Studio 2005"),
    0x0049: ("Utc14_POGO_O_C", "Visual Studio 2005"),
    0x004A: ("Utc14_POGO_O_CPP", "Visual Studio 2005"),
    0x005D: ("Utc1500_C", "Visual Studio 2008"),
    0x005E: ("Utc1500_CPP", "Visual Studio 2008"),
    0x005F: ("Utc1500_CVTCIL_C", "Visual Studio 2008"),
    0x0060: ("Utc1500_CVTCIL_CPP", "Visual Studio 2008"),
    0x0061: ("Utc1500_LTCG_C", "Visual Studio 2008"),
    0x0062: ("Utc1500_LTCG_CPP", "Visual Studio 2008"),
    0x0063: ("Cvtres900", "Visual Studio 2008"),
    0x0064: ("Linker900", "Visual Studio 2008"),
    0x0065: ("Masm900", "Visual Studio 2008"),
    0x0066: ("AliasObj90", "Visual Studio 2008"),
    0x0078: ("Utc1600_C", "Visual Studio 2010"),
    0x0079: ("Utc1600_CPP", "Visual Studio 2010"),
    0x007A: ("Utc1600_CVTCIL_C", "Visual Studio 2010"),
    0x007B: ("Utc1600_CVTCIL_CPP", "Visual Studio 2010"),
    0x007C: ("Utc1600_LTCG_C", "Visual Studio 2010"),
    0x007D: ("Utc1600_LTCG_CPP", "Visual Studio 2010"),
    0x007E: ("Cvtres1000", "Visual Studio 2010"),
    0x007F: ("Linker1000", "Visual Studio 2010"),
    0x0080: ("Masm1000", "Visual Studio 2010"),
    0x0081: ("AliasObj1000", "Visual Studio 2010"),
    0x0091: ("Utc1700_C", "Visual Studio 2012"),
    0x0092: ("Utc1700_CPP", "Visual Studio 2012"),
    0x0093: ("Utc1700_CVTCIL_C", "Visual Studio 2012"),
    0x0094: ("Utc1700_CVTCIL_CPP", "Visual Studio 2012"),
    0x0095: ("Utc1700_LTCG_C", "Visual Studio 2012"),
    0x0096: ("Utc1700_LTCG_CPP", "Visual Studio 2012"),
    0x0097: ("Cvtres1100", "Visual Studio 2012"),
    0x0098: ("Linker1100", "Visual Studio 2012"),
    0x0099: ("Masm1100", "Visual Studio 2012"),
    0x009A: ("AliasObj1100", "Visual Studio 2012"),
    0x00AA: ("Utc1800_C", "Visual Studio 2013"),
    0x00AB: ("Utc1800_CPP", "Visual Studio 2013"),
    0x00AC: ("Utc1800_CVTCIL_C", "Visual Studio 2013"),
    0x00AD: ("Utc1800_CVTCIL_CPP", "Visual Studio 2013"),
    0x00AE: ("Utc1800_LTCG_C", "Visual Studio 2013"),
    0x00AF: ("Utc1800_LTCG_CPP", "Visual Studio 2013"),
    0x00B0: ("Cvtres1200", "Visual Studio 2013"),
    0x00B1: ("Linker1200", "Visual Studio 2013"),
    0x00B2: ("Masm1200", "Visual Studio 2013"),
    0x00B3: ("AliasObj1200", "Visual Studio 2013"),
    0x00C1: ("Utc1900_C", "Visual Studio 2015"),
    0x00C2: ("Utc1900_CPP", "Visual Studio 2015"),
    0x00C3: ("Utc1900_CVTCIL_C", "Visual Studio 2015"),
    0x00C4: ("Utc1900_CVTCIL_CPP", "Visual Studio 2015"),
    0x00C5: ("Utc1900_LTCG_C", "Visual Studio 2015"),
    0x00C6: ("Utc1900_LTCG_CPP", "Visual Studio 2015"),
    0x00C7: ("Cvtres1400", "Visual Studio 2015"),
    0x00C8: ("Linker1400", "Visual Studio 2015"),
    0x00C9: ("Masm1400", "Visual Studio 2015"),
    0x00CA: ("AliasObj1400", "Visual Studio 2015"),
    0x00D1: ("Utc1910_C", "Visual Studio 2017"),
    0x00D2: ("Utc1910_CPP", "Visual Studio 2017"),
    0x00D3: ("Utc1910_CVTCIL_C", "Visual Studio 2017"),
    0x00D4: ("Utc1910_CVTCIL_CPP", "Visual Studio 2017"),
    0x00D5: ("Utc1910_LTCG_C", "Visual Studio 2017"),
    0x00D6: ("Utc1910_LTCG_CPP", "Visual Studio 2017"),
    0x00D7: ("Cvtres1410", "Visual Studio 2017"),
    0x00D8: ("Linker1410", "Visual Studio 2017"),
    0x00D9: ("Masm1410", "Visual Studio 2017"),
    0x00DA: ("AliasObj1410", "Visual Studio 2017"),
    0x00E1: ("Utc1920_C", "Visual Studio 2019"),
    0x00E2: ("Utc1920_CPP", "Visual Studio 2019"),
    0x00E3: ("Utc1920_CVTCIL_C", "Visual Studio 2019"),
    0x00E4: ("Utc1920_CVTCIL_CPP", "Visual Studio 2019"),
    0x00E5: ("Utc1920_LTCG_C", "Visual Studio 2019"),
    0x00E6: ("Utc1920_LTCG_CPP", "Visual Studio 2019"),
    0x00E7: ("Cvtres1420", "Visual Studio 2019"),
    0x00E8: ("Linker1420", "Visual Studio 2019"),
    0x00E9: ("Masm1420", "Visual Studio 2019"),
    0x00EA: ("AliasObj1420", "Visual Studio 2019"),
    0x00F1: ("Utc1930_C", "Visual Studio 2022"),
    0x00F2: ("Utc1930_CPP", "Visual Studio 2022"),
    0x00F3: ("Utc1930_CVTCIL_C", "Visual Studio 2022"),
    0x00F4: ("Utc1930_CVTCIL_CPP", "Visual Studio 2022"),
    0x00F5: ("Utc1930_LTCG_C", "Visual Studio 2022"),
    0x00F6: ("Utc1930_LTCG_CPP", "Visual Studio 2022"),
    0x00F7: ("Cvtres1430", "Visual Studio 2022"),
    0x00F8: ("Linker1430", "Visual Studio 2022"),
    0x00F9: ("Masm1430", "Visual Studio 2022"),
    0x00FA: ("AliasObj1430", "Visual Studio 2022"),
}


def _dos_stub_end(sample_data: bytes) -> int | None:
    """Return the PE header offset from the DOS header."""
    if len(sample_data) < 0x40:
        return None

    if not sample_data.startswith(b"MZ"):
        return None

    return int.from_bytes(
        sample_data[0x3C:0x40],
        byteorder="little",
    )


def _find_rich_marker(
    sample_data: bytes,
    search_end: int,
) -> int | None:
    """Return the last Rich marker before the PE header."""
    offset = sample_data.rfind(
        RICH_MARKER,
        0,
        search_end,
    )

    if offset < 0:
        return None

    if offset + 8 > search_end:
        return None

    return offset


def _decode_rich_region(
    sample_data: bytes,
    *,
    rich_offset: int,
    xor_key: int,
) -> tuple[int | None, tuple[int, ...]]:
    """Decode DWORDs before the Rich marker and locate DanS."""
    decoded: list[int] = []
    dans_offset: int | None = None

    cursor = rich_offset - 4

    while cursor >= 0:
        encoded = int.from_bytes(
            sample_data[cursor : cursor + 4],
            byteorder="little",
        )
        value = encoded ^ xor_key

        decoded.append(value)

        if value == DANS_MARKER:
            dans_offset = cursor
            break

        cursor -= 4

    decoded.reverse()

    return dans_offset, tuple(decoded)


def _decode_entries(
    decoded_words: tuple[int, ...],
) -> tuple[RichHeaderEntry, ...]:
    """Decode Rich component/count pairs after the DanS header."""
    if len(decoded_words) < 4:
        return ()

    payload = decoded_words[4:]
    entries: list[RichHeaderEntry] = []

    for index in range(
        0,
        len(payload) - 1,
        2,
    ):
        component_id = payload[index]
        count = payload[index + 1]

        product_id = (component_id >> 16) & 0xFFFF
        build_number = component_id & 0xFFFF

        mapped = PRODUCT_MAP.get(product_id)

        if mapped is None:
            product_name = None
            toolchain_family = None
        else:
            product_name, toolchain_family = mapped

        entries.append(
            RichHeaderEntry(
                product_id=product_id,
                build_number=build_number,
                count=count,
                component_id=component_id,
                product_name=product_name,
                toolchain_family=toolchain_family,
            )
        )

    return tuple(entries)


def _rotate_left_32(
    value: int,
    count: int,
) -> int:
    """Rotate an integer left within 32 bits."""
    value &= 0xFFFFFFFF
    rotation = count & 31

    if rotation == 0:
        return value

    return ((value << rotation) | (value >> (32 - rotation))) & 0xFFFFFFFF


def _checksum(
    sample_data: bytes,
    *,
    rich_header_start: int,
    entries: tuple[RichHeaderEntry, ...],
) -> int:
    """Calculate the Rich Header XOR checksum."""
    checksum = rich_header_start

    for index, byte in enumerate(sample_data[:rich_header_start]):
        if 0x3C <= index < 0x40:
            continue

        checksum = (
            checksum
            + _rotate_left_32(
                byte,
                index,
            )
        ) & 0xFFFFFFFF

    for entry in entries:
        checksum = (
            checksum
            + _rotate_left_32(
                entry.component_id,
                entry.count,
            )
        ) & 0xFFFFFFFF

    return checksum


def _build_findings(
    data: RichHeaderAnalysisData,
) -> tuple[Finding, ...]:
    """Generate findings from Rich Header properties."""
    findings: list[Finding] = []

    if not data.rich_header_present:
        return ()

    if data.malformed:
        findings.append(
            Finding(
                title="Malformed PE Rich Header detected",
                description=("The Rich Header markers or decoded structure are inconsistent."),
                category="pe-rich-header",
                severity=Severity.MEDIUM,
                confidence=80,
                evidence=(
                    Evidence(
                        kind="rich-header",
                        value="malformed",
                        location="DOS stub",
                    ),
                ),
                tags=(
                    "pe",
                    "rich-header",
                    "malformed",
                ),
            )
        )

    if data.checksum_valid is False:
        findings.append(
            Finding(
                title="Rich Header checksum mismatch",
                description=(
                    "The decoded Rich Header checksum does not match "
                    "the calculated DOS-stub checksum."
                ),
                category="pe-rich-header",
                severity=Severity.LOW,
                confidence=75,
                evidence=(
                    Evidence(
                        kind="rich-header-checksum",
                        value=(f"0x{data.xor_key:08x}" if data.xor_key is not None else "unknown"),
                        location="Rich marker",
                    ),
                ),
                tags=(
                    "pe",
                    "rich-header",
                    "checksum",
                ),
            )
        )

    if data.zero_count_entries:
        findings.append(
            Finding(
                title="Zero-count Rich Header entries detected",
                description=(
                    "One or more decoded Rich Header component records contain a zero object count."
                ),
                category="pe-rich-header",
                severity=Severity.INFO,
                confidence=60,
                evidence=(
                    Evidence(
                        kind="rich-header-entry-count",
                        value=str(data.zero_count_entries),
                        location="Rich Header records",
                    ),
                ),
                tags=(
                    "pe",
                    "rich-header",
                    "toolchain",
                ),
            )
        )

    if data.unknown_product_entries:
        findings.append(
            Finding(
                title="Unknown Rich Header product identifiers detected",
                description=(
                    "One or more Rich Header component identifiers "
                    "could not be mapped to a known Microsoft toolchain."
                ),
                category="pe-rich-header",
                severity=Severity.INFO,
                confidence=55,
                evidence=(
                    Evidence(
                        kind="rich-header-product",
                        value=str(data.unknown_product_entries),
                        location="Rich Header records",
                    ),
                ),
                tags=(
                    "pe",
                    "rich-header",
                    "unknown-toolchain",
                ),
            )
        )

    return tuple(findings)


class RichHeaderAnalyzer:
    """Analyze and decode PE Rich Header metadata."""

    name = "richheader"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisResult:
        """Analyze PE Rich Header metadata."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()
        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        try:
            sample_data = resolved_path.read_bytes()

            pe = pefile.PE(
                str(resolved_path),
                fast_load=True,
            )

            try:
                pe_offset = _dos_stub_end(sample_data)

                if pe_offset is None:
                    raise pefile.PEFormatError("Invalid DOS header")

                rich_offset = _find_rich_marker(
                    sample_data,
                    pe_offset,
                )

                if rich_offset is None:
                    analysis_data = RichHeaderAnalysisData(
                        rich_header_present=False,
                    )
                else:
                    xor_key = int.from_bytes(
                        sample_data[rich_offset + 4 : rich_offset + 8],
                        byteorder="little",
                    )

                    (
                        dans_offset,
                        decoded_words,
                    ) = _decode_rich_region(
                        sample_data,
                        rich_offset=rich_offset,
                        xor_key=xor_key,
                    )

                    malformed = (
                        dans_offset is None
                        or len(decoded_words) < 4
                        or len(decoded_words[4:]) % 2 != 0
                    )

                    entries = _decode_entries(decoded_words) if not malformed else ()

                    product_counts = Counter(entry.component_id for entry in entries)

                    duplicate_entries = sum(
                        count - 1 for count in product_counts.values() if count > 1
                    )

                    zero_count_entries = sum(entry.count == 0 for entry in entries)

                    unknown_product_entries = sum(entry.product_name is None for entry in entries)

                    toolchain_families = tuple(
                        sorted(
                            {
                                entry.toolchain_family
                                for entry in entries
                                if entry.toolchain_family is not None
                            }
                        )
                    )

                    calculated_checksum = (
                        _checksum(
                            sample_data,
                            rich_header_start=dans_offset,
                            # pe_offset=pe_offset,
                            entries=entries,
                        )
                        if dans_offset is not None and not malformed
                        else None
                    )

                    checksum_valid = (
                        calculated_checksum == xor_key if calculated_checksum is not None else None
                    )

                    analysis_data = RichHeaderAnalysisData(
                        rich_header_present=True,
                        dans_offset=dans_offset,
                        rich_offset=rich_offset,
                        xor_key=xor_key,
                        checksum_valid=checksum_valid,
                        malformed=malformed,
                        entry_count=len(entries),
                        total_object_count=sum(entry.count for entry in entries),
                        unique_product_ids=tuple(sorted({entry.product_id for entry in entries})),
                        unique_build_numbers=tuple(
                            sorted({entry.build_number for entry in entries})
                        ),
                        toolchain_families=(toolchain_families),
                        entries=entries,
                        duplicate_entries=duplicate_entries,
                        zero_count_entries=(zero_count_entries),
                        unknown_product_entries=(unknown_product_entries),
                    )
            finally:
                pe.close()

            findings = _build_findings(analysis_data)
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=AnalysisStatus.COMPLETED,
                started_at=started_at,
                duration_ms=duration_ms,
                findings=findings,
                data=analysis_data.model_dump(mode="json"),
            )

        except pefile.PEFormatError as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=AnalysisStatus.FAILED,
                started_at=started_at,
                duration_ms=duration_ms,
                errors=(
                    AnalyzerError(
                        error_type=type(error).__name__,
                        message=str(error),
                        recoverable=False,
                    ),
                ),
            )

        except Exception as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=AnalysisStatus.PARTIAL,
                started_at=started_at,
                duration_ms=duration_ms,
                errors=(
                    AnalyzerError(
                        error_type=type(error).__name__,
                        message=str(error),
                        recoverable=True,
                    ),
                ),
            )
