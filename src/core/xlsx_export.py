"""Tiny dependency-free XLSX writer for local administrative exports.

The writer intentionally supports the narrow NetShare reporting contract only:
multiple worksheets, scalar cells and a bold header row. It keeps reporting
available in packaged builds without adding an office-library dependency.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape
import math
import re
import zipfile

_INVALID_SHEET = re.compile(r"[\\/*?:\[\]]")


def _sheet_name(value: str, used: set[str]) -> str:
    base = _INVALID_SHEET.sub("_", str(value or "Sheet")).strip("'")[:31] or "Sheet"
    name = base
    index = 2
    while name.casefold() in used:
        suffix = f" {index}"
        name = f"{base[:31-len(suffix)]}{suffix}"
        index += 1
    used.add(name.casefold())
    return name


def _column_name(index: int) -> str:
    result = ""
    value = index
    while value:
        value, remainder = divmod(value - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _cell(ref: str, value, *, header: bool = False) -> str:
    style = ' s="1"' if header else ""
    if value is None:
        return f'<c r="{ref}"{style} t="inlineStr"><is><t></t></is></c>'
    if isinstance(value, bool):
        return f'<c r="{ref}"{style} t="b"><v>{1 if value else 0}</v></c>'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if math.isfinite(number):
            rendered = str(int(value)) if isinstance(value, int) else repr(number)
            return f'<c r="{ref}"{style}><v>{rendered}</v></c>'
    if isinstance(value, datetime):
        value = value.isoformat(timespec="seconds")
    text = escape(str(value), {'"': '&quot;'})
    preserve = ' xml:space="preserve"' if text != text.strip() else ""
    return f'<c r="{ref}"{style} t="inlineStr"><is><t{preserve}>{text}</t></is></c>'


def _worksheet(rows: list[list]) -> str:
    xml_rows = []
    max_columns = 1
    for row_index, row in enumerate(rows, 1):
        values = list(row)
        max_columns = max(max_columns, len(values))
        cells = "".join(
            _cell(f"{_column_name(column_index)}{row_index}", value, header=row_index == 1)
            for column_index, value in enumerate(values, 1)
        )
        xml_rows.append(f'<row r="{row_index}">{cells}</row>')
    dimension = f"A1:{_column_name(max_columns)}{max(1, len(rows))}"
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="{dimension}"/><sheetViews><sheetView workbookViewId="0"/></sheetViews>'
        '<sheetFormatPr defaultRowHeight="15"/><sheetData>'
        + "".join(xml_rows)
        + '</sheetData></worksheet>'
    )


def write_xlsx(target_path: str | Path, sheets: list[tuple[str, list[list]]]) -> Path:
    target = Path(target_path).expanduser()
    if target.suffix.lower() != ".xlsx":
        target = target.with_suffix(".xlsx")
    target.parent.mkdir(parents=True, exist_ok=True)
    if not sheets:
        sheets = [("Report", [["Status"], ["No data"]])]

    used: set[str] = set()
    normalized = [(_sheet_name(name, used), rows or [[]]) for name, rows in sheets]
    content_types = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
    ]
    for index in range(1, len(normalized) + 1):
        content_types.append(
            f'<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    content_types.append('</Types>')

    workbook_sheets = "".join(
        f'<sheet name="{escape(name)}" sheetId="{index}" r:id="rId{index}"/>'
        for index, (name, _) in enumerate(normalized, 1)
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets>{workbook_sheets}</sheets></workbook>'
    )
    workbook_rels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    for index in range(1, len(normalized) + 1):
        workbook_rels.append(
            f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>'
        )
    workbook_rels.append(
        f'<Relationship Id="rId{len(normalized)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    )
    workbook_rels.append('</Relationships>')

    styles = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="1"><fill><patternFill patternType="none"/></fill></fills>'
        '<borders count="1"><border/></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
        '</styleSheet>'
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>'
    )

    temp = target.with_suffix(target.suffix + ".tmp")
    with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "".join(content_types))
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", "".join(workbook_rels))
        archive.writestr("xl/styles.xml", styles)
        for index, (_, rows) in enumerate(normalized, 1):
            archive.writestr(f"xl/worksheets/sheet{index}.xml", _worksheet(rows))
    temp.replace(target)
    return target
