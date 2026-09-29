"""Archive inspection, malformed-input robustness and CLI tests."""

import io
import json
import time
import zipfile
from email.message import EmailMessage

import pytest

from phishtriage.analyzer import Analyzer
from phishtriage.cli import main
from phishtriage.parser import load_email


def _zip(entries, encrypted=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypted:
        # zipfile can't write encrypted archives and recomputes flag_bits on
        # write, so set the "encrypted" bit in the headers the way a
        # password-protected zip carries it: local header +6, central +8.
        for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = raw.find(sig)
            while pos != -1:
                raw[pos + offset] |= 0x1
                pos = raw.find(sig, pos + 4)
    return bytes(raw)


def _email(attachments=(), html='<p>Hi, see the <a href="https://example.com/doc">document</a>.</p>'):
    m = EmailMessage()
    m["From"] = "HR <hr@company-benefits.test>"
    m["To"] = "victim@example.org"
    m["Subject"] = "Q3 benefits document"
    m.set_content("Hi, please find the document attached.")
    m.add_alternative(html, subtype="html")
    for name, data, mime in attachments:
        maintype, subtype = mime.split("/")
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return bytes(m)


def _findings(raw):
    report = Analyzer().analyze(load_email(raw))
    return report, {f.title: f for f in report.findings}


def test_executable_inside_zip_is_high():
    raw = _email([("benefits.zip", _zip([("scan_0928.exe", b"MZ")]), "application/zip")])
    report, found = _findings(raw)
    assert "Executable inside archive" in found
    assert found["Executable inside archive"].evidence == ["benefits.zip → scan_0928.exe"]
    # Same weight as a bare .exe attachment (HIGH = 5) on top of the archive note;
    # before, the only signal was the LOW archive note and the verdict was LOW.
    assert report.score == 6
    assert report.verdict.value == "medium"


def test_double_extension_and_macro_inside_zip():
    data = _zip([("docs/invoice.pdf.exe", b"MZ"), ("budget.xlsm", b"PK"), ("readme.txt", b"hi")])
    _, found = _findings(_email([("files.zip", data, "application/octet-stream")]))
    assert "Executable inside archive" in found
    assert "Macro-enabled document inside archive" in found


def test_password_protected_zip():
    data = _zip([("statement.pdf", b"%PDF")], encrypted=True)
    _, found = _findings(_email([("statement.zip", data, "application/zip")]))
    assert "Password-protected archive" in found
    assert "Executable inside archive" not in found


def test_zip_slip_and_nested_archive():
    data = _zip([("../../home/user/.bashrc", b"x"), ("inner.7z", b"7z")])
    _, found = _findings(_email([("a.zip", data, "application/zip")]))
    assert "Path traversal in archive" in found
    assert "Nested archive" in found


def test_clean_zip_only_gets_the_generic_archive_note():
    data = _zip([("report.pdf", b"%PDF"), ("photo.jpg", b"\xff\xd8")])
    _, found = _findings(_email([("report.zip", data, "application/zip")]))
    assert set(found) & {
        "Executable inside archive",
        "Password-protected archive",
        "Path traversal in archive",
        "Unreadable archive",
    } == set()
    assert "Archive attachment" in found


def test_corrupt_zip_is_flagged_not_crashing():
    _, found = _findings(_email([("broken.zip", b"PK\x03\x04garbage", "application/zip")]))
    assert "Unreadable archive" in found


def test_zip_bomb_is_listed_not_extracted():
    bomb = _zip([("huge.bin", b"\0" * (20 * 1024 * 1024))])  # 20 MB of zeros, ~20 KB zipped
    assert len(bomb) < 100_000
    start = time.perf_counter()
    _, found = _findings(_email([("bomb.zip", bomb, "application/zip")]))
    assert time.perf_counter() - start < 1.0
    assert "Executable inside archive" not in found


def test_office_documents_are_not_treated_as_zip():
    # .docx is a zip container too; it must not be unpacked as an "archive".
    docx = _zip([("word/document.xml", b"<w:document/>"), ("word/vbaProject.bin", b"x")])
    raw = _email([("letter.docx", docx, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")])
    assert load_email(raw).archives == []


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x00\xff\xfe garbage \x80\x81",
        b"Subject: =?utf-8?b?!!!notbase64?=\r\nFrom: <>\r\n\r\nbody",
        b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: multipart/mixed; boundary=y\r\n\r\n--y\r\n",
        b"From: a@b.c\r\nContent-Type: application/zip; name=a.zip\r\nContent-Transfer-Encoding: base64\r\n"
        b"Content-Disposition: attachment; filename=a.zip\r\n\r\n%%%not-base64%%%",
    ],
)
def test_malformed_input_does_not_crash(raw):
    report = Analyzer().analyze(load_email(raw))
    assert report.score >= 0


def test_cli_json_and_html(tmp_path, capsys):
    eml = tmp_path / "m.eml"
    eml.write_bytes(_email([("b.zip", _zip([("x.scr", b"MZ")]), "application/zip")]))
    out = tmp_path / "r.html"
    main([str(eml), "--json"])
    payload = json.loads(capsys.readouterr().out)
    payload = payload[0] if isinstance(payload, list) else payload
    assert any(f["title"] == "Executable inside archive" for f in payload["findings"])
    main([str(eml), "--html", str(out), "--no-color"])
    assert "Executable inside archive" in out.read_text()


def test_html_report_escapes_subject(tmp_path, capsys):
    m = EmailMessage()
    m["From"] = "x@y.test"
    m["Subject"] = "<script>alert(1)</script>"
    m.set_content("hi")
    eml = tmp_path / "x.eml"
    eml.write_bytes(bytes(m))
    out = tmp_path / "r.html"
    main([str(eml), "--html", str(out), "--no-color"])
    assert "<script>alert(1)</script>" not in out.read_text()
