"""Readers for Sysmon XML exports and native Windows EVTX files."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable
import xml.etree.ElementTree as ET


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_sysmon_xml_event(xml_text: str) -> dict[str, Any]:
    """Parse one Windows event XML document into a flat telemetry record."""
    root = ET.fromstring(xml_text)
    values: dict[str, str] = {}
    event_id: int | None = None
    computer: str | None = None
    system_time: str | None = None

    for element in root.iter():
        name = _local_name(element.tag)
        if name == "EventID" and element.text:
            event_id = int(element.text)
        elif name == "Computer" and element.text:
            computer = element.text
        elif name == "TimeCreated":
            system_time = element.attrib.get("SystemTime")
        elif name == "Data" and element.attrib.get("Name"):
            values[element.attrib["Name"]] = element.text or ""

    timestamp = values.get("UtcTime") or system_time
    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "computer": computer,
        "process_guid": values.get("ProcessGuid") or values.get("SourceProcessGUID"),
        "process_id": values.get("ProcessId") or values.get("SourceProcessId"),
        "image": values.get("Image") or values.get("SourceImage"),
        "parent_image": values.get("ParentImage"),
        "command_line": values.get("CommandLine"),
        "target_filename": values.get("TargetFilename"),
        "target_object": values.get("TargetObject"),
        "destination_ip": values.get("DestinationIp"),
        "destination_port": values.get("DestinationPort"),
        **values,
    }


def _xml_documents(contents: str) -> Iterable[str]:
    """Yield Event documents from a Splunk XML log (which has no root element)."""
    start = 0
    while True:
        begin = contents.find("<Event", start)
        if begin < 0:
            return
        end = contents.find("</Event>", begin)
        if end < 0:
            raise ValueError("Incomplete Event element in Sysmon XML log")
        yield contents[begin : end + len("</Event>")]
        start = end + len("</Event>")


def read_sysmon_xml(path: str | Path) -> list[dict[str, Any]]:
    """Read a Splunk-style XML Windows event log."""
    content = Path(path).read_text(encoding="utf-8", errors="replace")
    return [parse_sysmon_xml_event(event) for event in _xml_documents(content)]


def read_evtx(path: str | Path) -> list[dict[str, Any]]:
    """Read native EVTX. python-evtx remains optional until EVTX inputs are used."""
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:  # pragma: no cover - depends on optional package
        raise RuntimeError("EVTX support requires python-evtx. Install requirements.txt.") from exc

    with Evtx(str(path)) as log:
        return [parse_sysmon_xml_event(record.xml()) for record in log.records()]


def read_events(path: str | Path) -> list[dict[str, Any]]:
    """Read either .evtx or XML event logs based on their file extension."""
    source = Path(path)
    return read_evtx(source) if source.suffix.lower() == ".evtx" else read_sysmon_xml(source)
