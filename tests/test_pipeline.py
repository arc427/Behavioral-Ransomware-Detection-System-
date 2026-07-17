from pipeline.event_filter import filter_sysmon_events
from pipeline.evtx_reader import parse_sysmon_xml_event
from pipeline.temporal_aggregator import aggregate_process_windows
from pipeline.vectorizer import vectorize


SAMPLE_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>11</EventID><TimeCreated SystemTime='2026-01-01T00:00:01Z'/><Computer>host-a</Computer></System><EventData><Data Name='UtcTime'>2026-01-01 00:00:01.000</Data><Data Name='ProcessGuid'>{process}</Data><Data Name='Image'>C:\\Temp\\run.exe</Data><Data Name='TargetFilename'>C:\\Temp\\note.txt</Data></EventData></Event>"""


def test_parse_filter_aggregate_and_vectorize():
    first = parse_sysmon_xml_event(SAMPLE_XML.format(process="one"))
    second = parse_sysmon_xml_event(SAMPLE_XML.replace("00:00:01", "00:00:03").format(process="one"))
    windows = aggregate_process_windows(filter_sysmon_events([first, second]), window_seconds=5)
    features, names = vectorize(windows)
    assert len(windows) == 1
    assert windows.loc[0, "event_11_count"] == 2
    assert windows.loc[0, "suspicious_path_count"] == 2
    assert features.shape == (1, len(names))
