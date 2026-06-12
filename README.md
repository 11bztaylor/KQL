# KQL

Syslog
| where ProcessName == "apmd"
| extend MessageID = extract(@"(\d{8})", 1, RawMessage),
         Severity = extract(@":(\d):", 1, RawMessage),
         PolicyPath = extract(@": (\/\S+):", 1, RawMessage),
         SessionID = extract(@": ([a-f0-9]{8}):", 1, RawMessage),
         EventDescription = extract(@": [a-f0-9]{8}: (.+)$", 1, RawMessage)
