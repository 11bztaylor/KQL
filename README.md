# KQL

Syslog
| where ProcessName in ("apmd", "tmm", "tmm1", "tmm2", "tmm3", "tmm4")
| extend MessageID = extract(@"(\d{8})", 1, SyslogMessage),
         Severity = extract(@":(\d):", 1, SyslogMessage),
         PolicyPath = extract(@": (\/\S+?):", 1, SyslogMessage),
         Partition = extract(@"/\S+:(\w+):", 1, SyslogMessage),
         SessionID = extract(@": ([a-f0-9]{8}):", 1, SyslogMessage),
         EventType = case(MessageID == "01490500","New Session", MessageID == "01490102", "Access Policy Result", MessageID == "01490521", "Session Statistics", MessageID == "01490005", "Username", MessageID == "01490113", "Session Variable", MessageID == "01490115", "User Agent", MessageID == "01490506", "Received Header", "Other"),
         EventDescription = extract(@": [a-f0-9]{8}: (.+)$", 1, SyslogMessage)
