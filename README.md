Syslog
| where ProcessName contains "CEF" or SyslogMessage contains "CEF:0"
| extend _p   = split(SyslogMessage, '|')
| extend _ext = strcat_array(array_slice(_p, 7, -1), '|')
| parse-kv _ext as (rt:string, src:string, dst:string, spt:int, dpt:int, act:string, msg:string)
    with (pair_delimiter=' ', kv_delimiter='=', greedy=true)
| project
    DeviceVendor       = tostring(_p[1]),
    DeviceProduct      = tostring(_p[2]),
    DeviceVersion      = tostring(_p[3]),
    DeviceEventClassID = tostring(_p[4]),
    Activity           = tostring(_p[5]),
    LogSeverity        = tostring(_p[6]),
    ReceiptTime  = rt,
    SourceIP     = src,
    DestinationIP= dst,
    DeviceAction = act,
    Message      = msg,
    _extPreview  = substring(_ext, 0, 200)
| take 5
