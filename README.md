// =====================================================================================
// Palo Alto Networks (PAN-OS) CEF -> per-log-type tables, parsed out of Syslog (ADX)
// =====================================================================================
//
// GOAL
//   Fan the raw Syslog CEF stream out into VENDOR + LOG-TYPE specific tables.
//   This file does Palo Alto:
//       PaloAlto_Traffic   <- PAN-OS TRAFFIC logs
//       PaloAlto_Threat    <- PAN-OS THREAT logs (incl. url/virus/spyware/wildfire/file subtypes)
//       PaloAlto_Audit     <- PAN-OS CONFIG logs (configuration-change audit trail)
//       PaloAlto_Other     <- catch-all for every other $type (SYSTEM, HIPMATCH, USERID,
//                             GLOBALPROTECT, AUTHENTICATION, DECRYPTION, CORRELATION, ...)
//
// ROUTING / FILTERING  -- validated against a real sample (2026-06):
//   The actual SyslogMessage arrives WITHOUT the "CEF:" token, e.g.:
//       0|Palo Alto Networks|PAN-OS|13.5.60-h10|drop|TRAFFIC|1|rt=Jun 15 2026 ... 
//   so we must NOT filter on "CEF:". We filter on the vendor string, then confirm it
//   after splitting on '|'. The header is positional:
//       <ver>|DeviceVendor|DeviceProduct|DeviceVersion|$subtype|$type|Severity|<ext>
//        _p[0]   _p[1]        _p[2]         _p[3]        _p[4]   _p[5]   _p[6]
//   The vendor is always _p[1] (no '|' precedes it). $type (TRAFFIC/THREAT/...) is _p[5];
//   $subtype (drop/start/url/...) is _p[4]. We split tables on _p[5].
//   (ProcessName is deliberately ignored -- AMA >=1.41 may omit "CEF" from it.)
//
// FIELD LABELS  -- this firewall's custom syslog profile maps:
//       cs1=Rule   cs2=URL Category   cs4=Source Zone   cs5=Destination Zone   cs6=LogProfile
//       cn1=SessionID   cn2=Packets   cn3=Elapsed time (s)
//       flexString1=Flags   flexNumber1=Total bytes   externalId=Sequence Number
//   These were read from a TRAFFIC sample; THREAT/CONFIG profiles should be confirmed
//   with their own samples. Raw AdditionalExtensions is always retained so nothing is lost.
//
// PARSING NOTE
//   parse-kv runs in greedy mode (values may contain spaces, e.g. rt=Jun 15 2026 ... GMT,
//   cs5=Destination Zone). Greedy mode requires EVERY key in the message to be declared,
//   otherwise an undeclared key is absorbed into the previous value. The schema below
//   therefore also declares the PAN-specific PanOS*/Pan* keys seen in the logs.
// =====================================================================================


// -------------------------------------------------------------------------------------
// 1) Base parser: Syslog -> Palo Alto CEF, split header, parse the extension.
// -------------------------------------------------------------------------------------
.create-or-alter function
  with (docstring = 'Palo Alto Networks PAN-OS CEF parsed out of Syslog - common projection, routed by log type', folder = 'PaloAlto')
  PaloAlto_CEF_Parsed() {
    Syslog
    | where SyslogMessage has "Palo Alto Networks"
    | extend _p = split(SyslogMessage, '|')
    | where tostring(_p[1]) == "Palo Alto Networks"
    | extend
        DeviceVendor  = tostring(_p[1]),
        DeviceProduct = tostring(_p[2]),
        DeviceVersion = tostring(_p[3]),
        SubType       = tostring(_p[4]),
        LogType       = toupper(tostring(_p[5])),
        LogSeverity   = tostring(_p[6])
    | extend _ext = strcat_array(array_slice(_p, 7, -1), '|')
    | parse-kv _ext as (
        // --- standard CEF keys ---
        ['act']:string, ['app']:string, ['cat']:string, ['cnt']:int,
        ['deviceDirection']:string, ['deviceExternalId']:string,
        ['deviceInboundInterface']:string, ['deviceOutboundInterface']:string,
        ['destinationServiceName']:string, ['destinationTranslatedAddress']:string, ['destinationTranslatedPort']:int,
        ['dhost']:string, ['dmac']:string, ['dntdom']:string, ['dpid']:int, ['dpt']:int, ['dproc']:string, ['dpriv']:string,
        ['dst']:string, ['dtz']:string, ['duid']:string, ['duser']:string,
        ['dvc']:string, ['dvchost']:string, ['dvcmac']:string,
        ['end']:string, ['externalId']:string,
        ['fileHash']:string, ['filePath']:string, ['fname']:string,
        ['in']:long, ['msg']:string, ['out']:long, ['outcome']:string, ['proto']:string, ['reason']:string,
        ['request']:string, ['requestContext']:string, ['requestMethod']:string, ['rt']:string,
        ['shost']:string, ['smac']:string, ['sntdom']:string, ['sourceServiceName']:string,
        ['sourceTranslatedAddress']:string, ['sourceTranslatedPort']:int,
        ['spid']:int, ['spriv']:string, ['sproc']:string, ['spt']:int, ['src']:string, ['start']:string, ['suid']:string, ['suser']:string,
        // --- custom string/number/flex fields (+ their profile labels) ---
        ['cs1']:string, ['cs1Label']:string, ['cs2']:string, ['cs2Label']:string, ['cs3']:string, ['cs3Label']:string,
        ['cs4']:string, ['cs4Label']:string, ['cs5']:string, ['cs5Label']:string, ['cs6']:string, ['cs6Label']:string,
        ['cn1']:int, ['cn1Label']:string, ['cn2']:int, ['cn2Label']:string, ['cn3']:int, ['cn3Label']:string,
        ['flexString1']:string, ['flexString1Label']:string, ['flexString2']:string, ['flexString2Label']:string,
        ['flexNumber1']:long, ['flexNumber1Label']:string, ['flexNumber2']:long, ['flexNumber2Label']:string,
        // --- PAN-OS specific keys (declared so greedy parse-kv keeps correct boundaries) ---
        ['PanOSPacketsReceived']:long, ['PanOSPacketsSent']:long,
        ['PanOSSCTPAssocID']:long, ['PanOSSCTPChunks']:long, ['PanOSSCTPChunkSent']:long, ['PanOSSCTPChunksRcv']:long,
        ['PanOSRuleUUID']:string, ['PanOSHTTP2Con']:int, ['PanLinkChange']:int,
        ['PanPolicyID']:string, ['PanLinkDetail']:string,
        ['PanSDWANCluster']:string, ['PanSDWANDevice']:string, ['PanSDWANClustype']:string, ['PanSDWANSite']:string,
        ['PanSrcEDL']:string, ['PanDstEDL']:string, ['PanGPHostID']:string,
        ['PanSrcDAG']:string, ['PanDstDAG']:string, ['PanHASessionOwner']:string
      )
      with (pair_delimiter = ' ', kv_delimiter = '=', greedy = true)
    | extend AdditionalExtensions = _ext
  }


// -------------------------------------------------------------------------------------
// 2) TRAFFIC  ->  PaloAlto_Traffic        (validated against a real TRAFFIC sample)
// -------------------------------------------------------------------------------------
.create-or-alter function
  with (docstring = 'PAN-OS TRAFFIC logs projected for the PaloAlto_Traffic table', folder = 'PaloAlto')
  PaloAlto_Traffic_parse() {
    PaloAlto_CEF_Parsed()
    | where LogType == "TRAFFIC"
    | project
        TimeGenerated,
        DeviceVendor,
        DeviceProduct,
        DeviceVersion,
        LogType,
        SubType,
        LogSeverity,
        Computer,
        DeviceName                   = ['dvchost'],
        FirewallSerial               = ['deviceExternalId'],
        SourceIP                     = ['src'],
        SourcePort                   = ['spt'],
        DestinationIP                = ['dst'],
        DestinationPort              = ['dpt'],
        Protocol                     = ['proto'],
        ApplicationProtocol          = ['app'],
        DeviceAction                 = ['act'],
        SourceUserName               = ['suser'],
        DestinationUserName          = ['duser'],
        SourceTranslatedAddress      = ['sourceTranslatedAddress'],
        SourceTranslatedPort         = ['sourceTranslatedPort'],
        DestinationTranslatedAddress = ['destinationTranslatedAddress'],
        DestinationTranslatedPort    = ['destinationTranslatedPort'],
        DeviceInboundInterface       = ['deviceInboundInterface'],
        DeviceOutboundInterface      = ['deviceOutboundInterface'],
        ReceivedBytes                = ['in'],
        SentBytes                    = ['out'],
        TotalBytes                   = ['flexNumber1'],   // flexNumber1Label=Total bytes
        PacketCount                  = ['cn2'],           // cn2Label=Packets
        EventCount                   = ['cnt'],
        ElapsedTimeSec               = ['cn3'],           // cn3Label=Elapsed time in seconds
        SessionID                    = ['cn1'],           // cn1Label=SessionID
        SequenceNumber               = ['externalId'],
        RuleName                     = ['cs1'],           // cs1Label=Rule
        URLCategory                  = ['cs2'],           // cs2Label=URL Category
        SourceZone                   = ['cs4'],           // cs4Label=Source Zone
        DestinationZone              = ['cs5'],           // cs5Label=Destination Zone
        LogProfile                   = ['cs6'],           // cs6Label=LogProfile
        Flags                        = ['flexString1'],   // flexString1Label=Flags
        RuleUUID                     = ['PanOSRuleUUID'],
        Reason                       = ['reason'],
        Category                     = ['cat'],
        StartTime                    = ['start'],         // raw PAN format "Mon dd yyyy HH:mm:ss GMT"
        ReceiptTime                  = ['rt'],            // raw PAN format
        AdditionalExtensions
  }

.create table PaloAlto_Traffic (
    TimeGenerated:datetime, DeviceVendor:string, DeviceProduct:string, DeviceVersion:string,
    LogType:string, SubType:string, LogSeverity:string, Computer:string, DeviceName:string,
    FirewallSerial:string, SourceIP:string, SourcePort:int, DestinationIP:string, DestinationPort:int,
    Protocol:string, ApplicationProtocol:string, DeviceAction:string, SourceUserName:string,
    DestinationUserName:string, SourceTranslatedAddress:string, SourceTranslatedPort:int,
    DestinationTranslatedAddress:string, DestinationTranslatedPort:int, DeviceInboundInterface:string,
    DeviceOutboundInterface:string, ReceivedBytes:long, SentBytes:long, TotalBytes:long, PacketCount:int,
    EventCount:int, ElapsedTimeSec:int, SessionID:int, SequenceNumber:string, RuleName:string,
    URLCategory:string, SourceZone:string, DestinationZone:string, LogProfile:string, Flags:string,
    RuleUUID:string, Reason:string, Category:string, StartTime:string, ReceiptTime:string,
    AdditionalExtensions:string
)

.alter table PaloAlto_Traffic policy update
'[{"IsEnabled":true,"Source":"Syslog","Query":"PaloAlto_Traffic_parse()","IsTransactional":false,"PropagateIngestionProperties":false}]'


// -------------------------------------------------------------------------------------
// 3) THREAT  ->  PaloAlto_Threat   (subtypes: url, virus, spyware, vulnerability, wildfire, file, data, ...)
//    NOTE: mappings reuse the TRAFFIC profile labels. Confirm with a real THREAT sample;
//          declare any extra PanOS* keys it carries in PaloAlto_CEF_Parsed() above.
// -------------------------------------------------------------------------------------
.create-or-alter function
  with (docstring = 'PAN-OS THREAT logs projected for the PaloAlto_Threat table', folder = 'PaloAlto')
  PaloAlto_Threat_parse() {
    PaloAlto_CEF_Parsed()
    | where LogType == "THREAT"
    | project
        TimeGenerated,
        DeviceVendor,
        DeviceProduct,
        DeviceVersion,
        LogType,
        SubType,
        LogSeverity,
        Computer,
        DeviceName             = ['dvchost'],
        FirewallSerial         = ['deviceExternalId'],
        SourceIP               = ['src'],
        SourcePort             = ['spt'],
        DestinationIP          = ['dst'],
        DestinationPort        = ['dpt'],
        Protocol               = ['proto'],
        ApplicationProtocol    = ['app'],
        DeviceAction           = ['act'],
        CommunicationDirection = ['deviceDirection'],
        SourceUserName         = ['suser'],
        DestinationUserName    = ['duser'],
        RequestURL             = ['request'],
        RequestContext         = ['requestContext'],
        RequestMethod          = ['requestMethod'],
        FileName               = ['fname'],
        FilePath               = ['filePath'],
        FileHash               = ['fileHash'],
        ThreatCategory         = ['cat'],
        Message                = ['msg'],
        SessionID              = ['cn1'],           // cn1Label=SessionID
        SequenceNumber         = ['externalId'],
        RuleName               = ['cs1'],           // cs1Label=Rule
        URLCategory            = ['cs2'],           // cs2Label=URL Category
        SourceZone             = ['cs4'],           // cs4Label=Source Zone
        DestinationZone        = ['cs5'],           // cs5Label=Destination Zone
        LogProfile             = ['cs6'],           // cs6Label=LogProfile
        Flags                  = ['flexString1'],   // flexString1Label=Flags
        RuleUUID               = ['PanOSRuleUUID'],
        ReceiptTime            = ['rt'],
        AdditionalExtensions
  }

.create table PaloAlto_Threat (
    TimeGenerated:datetime, DeviceVendor:string, DeviceProduct:string, DeviceVersion:string,
    LogType:string, SubType:string, LogSeverity:string, Computer:string, DeviceName:string,
    FirewallSerial:string, SourceIP:string, SourcePort:int, DestinationIP:string, DestinationPort:int,
    Protocol:string, ApplicationProtocol:string, DeviceAction:string, CommunicationDirection:string,
    SourceUserName:string, DestinationUserName:string, RequestURL:string, RequestContext:string,
    RequestMethod:string, FileName:string, FilePath:string, FileHash:string, ThreatCategory:string,
    Message:string, SessionID:int, SequenceNumber:string, RuleName:string, URLCategory:string,
    SourceZone:string, DestinationZone:string, LogProfile:string, Flags:string, RuleUUID:string,
    ReceiptTime:string, AdditionalExtensions:string
)

.alter table PaloAlto_Threat policy update
'[{"IsEnabled":true,"Source":"Syslog","Query":"PaloAlto_Threat_parse()","IsTransactional":false,"PropagateIngestionProperties":false}]'


// -------------------------------------------------------------------------------------
// 4) CONFIG  ->  PaloAlto_Audit   (configuration-change audit: who / what / result)
//    NOTE: CONFIG logs use a different field set; cs* labels likely differ from TRAFFIC.
//          Core fields are mapped here; everything else stays in AdditionalExtensions
//          until a real CONFIG sample is available to finalize the projection.
// -------------------------------------------------------------------------------------
.create-or-alter function
  with (docstring = 'PAN-OS CONFIG (configuration-change audit) logs projected for the PaloAlto_Audit table', folder = 'PaloAlto')
  PaloAlto_Audit_parse() {
    PaloAlto_CEF_Parsed()
    | where LogType == "CONFIG"
    | project
        TimeGenerated,
        DeviceVendor,
        DeviceProduct,
        DeviceVersion,
        LogType,
        SubType,
        LogSeverity,
        Computer,
        DeviceName       = ['dvchost'],
        FirewallSerial   = ['deviceExternalId'],
        AdminUser        = ['suser'],     // administrator who made the change
        ClientIP         = ['src'],       // host the admin connected from
        ClientHost       = ['shost'],
        Command          = ['act'],       // add / edit / delete / set / commit ...
        Result           = ['outcome'],
        Message          = ['msg'],
        SequenceNumber   = ['externalId'],
        ReceiptTime      = ['rt'],
        AdditionalExtensions
  }

.create table PaloAlto_Audit (
    TimeGenerated:datetime, DeviceVendor:string, DeviceProduct:string, DeviceVersion:string,
    LogType:string, SubType:string, LogSeverity:string, Computer:string, DeviceName:string,
    FirewallSerial:string, AdminUser:string, ClientIP:string, ClientHost:string, Command:string,
    Result:string, Message:string, SequenceNumber:string, ReceiptTime:string, AdditionalExtensions:string
)

.alter table PaloAlto_Audit policy update
'[{"IsEnabled":true,"Source":"Syslog","Query":"PaloAlto_Audit_parse()","IsTransactional":false,"PropagateIngestionProperties":false}]'


// -------------------------------------------------------------------------------------
// 5) CATCH-ALL  ->  PaloAlto_Other   (every $type not handled above; nothing is dropped)
//    Promote any of these (SYSTEM, HIPMATCH, GLOBALPROTECT, ...) to a dedicated table by
//    excluding it here and copying the TRAFFIC pattern.
// -------------------------------------------------------------------------------------
.create-or-alter function
  with (docstring = 'PAN-OS logs of any type not routed to a dedicated table (SYSTEM, HIPMATCH, USERID, GLOBALPROTECT, ...)', folder = 'PaloAlto')
  PaloAlto_Other_parse() {
    PaloAlto_CEF_Parsed()
    | where LogType !in ("TRAFFIC", "THREAT", "CONFIG")
    | project
        TimeGenerated,
        DeviceVendor,
        DeviceProduct,
        DeviceVersion,
        LogType,
        SubType,
        LogSeverity,
        Computer,
        DeviceName       = ['dvchost'],
        FirewallSerial   = ['deviceExternalId'],
        SourceIP         = ['src'],
        DestinationIP    = ['dst'],
        SourceUserName   = ['suser'],
        DestinationUserName = ['duser'],
        DeviceAction     = ['act'],
        EventCategory    = ['cat'],
        Message          = ['msg'],
        Result           = ['outcome'],
        SequenceNumber   = ['externalId'],
        ReceiptTime      = ['rt'],
        AdditionalExtensions
  }

.create table PaloAlto_Other (
    TimeGenerated:datetime, DeviceVendor:string, DeviceProduct:string, DeviceVersion:string,
    LogType:string, SubType:string, LogSeverity:string, Computer:string, DeviceName:string,
    FirewallSerial:string, SourceIP:string, DestinationIP:string, SourceUserName:string,
    DestinationUserName:string, DeviceAction:string, EventCategory:string, Message:string,
    Result:string, SequenceNumber:string, ReceiptTime:string, AdditionalExtensions:string
)

.alter table PaloAlto_Other policy update
'[{"IsEnabled":true,"Source":"Syslog","Query":"PaloAlto_Other_parse()","IsTransactional":false,"PropagateIngestionProperties":false}]'
