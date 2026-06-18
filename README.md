// =====================================================================================
// Palo Alto Networks (PAN-OS) CEF -> per-log-type tables, parsed out of Syslog (ADX)
// =====================================================================================
//
// GOAL
//   Instead of rebuilding the unified CommonSecurityLog table, fan the raw Syslog CEF
//   stream out into VENDOR + LOG-TYPE specific tables. This file does Palo Alto:
//       PaloAlto_Traffic   <- PAN-OS TRAFFIC logs
//       PaloAlto_Threat    <- PAN-OS THREAT logs (incl. url/virus/spyware/wildfire/file subtypes)
//       PaloAlto_Audit     <- PAN-OS CONFIG logs (configuration-change audit trail)
//       PaloAlto_Other     <- catch-all for every other $type (SYSTEM, HIPMATCH, USERID,
//                             GLOBALPROTECT, AUTHENTICATION, DECRYPTION, CORRELATION, ...)
//                             so nothing is ever silently dropped.
//
// ROUTING KEY  (why we do NOT trust ProcessName)
//   Microsoft documents that since AMA v1.41 the Syslog ProcessName field may NOT contain
//   "CEF" for vendors that don't strictly follow RFC 3164/5424. So we route off the parsed
//   CEF header instead. The CEF header is positional:
//
//       CEF:0|DeviceVendor|DeviceProduct|DeviceVersion|DeviceEventClassID|Name|Severity|<ext>
//        _p[0]   _p[1]        _p[2]         _p[3]            _p[4]         _p[5]  _p[6]
//
//   Palo Alto PAN-OS emits:
//       CEF:0|Palo Alto Networks|PAN-OS|$sender_sw_version|$subtype|$type|<sev>|<ext>
//   so:
//       _p[1] == "Palo Alto Networks"   -> the real vendor routing key
//       $type   (TRAFFIC/THREAT/...)    -> the log type we split tables on
//       $subtype(start/end/url/...)     -> finer subtype, kept as a column
//
//   To be resilient to the alternate Cortex Data Lake "LF" ordering (which swaps the
//   $type/$subtype positions), PaloAlto_CEF_Parsed() picks whichever of _p[4]/_p[5] is a
//   known PAN-OS log type rather than hard-coding the position.
//
// NOTE on cs1..cs6 / cn1..cn3 / flexString labels
//   Their meaning is defined by YOUR firewall's custom syslog profile (that's why each
//   carries a *Label companion, e.g. cs1Label=Rule). The friendly mappings below
//   (cs1=Rule, cs3=Virtual System, cs4=Source Zone, cs5=Destination Zone, cs6=URL/Threat
//   category) are the common PAN-OS defaults -- adjust them to match your profile. The raw
//   labels and AdditionalExtensions are retained so nothing is lost if a profile differs.
// =====================================================================================


// -------------------------------------------------------------------------------------
// 1) Base parser: filter Syslog -> Palo Alto CEF, split the header, parse the extension.
//    Every per-type function below selects from this and projects its own subset.
// -------------------------------------------------------------------------------------
.create-or-alter function
  with (docstring = 'Palo Alto Networks PAN-OS CEF parsed out of Syslog - common projection, routed by log type', folder = 'PaloAlto')
  PaloAlto_CEF_Parsed() {
    let _knownTypes = dynamic(["TRAFFIC","THREAT","SYSTEM","CONFIG","HIPMATCH","HIP-MATCH","CORRELATION","USERID","AUTHENTICATION","AUTH","GLOBALPROTECT","DECRYPTION","GTP","SCTP","TUNNEL","URL"]);
    Syslog
    | where SyslogMessage has "CEF:"
    | extend _p = split(SyslogMessage, '|')
    | where tostring(_p[1]) == "Palo Alto Networks"
    | extend _f4 = toupper(tostring(_p[4])), _f5 = toupper(tostring(_p[5]))
    | extend LogType = iff(_f4 in (_knownTypes), _f4, _f5)
    | extend SubType = iff(_f4 in (_knownTypes), tostring(_p[5]), tostring(_p[4]))
    | extend _ext = strcat_array(array_slice(_p, 7, -1), '|')
    | parse-kv _ext as (
        ['act']:string, ['app']:string, ['cat']:string,
        ['cnt']:int, ['cn1']:int, ['cn1Label']:string, ['cn2']:int, ['cn2Label']:string, ['cn3']:int, ['cn3Label']:string,
        ['cs1']:string, ['cs1Label']:string, ['cs2']:string, ['cs2Label']:string, ['cs3']:string, ['cs3Label']:string,
        ['cs4']:string, ['cs4Label']:string, ['cs5']:string, ['cs5Label']:string, ['cs6']:string, ['cs6Label']:string,
        ['deviceDirection']:string, ['deviceExternalId']:string, ['deviceInboundInterface']:string, ['deviceOutboundInterface']:string,
        ['destinationServiceName']:string, ['destinationTranslatedAddress']:string, ['destinationTranslatedPort']:int,
        ['dhost']:string, ['dmac']:string, ['dntdom']:string, ['dpt']:int, ['dst']:string, ['duser']:string, ['dvc']:string, ['dvchost']:string, ['dvcmac']:string,
        ['end']:datetime, ['externalId']:string,
        ['fileHash']:string, ['filePath']:string, ['fname']:string,
        ['flexString1']:string, ['flexString1Label']:string, ['flexString2']:string, ['flexString2Label']:string,
        ['in']:long, ['msg']:string, ['out']:long, ['outcome']:string, ['proto']:string, ['reason']:string,
        ['request']:string, ['requestContext']:string, ['requestMethod']:string, ['rt']:string,
        ['shost']:string, ['smac']:string, ['sntdom']:string, ['sourceServiceName']:string,
        ['sourceTranslatedAddress']:string, ['sourceTranslatedPort']:int, ['spt']:int, ['src']:string, ['start']:datetime, ['suser']:string
      )
      with (pair_delimiter = ' ', kv_delimiter = '=', greedy = true)
    | extend
        DeviceVendor       = tostring(_p[1]),
        DeviceProduct      = tostring(_p[2]),
        DeviceVersion      = tostring(_p[3]),
        LogSeverity        = tostring(_p[6]),
        AdditionalExtensions = _ext
  }


// -------------------------------------------------------------------------------------
// 2) TRAFFIC  ->  PaloAlto_Traffic
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
        DeviceAddress                = ['dvc'],
        DeviceExternalId             = ['deviceExternalId'],
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
        EventCount                   = ['cnt'],
        StartTime                    = ['start'],
        EndTime                      = ['end'],
        ReceiptTime                  = ['rt'],
        Reason                       = ['reason'],
        SessionID                    = ['externalId'],
        RuleName                     = ['cs1'],          // cs1Label=Rule (default profile)
        VirtualSystem                = ['cs3'],          // cs3Label=Virtual System
        SourceZone                   = ['cs4'],          // cs4Label=Source Zone
        DestinationZone              = ['cs5'],          // cs5Label=Destination Zone
        AdditionalExtensions
  }

.create table PaloAlto_Traffic (
    TimeGenerated:datetime, DeviceVendor:string, DeviceProduct:string, DeviceVersion:string,
    LogType:string, SubType:string, LogSeverity:string, Computer:string, DeviceName:string,
    DeviceAddress:string, DeviceExternalId:string, SourceIP:string, SourcePort:int,
    DestinationIP:string, DestinationPort:int, Protocol:string, ApplicationProtocol:string,
    DeviceAction:string, SourceUserName:string, DestinationUserName:string,
    SourceTranslatedAddress:string, SourceTranslatedPort:int, DestinationTranslatedAddress:string,
    DestinationTranslatedPort:int, DeviceInboundInterface:string, DeviceOutboundInterface:string,
    ReceivedBytes:long, SentBytes:long, EventCount:int, StartTime:datetime, EndTime:datetime,
    ReceiptTime:string, Reason:string, SessionID:string, RuleName:string, VirtualSystem:string,
    SourceZone:string, DestinationZone:string, AdditionalExtensions:string
)

.alter table PaloAlto_Traffic policy update
'[{"IsEnabled":true,"Source":"Syslog","Query":"PaloAlto_Traffic_parse()","IsTransactional":false,"PropagateIngestionProperties":false}]'


// -------------------------------------------------------------------------------------
// 3) THREAT  ->  PaloAlto_Threat   (subtypes: url, virus, spyware, vulnerability, wildfire, file, data, ...)
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
        DeviceName                   = ['dvchost'],
        DeviceAddress                = ['dvc'],
        DeviceExternalId             = ['deviceExternalId'],
        SourceIP                     = ['src'],
        SourcePort                   = ['spt'],
        DestinationIP                = ['dst'],
        DestinationPort              = ['dpt'],
        Protocol                     = ['proto'],
        ApplicationProtocol          = ['app'],
        DeviceAction                 = ['act'],
        CommunicationDirection       = ['deviceDirection'],
        SourceUserName               = ['suser'],
        DestinationUserName          = ['duser'],
        SourceTranslatedAddress      = ['sourceTranslatedAddress'],
        DestinationTranslatedAddress = ['destinationTranslatedAddress'],
        ThreatCategory               = ['cat'],
        RequestURL                   = ['request'],
        RequestContext               = ['requestContext'],
        RequestMethod                = ['requestMethod'],
        FileName                     = ['fname'],
        FilePath                     = ['filePath'],
        FileHash                     = ['fileHash'],
        Message                      = ['msg'],
        SessionID                    = ['externalId'],
        RuleName                     = ['cs1'],          // cs1Label=Rule
        VirtualSystem                = ['cs3'],          // cs3Label=Virtual System
        SourceZone                   = ['cs4'],          // cs4Label=Source Zone
        DestinationZone              = ['cs5'],          // cs5Label=Destination Zone
        URLCategory                  = ['cs6'],          // cs6Label=URL Category (threat/url logs)
        FlexString1                  = ['flexString1'],
        FlexString1Label             = ['flexString1Label'],
        FlexString2                  = ['flexString2'],
        FlexString2Label             = ['flexString2Label'],
        ReceiptTime                  = ['rt'],
        AdditionalExtensions
  }

.create table PaloAlto_Threat (
    TimeGenerated:datetime, DeviceVendor:string, DeviceProduct:string, DeviceVersion:string,
    LogType:string, SubType:string, LogSeverity:string, Computer:string, DeviceName:string,
    DeviceAddress:string, DeviceExternalId:string, SourceIP:string, SourcePort:int,
    DestinationIP:string, DestinationPort:int, Protocol:string, ApplicationProtocol:string,
    DeviceAction:string, CommunicationDirection:string, SourceUserName:string, DestinationUserName:string,
    SourceTranslatedAddress:string, DestinationTranslatedAddress:string, ThreatCategory:string,
    RequestURL:string, RequestContext:string, RequestMethod:string, FileName:string, FilePath:string,
    FileHash:string, Message:string, SessionID:string, RuleName:string, VirtualSystem:string,
    SourceZone:string, DestinationZone:string, URLCategory:string, FlexString1:string,
    FlexString1Label:string, FlexString2:string, FlexString2Label:string, ReceiptTime:string,
    AdditionalExtensions:string
)

.alter table PaloAlto_Threat policy update
'[{"IsEnabled":true,"Source":"Syslog","Query":"PaloAlto_Threat_parse()","IsTransactional":false,"PropagateIngestionProperties":false}]'


// -------------------------------------------------------------------------------------
// 4) CONFIG  ->  PaloAlto_Audit   (configuration-change audit trail: who/what/result)
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
        DeviceAddress    = ['dvc'],
        DeviceExternalId = ['deviceExternalId'],
        AdminUser        = ['suser'],          // administrator who made the change
        ClientIP         = ['src'],            // host the admin connected from
        ClientHost       = ['shost'],
        Command          = ['act'],            // add / edit / delete / set / commit ...
        Result           = ['outcome'],
        VirtualSystem    = ['cs3'],            // cs3Label=Virtual System
        BeforeChange     = ['cs1'],            // cs1Label=Before Change Detail (default profile)
        AfterChange      = ['cs2'],            // cs2Label=After Change Detail
        Message          = ['msg'],
        ReceiptTime      = ['rt'],
        AdditionalExtensions
  }

.create table PaloAlto_Audit (
    TimeGenerated:datetime, DeviceVendor:string, DeviceProduct:string, DeviceVersion:string,
    LogType:string, SubType:string, LogSeverity:string, Computer:string, DeviceName:string,
    DeviceAddress:string, DeviceExternalId:string, AdminUser:string, ClientIP:string, ClientHost:string,
    Command:string, Result:string, VirtualSystem:string, BeforeChange:string, AfterChange:string,
    Message:string, ReceiptTime:string, AdditionalExtensions:string
)

.alter table PaloAlto_Audit policy update
'[{"IsEnabled":true,"Source":"Syslog","Query":"PaloAlto_Audit_parse()","IsTransactional":false,"PropagateIngestionProperties":false}]'


// -------------------------------------------------------------------------------------
// 5) CATCH-ALL  ->  PaloAlto_Other   (every $type not handled above; nothing is dropped)
//    Promote any of these (e.g. SYSTEM, HIPMATCH, GLOBALPROTECT) to a dedicated table later
//    by adding it as an exclusion here and copying the TRAFFIC pattern.
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
        DeviceAddress    = ['dvc'],
        DeviceExternalId = ['deviceExternalId'],
        SourceIP         = ['src'],
        DestinationIP    = ['dst'],
        SourceUserName   = ['suser'],
        DestinationUserName = ['duser'],
        DeviceAction     = ['act'],
        EventCategory    = ['cat'],
        Message          = ['msg'],
        Result           = ['outcome'],
        ReceiptTime      = ['rt'],
        AdditionalExtensions
  }

.create table PaloAlto_Other (
    TimeGenerated:datetime, DeviceVendor:string, DeviceProduct:string, DeviceVersion:string,
    LogType:string, SubType:string, LogSeverity:string, Computer:string, DeviceName:string,
    DeviceAddress:string, DeviceExternalId:string, SourceIP:string, DestinationIP:string,
    SourceUserName:string, DestinationUserName:string, DeviceAction:string, EventCategory:string,
    Message:string, Result:string, ReceiptTime:string, AdditionalExtensions:string
)

.alter table PaloAlto_Other policy update
'[{"IsEnabled":true,"Source":"Syslog","Query":"PaloAlto_Other_parse()","IsTransactional":false,"PropagateIngestionProperties":false}]'
