# LogSlothParser

LogSloth Parser aims to import a variety of log files (e.g. SCCM, CSV, Text Based, etc.) and convert them into a normalized PowerShell Object for easy referencing.  Additionally, it will work to sanitize log inputs so that the logs can be safely shared online.

Eventually, this module will replace the code currently running the [LogSloth Website](https://www.logsloth.com/).

# Public Functions

All of the below functions will also accept the `-SkipWarning` parameter that displays a warning message on calls to the public functions noting that this module is currently in beta.

## Import-LogSloth

Used to import a log file and convert it into a custom `[LogSloth]` class (see lower section for more information).

Sample Use:
```
> Import-LogSloth -LogFile c:\windows\ccm\logs\execmgr.log
> Import-LogSloth -LogData (Get-Content c:\windows\ccm\logs\execmgr.log -Raw)
> Get-Content c:\windows\ccm\logs\execmgr.log | Import-LogSloth
```

## Import-LogSlothSanitized

Used to import a log file and then sanitize the data to remove certain information that should not be shared in a public setting

Sample Use:
```
> Import-LogSlothSanitized -LogFile c:\windows\ccm\logs\execmgr.log -Sanitize All -Prefix "XXX"
> Import-LogSlothSanitized -LogData (Get-Content c:\windows\ccm\logs\execmgr.log -Raw) -Sanitize IPv4,SID,URLHost,CMSiteCode
> $log = Import-LogSloth -LogFile c:\windows\ccm\logs\execmgr.log | Import-LogSlothSanitized -Sanitize SID,GUID
> Get-Content c:\windows\ccm\logs\execmgr.log | Import-LogSlothSanitized
```

Values for `Sanitized` Parameter include one or more of the following:

Flag|Action|Applies To
-|-|-
All|Includes all sanitization rules|All Log Files
GUID|Sanitizes GUIDs that are in 8-4-4-4-12 Format|All Log Files
Hash64|Sanitizes 64 character hashes|All Log Files
IPv4|Sanitizes Valid IPv4 Addresses|All Log Files
SID|Sanitizes SIDs (Security Identifiers) in `S-1-` Format|All Log Files
URLHost|Sanitizes the host/domain or URLs|All Log Files
CMDistributionPoint|Sanitizes CM Distribution Points|SCCM & SCCM2007 Log Files
CMAdvertisementID|Sanitizes CM Advertisement IDs|SCCM & SCCM2007 Log Files
CMPackageID|Sanitizes CM Package IDs|SCCM & SCCM2007 Log Files
CMProgramID|Sanitizes CM Program IDs|SCCM & SCCM2007 Log Files
CMMachineName|Sanitizes CM Machine Names|SCCM & SCCM2007 Log Files
CMSiteCode|Sanitizes CM Site Codes|SCCM & SCCM2007 Log Files
CMADSite|Sanitizes CM Active Directory Site Names|SCCM & SCCM2007 Log Files
CMAll|Includes all CM Sanitization Rules|SCCM & SCCM2007 Log Files

Notes:
- When a prefix is not defined, the default prefix 'sanitized' will be used
- When no sanitization options are selected, the default 'All' will be used

## Get-LogSlothType

This function attempts to identify the format of a log file given the contents or the file name

Sample Use:
```
> Get-LogSlothType -LogFile c:\windows\ccm\logs\execmgr.log
> Get-LogSlothType -LogData (Get-Content c:\windows\ccm\logs\execmgr.log -Raw)
```

# LogSloth Class

The public import functions of this module use the `[LogSloth]` class, which can be made available by adding `using module LogSlothParser` to the top of your calling script.  The class contains the following:

Attribute|Property Type|Definition
-|-|-
LogType|Enum|The type of log that was detected (see `LogType` in the Enums section below)
SanitizeType|Enum|One or more sanitization rules used
SanitizedReplacements|ArrayList|Text replaced and what it was replaced with
LogData|ArrayList|The content of the log imported

# LogSloth Enums

The following public enums are used by this module and can be used by the calling script by adding `using module LogSlothParser` to the top of your calling script.

## LogType

Contains the values SCCM, SCCM2007, CSV, TSV, ColonSV, and NOTHING.  Used to denote the type of log a file is that has been imported.

## SanitizeType (Flags)

Contains all of the potential sanitization rules.  See the values in the `Import-LogSlothSanitized` table above.
