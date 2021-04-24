# Import-LogSlothSanitized Function

This function is used to import a log file into PowerShell for manipulation or viewing and attempting to sanitize the file as part of the import process.

When a log is sanitized, certain parts of the text are replaced with a sanitization marker that are prefixed based on what the text _was_, and then a unique index for that sanitization type is applied.

For example, consider the following input:
```
DateTime,LogText
1/1/2020 8:15 PM,User 1 connected from 10.0.0.1
1/1/2021 8:16 PM,User 2 connected from 10.0.0.2
1/1/2021 8:16 PM,User 1 at 10.0.0.1 assigned GUID {00000000-0000-0000-0000-000000000001}
1/1/2021 8:17 PM,User 2 at 10.0.0.2 assigned GUID {00000000-0000-0000-0000-000000000002}
```

When sanitized, the IP and GUIDs would be replaced with markers as shown:
```
DateTime,LogText
1/1/2020 8:15 PM,User 1 connected from sanitizedip1
1/1/2021 8:16 PM,User 2 connected from sanitizedip2
1/1/2021 8:16 PM,User 1 at sanitizedip1 assigned GUID {sanitizedguid1}
1/1/2021 8:17 PM,User 2 at sanitizedip2 assigned GUID {sanitizedguid2}
```

Notice that when 10.0.0.1 and 10.0.0.2 were replaced, they kept the same marker throughout the rest of the log file so that you always knew that `sanitizedip1` was referring to the same IP throughout the log, even though you don't know what that IP address is.

All of the parameters available in [Import-LogSloth](import-logsloth.md) are also available to `Import-LogSlothSanitized`, so they will not be redefined on this page. The following additional options are available.

## Define the Sanitization Rules

LogSloth has a number of built-in rules that you can use to sanitize your log file.  If you do not define any rules, all rules will be applied.  The following rules are available:

Flag|Action|Applies To
-|-|-
All|Includes all sanitization rules|All Log Files
GUID|Sanitizes GUIDs that are in 8-4-4-4-12 Format|All Log Files
Hash64|Sanitizes 64 character hashes|All Log Files
IPv4|Sanitizes Valid IPv4 Addresses|All Log Files
SID|Sanitizes SIDs (Security Identifiers) in `S-1-` Format|All Log Files
URLHost|Sanitizes the host/domain or URLs|All Log Files
CMDistributionPoint|Sanitizes CM Distribution Points|SCCM Log Files
CMAdvertisementID|Sanitizes CM Advertisement IDs|SCCM Log Files
CMPackageID|Sanitizes CM Package IDs|SCCM Log Files
CMProgramID|Sanitizes CM Program IDs|SCCM Log Files
CMMachineName|Sanitizes CM Machine Names|SCCM Log Files
CMSiteCode|Sanitizes CM Site Codes|SCCM Log Files
CMADSite|Sanitizes CM Active Directory Site Names|SCCM Log Files
CMAll|Includes all CM Sanitization Rules|SCCM Log Files

You can pass one or more of these to the import function:

```
# Only sanitize the IPv4 Addresses and the SIDs in the log file, leave all other data as-is.
$log = Import-LogSlothSanitized -LogFile ExecMgr.log -Sanitize IPv4,SID
```

## Changing the Sanitize Prefix

By default, the prefix added to to beginning to each replacement in the log is `sanitized` (e.g. `sanitizedip1` as shown in the example further up on this page).  To replace that prefix, use the `-prefix` parameter:

```
Import-LogSlothSanitized -LogFile ExecMgr.log -Prefix "ABC"
```

## Additional Output Properties

When using `Import-LogSlothSanitized`, you get all of the same output properties as when using `Import-LogSloth`, as well as these additional properties:

Property|Purpose
-|-
SanitizedReplacements|An array of values that were replaced and what they were replaced with
SanitizeType|Which sanitization rules were supplied when the function was called, even if they were never used

