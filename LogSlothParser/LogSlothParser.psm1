Enum LogType {
    CSV
    TSV
    SCCM
    SCCMSimple
    MECM
    W3CExtended
    Nothing
}

[Flags()]
Enum SanitizeType {
    None = 0
    
    guid = 1
    hash64 = 2
    ipv4 = 4
    sid = 8
    urlHost = 16
    
    cmDistributionPoint = 32
    cmAdvertisementId = 64
    cmPackageId = 128
    cmProgramId = 256
    cmMachineName = 512
    cmSiteCode = 1024
    cmADSite = 2048
    cmServerName = 4096
    cmDatabaseName = 8192
    cmAll = 16352

    all = 2147483647
}

Class LogSloth {
    [LogType]$LogType = [LogType]::Nothing
    [SanitizeType]$SanitizeType = [SanitizeType]::None
    [System.Collections.ArrayList]$SanitizedReplacements = @()
    [System.Collections.ArrayList]$LogData = @()
    [String]$LogDataUnsanitized = $null
    [String]$LogDataRaw = $null
    
    [Boolean] IsSanitized() {
        Return $($this.SanitizeType -ne [SanitizeType]::None)
    }
}

Function SanitizeByMatch {
    Param(
        [string]$inputData,
        [string]$rx,
        [string]$stub,
        [switch]$quoted = $false
    )

    Write-Verbose "Private SanitizeByMatch Function is beginning"

    Write-Verbose "Initalizing RegEx and building Replacement ArrayList"
    $rxLookup = [regex]::new($rx)

    Write-Verbose "Getting Matches for Input Data"
    $matchList = $rxLookup.matches($inputData)
    
    Write-Verbose "Reducing to Unique List of Matches"
    $uniqueMatchList = New-Object -TypeName System.Collections.Generic.HashSet[String]
    [void]$matchList.ForEach{ $uniqueMatchList.Add($_.Groups[1].Value) }

    Write-Verbose "Completed Getting Matches for Input Data"

    $replList = [System.Collections.ArrayList]::New()

    Write-Verbose "Looping Over Unique Replacement Array to gather list of Text Strings to Replace"
    $index = 0

    ForEach($m in $uniqueMatchList | Where-Object { $_ -ne "" }) {
        $index++
        $replText = "$stub$index"
        if($quoted) { $replText = "`"$replText`""}
        Write-Verbose "... Adding '$m' => '$replText' using stub '$stub'"
        $replList.Add(
            [PSCustomObject]@{
                "OriginalText" = $m
                "ReplacementText" = $replText
                "Stub" = $stub
            }
        ) | Out-Null
    }    

    Write-Verbose "Private SanitizeByMatch Function is done"

    Return $replList
}
Function Get-LogSlothType {
    
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName = "LogData")]
        [String]$LogData,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName = "LogFile")]
        [System.IO.FileInfo]$LogFile,
        [switch]$SkipWarning
    )

    Write-Verbose "Get-LogSlothType Function is beginning"
    If(-Not($skipWarning)) { Write-Warning "LogSlothParser is Currently in Beta and may not function at 100% (Get-LogSlothType)" }

    If($logFile) {
        Try {
            Write-Verbose "LogFile Parameter Defined, Importing $logFile"
            $logData = Get-Content $logFile -Raw -ErrorAction Stop
        } Catch {
            Throw "Error reading $logFile $($_.Exception.Message)"
        }
    }

    Write-Verbose "Initalizing RegEx Checks"

    $rxSCCM = [regex]::new('<!\[LOG')
    $rxSCCMSimple = [regex]::new('(?msi).*? \$\$<.*?><.*?>')
    $rxW3CExtended = [regex]::new('(?msi)^#Software.*?^#Fields: ')

    $firstLineOfData = $($logData -split "`n") | Where-Object { $_ -notlike "ROLLOVER*" } | Select-Object -First 1

    Write-Verbose "Using RegEx to Determine Log Type"
    Switch ($logData) {
        # SCCM
        { $rxSCCM.IsMatch($firstLineOfData)  } { 
            Write-Verbose "RegEx Confirmation that Log is SCCM.  Returning."
            Return [LogType]::SCCM; break 
        }

        # SCCM Simple
        { $rxSCCMSimple.IsMatch($firstLineOfData) } {
            Write-Verbose "RegEx Confirmation that Log is SCCM Simple.  Returning."
            Return [LogType]::SCCMSimple; break
        }
        
        # W3C Extended
        { $rxW3CExtended.IsMatch($logData) } { 
            Write-Verbose "RegEx Confirmation that Log is W3CExtended.  Returning."
            Return [LogType]::W3CExtended; break 
        }

    }

    # Not a pre-defined type, let's make some best guesses
    Try {
        Write-Verbose "Converting Log Data to CSV"
        $csv = $logData | ConvertFrom-csv   
        Write-Verbose "Conversion to CSV was successful"
    } Catch {
        Write-Verbose "Failed to Convert Log  to CSV $($_.Exception.Message)"
        $csv = $null
    }

    Try {
        Write-Verbose "Converting Log Data to TSV"
        $tsv = $logData | ConvertFrom-Csv -Delimiter "`t"   
        Write-Verbose "Conversion to TSV was successful"
    } Catch {
        Write-Verbose "Failed to Convert Log to TSV $($_.Exception.Message)"
        $tsv = $null
    }

    if($csv -and $tsv) {
        $csvItems = $csv[0].PSObject.Members.Where{$_.MemberType -eq "NoteProperty"}.Count
        $tsvItems = $tsv[0].PSObject.Members.Where{$_.MemberType -eq "NoteProperty"}.Count
        if($csvItems -gt 1 -and $csvItems -ge $tsvItems) {
            Write-Verbose "There are equal or more properties in the CSV than TSV, selecting CSV as Winner"
            Return [LogType]::CSV
        } elseif($tsvItems -gt 1) {
            Write-Verbose "There are more properties in the TSV than CSV, selecting TSV as Winner"
            Return [LogType]::TSV
        } else {
            Write-Verbose "There is no clear winner between CSV and TSV, cannot select Winner"
        }
    }

    Write-Verbose "Could not find a match, Returning 'Nothing'"
    Return [LogType]::Nothing
}
Function Import-LogSloth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName = "LogData")]
        [String]$LogData,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName = "LogFile")]
        [System.IO.FileInfo]$LogFile,
        [Array]$Headers = @(),
        [switch]$SkipWarning
    )

    Write-Verbose "Import-LogSloth Function is beginning"
    If(-Not($skipWarning)) { Write-Warning "LogSlothParser is Currently in Beta and may not function at 100% (Import-LogSloth)" }

    If($logFile) {
        Try {
            Write-Verbose "LogFile Parameter Defined, Importing $logFile"
            $logData = Get-Content $logFile -Raw -ErrorAction Stop
        } Catch {
            Throw "Error reading $logFile. $($_.Exception.Message)"
        }
    }

    $log = [LogSloth]::New()

    $logData = $logData.Trim()
    
    $log.LogDataRaw = $LogData

    Write-Verbose "Getting Log Type using Get-LogSlothType Function"
    $log.logType = Get-LogSlothType -LogData $logData -skipWarning
    Write-Verbose "Detected log type is $($log.logType)"

    if($log.logType -eq [LogType]::Nothing) {
        Throw "Cannot determine type of log to import"
    }

    $oLog = [System.Collections.ArrayList]::New(@())
    Switch ($log.logType) {
        "SCCM" { 
            Write-Verbose "Importing SCCM Log using Import-LogSCCM Private Function"
            [System.Collections.ArrayList]$oLog = Import-LogSCCM -logData $logData 
        }
        "SCCMSimple" {
            Write-Verbose "Importing SCCM Simple Log using Import-LogSCCMSimple Private Function"
            [System.Collections.ArrayList]$oLog = Import-LogSCCMSimple -logData $logData 
        }
        "W3CExtended" {
            Write-Verbose "Importing W3C Extended Log using Import-LogW3CExtended Private Function"
            [System.Collections.ArrayList]$oLog = Import-LogW3CExtended -logData $logData
        }
        "CSV" {
            Write-Verbose "Importing CSV using Built-in PowerShell Function"
            $ConvertParams = @{
                InputObject = $logData
                Delimiter = ","
            }
            if($headers) { $ConvertParams.Add("Header",$headers) }
            [System.Collections.ArrayList]$oLog = ConvertFrom-Csv @ConvertParams
        }
        "TSV" {
            Write-Verbose "Importing TSV using Built-in PowerShell Function"
            $ConvertParams = @{
                InputObject = $logData
                Delimiter = "`t"
            }
            if($headers) { $ConvertParams.Add("Header",$headers) }
            [System.Collections.ArrayList]$oLog = ConvertFrom-Csv @ConvertParams
        }
        default {
            Throw "No action defined for this log type."
        }
    }

    $log.logData = $oLog

    Write-Verbose "Function is complete, Returning."
    Return $log
}

Function Import-LogSlothSanitized {
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName = "LogClass")]
        [LogSloth]$LogObject,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName = "LogData")]
        [String]$LogData,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName = "LogFile")]
        [System.IO.FileInfo]$LogFile,
        [Parameter(Mandatory=$false, ParameterSetName = "LogClass")]
        [Parameter(Mandatory=$false, ParameterSetName = "LogData")]
        [Parameter(Mandatory=$false, ParameterSetName = "LogFile")]      
        [SanitizeType]$Sanitize = [SanitizeType]::All,
        [Parameter(Mandatory=$false, ParameterSetName = "LogClass")]
        [Parameter(Mandatory=$false, ParameterSetName = "LogData")]
        [Parameter(Mandatory=$false, ParameterSetName = "LogFile")]      
        [ValidateScript({
            if($_ -match "(?i)^[a-z]+$") { $true } else { throw "You must use only letters A-Z." }
        })]
        [string]$Prefix = "sanitized",
        [Array]$Headers = @(),
        [switch]$SkipWarning
    )

    Write-Verbose "Import-LogSlothSanitized Function is beginning"

    If(-Not($skipWarning)) { Write-Warning "LogSlothParser is Currently in Beta and may not function at 100% (Import-LogSlothSanitized)" }

    If($logFile) {
        Try {
            Write-Verbose "LogFile Parameter Defined, Importing $logFile"
            $logData = Get-Content $logFile -Raw -ErrorAction Stop
        } Catch {
            Throw "Error reading $logFile $($_.Exception.Message)"
        }
    } elseif ($LogObject) {
        Write-Verbose "LogClass Passed, Capturing Raw Data"
        $logData = $LogObject.LogDataRaw
    }

    Write-Verbose "Getting Log Type"
    $logType = Get-LogSlothType -LogData $LogData -SkipWarning

    If($LogType -eq [LogType]::Nothing) { 
        Throw "Missing LogType"
    }

    $LogDataUnsanitized = $LogData

    $replacementList = [System.Collections.ArrayList]::New()
    
    # Build Replacements Table
    
    Write-Verbose "Building Replacements Table for Input Data to Sanitize"
    # -- Configuration Manager Specific --
    If($logType -eq [LogType]::SCCM -or $logType -eq [LogType]::SCCMSimple) {
        Write-Verbose "... Processing Configuration Manager (CM) Sanitization"
        Switch($sanitize) {
            { $_ -band [SanitizeType]::cmDistributionPoint } {
                # Download URLs
                Write-Verbose "...... Processing CM Distribution Points (Download URLs)"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)Matching DP location found [0-9]{1,} - (http(?:|s):\/\/.*?) "; Stub="$($prefix)dpurl"; Quoted=$false}) | Out-Null
                
                # CMG URL
                Write-Verbose "...... Processing CM Distribution Points (CMG URLs)"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)https:\/\/([^. ]+).cloudapp\.net"; Stub="$($prefix)cmghost"; Quoted=$false}) | Out-Null
            }
            { $_ -band [SanitizeType]::cmAdvertisementId } {
                #Advertisement ID by "ADV:#"
                Write-Verbose "...... Processing CM Advertisement IDs"
                $replacementList.Add([PSCustomObject]@{RegEx="Ad(?:vert|):(?: |)([A-Z]{1,3}[0-9A-F]{5,}\b)"; Stub="$($prefix)adv"; Quoted=$false}) | Out-Null
            }
            { $_-band [SanitizeType]::cmPackageId} {
                #Package IDs by "Package:#"
                Write-Verbose "...... Processing CM Package IDs"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)Package:(?: |)([A-Z]{1,3}[0-9A-F]{5,}\b)"; Stub="$($prefix)pkgid"; Quoted=$false}) | Out-Null
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)Download started for content ([A-Z]{1,3}[0-9]{5,})"; Stub="$($prefix)pkgiddl"; Quoted=$false}) | Out-Null
            }
            { $_ -band [SanitizeType]::cmProgramId } {
                # Program Names by "Program:'xxx'>"
                Write-Verbose "...... Processing CM Program IDs"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)Program:(?: |)(.*?)(?:[\b|\]|,]| \w+ with exit code)"; Stub="$($prefix)prgm"; Quoted=$false}) | Out-Null
            }
            { $_ -band [SanitizeType]::cmMachineName } {
                # Computer Names by "Machine Name = 'xxx'"
                Write-Verbose "...... Processing CM Machine Name"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)MachineName = `"(.*?)`""; Stub="$($prefix)hostname"; Quoted=$false}) | Out-Null
            }
            { $_ -band [SanitizeType]::cmSiteCode} {
                # Site Code in Quotes
                Write-Verbose "...... Processing CM Site Codes"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)SiteCode(?: |)=(?: |)`"([A-Z0-9]{1,3})`""; Stub="$($prefix)sitecodeA"; Quoted=$false}) | Out-Null
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)Site Code -> ([A-Z0-9]{1,3})"; Stub="$($prefix)sitecodeB"; Quoted=$false}) | Out-Null
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)(?:^| )SITE=(.*?)(?:,|\]| )"; Stub="$($prefix)cmsrvC"; Quoted=$false}) | Out-Null
            }
            { $_ -band [SanitizeType]::cmADSite} {
                # AD Site Name
                Write-Verbose "...... Processing CM AD Sites"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)<ADSite(?:.*?)Name=`"(.*?)`"\/>"; Stub="$($prefix)adsite"; Quoted=$false}) | Out-Null
            }
            { $_ -band [SanitizeType]::cmServerName} {
                # CM SQL Server Name
                Write-Verbose "...... Processing CM Server Names"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)sqlServerName(?: |)=(?: |)(.*?)(?:,| |\])"; Stub="$($prefix)cmsrvA"; Quoted=$false}) | Out-Null
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)Server Name: (.*?)(?:,|\]| )"; Stub="$($prefix)cmsrvB"; Quoted=$false}) | Out-Null
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)Setting Site Server -> (.*?)(?:,|\]| )"; Stub="$($prefix)cmsrvC"; Quoted=$false}) | Out-Null
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)(?:^| )SYS=(.*?)(?:,|\]| )"; Stub="$($prefix)cmsrvD"; Quoted=$false}) | Out-Null
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)(?:^| )Server: (.*?)(?:,|\]| )"; Stub="$($prefix)cmsrvE"; Quoted=$false}) | Out-Null
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)(?:^| )MP: (.*?)(?:,|\]| )"; Stub="$($prefix)cmsrvF"; Quoted=$false}) | Out-Null
            }
            { $_ -band [SanitizeType]::cmDatabaseName} {
                # CM Database Name
                Write-Verbose "...... Processing CM Database Names"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)databaseName(?: |)=(?: |)(.*?)(?:,| |\]|\.)"; Stub="$($prefix)cmdb"; Quoted=$false}) | Out-Null
            }
        } # // End of Switch
    } # // End of Log Type SCCM

    # -- Generic Replacements --
    Write-Verbose "... Processing Generic Sanitization"
    Switch($Sanitize) {
        { $_ -band [SanitizeType]::urlHost } {
            # URL Host
            Write-Verbose "...... Processing URL Hosts"
            $replacementList.Add([PSCustomObject]@{RegEx="(?msi)http(?:|s):\/\/(.*?)\/"; Stub="$($prefix)urlhost"; Quoted=$false}) | Out-Null
        }
        { $_ -band [SanitizeType]::guid } {
            # GUIDs in 8-4-4-4-12 Format
            Write-Verbose "...... Processing GUIDs"
            $replacementList.Add([PSCustomObject]@{RegEx="(?msi)([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})"; Stub="$($prefix)guid"; Quoted=$false}) | Out-Null
        }
        { $_ -band [SanitizeType]::hash64 } {
            # Hashes (64 Character Long Hex)
            Write-Verbose "...... Processing 64 Character Hashes"
            $replacementList.Add([PSCustomObject]@{RegEx="(?msi)([A-Z0-9]{64})"; Stub="$($prefix)hash"; Quoted=$false}) | Out-Null
        }
        { $_ -band [SanitizeType]::ipv4 } {
            # IP Addresses
            Write-Verbose "...... Processing IPv4 Addresses"
            $replacementList.Add([PSCustomObject]@{RegEx="(?msi)((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"; Stub="$($prefix)ip"; Quoted=$false}) | Out-Null
        }
        { $_ -band [SanitizeType]::sid } {
            # SID Format
            Write-Verbose "...... Processing SIDs"
            $replacementList.Add([PSCustomObject]@{RegEx="(?msi)(S-1-[0-9]{1,2}-\d{1,2}-(\d{8,10}-){3}\d{8,10})"; Stub="$($prefix)sid"; Quoted=$false}) | Out-Null
        }
    } # // End of Switch (Generic)

    Write-Verbose "Building List of Data to Sanitize"
    
    $replacementArray = [System.Collections.ArrayList]::New()
    
    ForEach($rule in $replacementList) {
        $uniqueStringMatches = [System.Collections.Generic.HashSet[string]]::New([StringComparer]::InvariantCultureIgnoreCase)
        $rxMatches = [regex]::Matches($LogData, $rule.regex)
        ForEach($m in $rxMatches) {
            $uniqueStringMatches.Add($m.groups[1].value) | Out-Null
        }
        
        $index = 0
        ForEach($find in $uniqueStringMatches) {
            $index++
            $replace = "$($rule.Stub)$index"
            if($rule.Quoted) { 
                $replace = "`"$replace`""
            }
            $replacementArray.Add(
                [PSCustomObject]@{
                    Text = $find
                    Replace = $replace
                }
            ) | Out-Null
        }
    }

    Write-Verbose "Starting Sanitization of Data based on Replacement ArrayList"
    
    ForEach($replacement in $replacementArray) {
        $logData = $LogData -replace [RegEx]::Escape($replacement.text), $replacement.Replace
    }

    Write-Verbose "Calling Import-LogSloth to Format Data Properly"
    $log = Import-LogSloth -LogData $LogData -SkipWarning

    Write-Verbose "Writing Sanitization Metadata to Log Class"
    $log.SanitizeType = $Sanitize
    $log.SanitizedReplacements = $replacementArray
    $log.LogDataUnsanitized = $LogDataUnsanitized
    
    Write-Verbose "Function is complete and returning"
    
    Return $log
}

Function Import-LogSCCM {
    
    [CmdLetBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $LogData
    )

    Write-Verbose "Private Import-LogSCCM Function is beginning"

    ## Fixes issue where CM adds unnecessary CRs when dumping data from an error report into a log
    $logData = $logData -replace '(?<!">)\r\n',"`n"

    ## SCCM breaks log files up by CR (\r).  Multiline within a single log line are broken up by NewLine (\n)
    $cmLogData = $logData -split "`r"

    $logArray = [System.Collections.ArrayList]::New()

    Write-Verbose "Building RegEx Variables"
    $rxLogText = [regex]::new('(?msi)<!\[LOG\[(.*)]LOG]!>')
    $rxLogTime = [regex]::new('(?msi)<!\[LOG\[.*?]LOG]!><.*?time="(.*?)"')
    $rxLogDate = [regex]::new('(?msi)<!\[LOG\[.*?]LOG]!><.*?date="(.*?)"')
    $rxLogComponent = [regex]::new('(?msi)<!\[LOG\[.*?]LOG]!><.*?component="(.*?)"')
    $rxLogContext = [regex]::new('(?msi)<!\[LOG\[.*?]LOG]!><.*?context="(.*?)"')
    $rxLogType = [regex]::new('(?msi)<!\[LOG\[.*?]LOG]!><.*?type="(.*?)"')
    $rxLogThread = [regex]::new('(?msi)<!\[LOG\[.*?]LOG]!><.*?thread="(.*?)"')
    $rxLogFile = [regex]::new('(?msi)<!\[LOG\[.*?]LOG]!><.*?file="(.*?)"')

    Write-Verbose "Looping over Lines in Log Data and building custom object"
    ForEach($item in $cmLogData) {
        $oLogLine = New-Object -TypeName PSCustomObject
        
        # Get Log Text
        $logText = $rxLogText.Match($item)
        $logTime = $rxLogTime.Match($item)
        $logDate = $rxLogDate.Match($item)
        $logComponent = $rxLogComponent.Match($item)
        $logContext = $rxLogContext.Match($item)
        $logType = $rxLogType.Match($item)
        $logThread = $rxLogThread.Match($item)
        $logFile = $rxLogFile.Match($item)

        Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Text -Value $logText.Groups[1].Value
        Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Time -Value $logTime.Groups[1].Value
        Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Date -Value $logDate.Groups[1].Value
        Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Component -Value $logComponent.Groups[1].Value
        Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Context -Value $logContext.Groups[1].Value
        Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Type -Value $logType.Groups[1].Value
        Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Thread  -Value $logThread.Groups[1].Value
        Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name File  -Value $logFile.Groups[1].Value
        
        $logArray.add($oLogLine) | Out-Null
    }
    Write-Verbose "Completed Looping over Lines in Log Data and building custom object"

    Write-Verbose "Function returning Log Array"
    Return $logArray

}

Function Import-LogSCCMSimple {
    
    [CmdLetBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $LogData
    )

    Write-Verbose "Private Import-LogSCCMSimple Function is beginning"
    
    $cmLogData = $logData -split "`r`n" | Where-Object { $_ -ne "" -and $_ -notin ("ROLLOVER")}
    
    $logArray = [System.Collections.ArrayList]::New()

    Write-Verbose "Building RegEx Variables"
    $rxLogData = [regex]::New('(.*?) \$\$<(.*?)><(.*?)><thread=(.*?)>')

    Write-Verbose "Looping over Lines in Log Data and building custom object"
    ForEach($item in $cmLogData) {
        
        $oLogLine = New-Object -TypeName PSCustomObject
        
        # Get Log Text
        $logText = $rxLogData.Match($item)
        
        if($logText.Success) {
            Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Text -Value $logText.Groups[1].Value
            Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Component -Value $logText.Groups[2].Value
            Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name DateTime -Value $logText.Groups[3].Value
            Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Thread  -Value $logText.Groups[4].Value
            $logArray.add($oLogLine) | Out-Null
        } else {
            Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Text -Value $item
            $logArray.add($oLogLine) | Out-Null
        }
    }

    Write-Verbose "Completed Looping over Lines in Log Data and building custom object"
    Write-Verbose "Function returning Log Array"
    
    Return $logArray

}
Function Import-LogW3CExtended {
    
    [CmdLetBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $LogData
    )

    Write-Verbose "Private Import-LogW3CExtended Function is beginning"

    $w3cLogData = $logData -split "`r`n" | Where-Object { $_ -ne "" }
    $headers = $w3cLogData.where{$_ -like "#Fields:*"} | Select-Object -First 1
    $headers = $headers -replace "#Fields:[ |]","" -split " "
    $logContent = $w3cLogData.where{$_ -notlike "#*" }

    $oLog = $logContent | ConvertFrom-Csv -Delimiter " " -Header $headers

    Return $oLog
}

# New changes here should be added to the manifest as well.
Export-ModuleMember -Function Import-LogSloth,Import-LogSlothSanitized,Get-LogSlothType
