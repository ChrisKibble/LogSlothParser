Enum LogType {
    CSV
    TSV
    ColonSV
    SCCM
    MECM
    SCCM2007
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
    cmAll = 4064

    all = 2147483647
}

Class LogSloth {
    [LogType]$logType = [LogType]::Nothing
    [SanitizeType]$SanitizeType = [SanitizeType]::None
    [System.Collections.ArrayList]$SanitizedReplacements = @()
    [System.Collections.ArrayList]$logData = @()

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
        [String]$logData,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName = "LogFile")]
        [System.IO.FileInfo]$logFile,
        [switch]$skipWarning
    )

    Write-Verbose "Get-LogSlothType Function is beginning"
    If(-Not($skipWarning)) { Write-Warning "LogSlothParser is Currently in Beta and may not function at 100% (Get-LogSlothType)" }

    If($logFile) {
        Try {
            Write-Verbose "LogFile Parameter Defined, Importing $logFile"
            $logData = Get-Content $logFile -Raw
        } Catch {
            Throw "Error reading $logFile $($_.Exception.Message)"
        }
    }

    Write-Verbose "Initalizing RegEx Checks"
    $rxSCCM = [regex]::new('^<!\[LOG')
    $rxSCCMSimple = [regex]::new('.*?<.*?><.*?><thread=\d{1,} \(.*?\)>')
    $rxW3CExtended = [regex]::new('(?msi)^#Software.*?^#Fields: ')

    Write-Verbose "Using RegEx to Determine Log Type"
    Switch ($logData) {
        # SCCM
        { $rxSCCM.IsMatch($logData)  } { 
            Write-Verbose "RegEx Confirmation that Log is SCCM.  Returning."
            Return [LogType]::SCCM; break 
        }
        
        # SCCM Simple
        { $rxSCCMSimple.IsMatch($logData) } { 
            Write-Verbose "RegEx Confirmation that Log is SCCM2007.  Returning."
            Return [LogType]::SCCM2007; break 
        }

        # W3C Extended
        { $rxW3CExtended.IsMatch($logData) } { 
            Write-Verbose "RegEx Confirmation that Log is W3CExtended.  Returning."
            Return [LogType]::W3CExtended; break 
        }

    }

    # Check for W3C Extended by looking at first line of log

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

    Try {
        Write-Verbose "Converting Log Data to Colon Delimited"
        $ColonSV = $logData | ConvertFrom-Csv -Delimiter ";"   
        Write-Verbose "Conversion to Colon Delimited was successful"
    } Catch {
        Write-Verbose "Failed to Convert Log to TSV $($_.Exception.Message)"
        $ColonSV = $null
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

    If($ColonSV[0].PSObject.Members.Where{$_.MemberType -eq "NoteProperty"}.Count -gt 1) {
        Write-Verbose "There are multiple properties returned with colon separated values, selecting ColonSV as Winner"
        Return [LogType]::ColonSV
    }

    Write-Verbose "Could not find a match, Returning 'Nothing'"
    Return [LogType]::Nothing
}
Function Import-LogSloth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName = "LogData")]
        [String]$logData,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName = "LogFile")]
        [System.IO.FileInfo]$logFile,
        [Array]$headers = @(),
        [switch]$skipWarning
    )

    Write-Verbose "Import-LogSloth Function is beginning"
    If(-Not($skipWarning)) { Write-Warning "LogSlothParser is Currently in Beta and may not function at 100% (Import-LogSloth)" }

    If($logFile) {
        Try {
            Write-Verbose "LogFile Parameter Defined, Importing $logFile"
            $logData = Get-Content $logFile -Raw
        } Catch {
            Throw "Error reading $logFile $($_.Exception.Message)"
        }
    }

    $log = [LogSloth]::New()

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
        "SCCM2007" { 
            Write-Verbose "Importing SCCM Log using Import-LogSCCM2007 Private Function"
            [System.Collections.ArrayList]$oLog = Import-LogSCCM2007 -logData $logData 
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
        "ColonSV" {
            Write-Verbose "Importing ColonSV using Built-in PowerShell Function"
            $ConvertParams = @{
                InputObject = $logData
                Delimiter = ";"
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
        [LogSloth]$log,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName = "LogData")]
        [String]$logData,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName = "LogFile")]
        [System.IO.FileInfo]$logFile,
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
        [string]$prefix = "sanitized",
        [Array]$headers = @(),
        [switch]$skipWarning
    )

    Write-Verbose "Import-LogSlothSanitized Function is beginning"

    If(-Not($skipWarning)) { Write-Warning "LogSlothParser is Currently in Beta and may not function at 100% (Import-LogSlothSanitized)" }

    Try {
        If($logData) { 
            Write-Verbose "Log Sanitized calling Import Function for passed Log Data"
            [LogSloth]$log = Import-LogSloth -logData $logData -skipWarning -headers $headers
        }
        If($logFile) { 
            Write-Verbose "Log Sanitized calling Import Function for passed Log File"
            [LogSloth]$log = Import-LogSloth -logFile $logFile -skipWarning -headers $headers
        }
    } Catch {
        Throw "Unable to read log data $($_.Exception.Message)"        
    }

    If($log.LogType -eq [LogType]::Nothing) { 
        Throw "Missing LogType"
    }

    $log.SanitizeType = $Sanitize

    $replacementList = [System.Collections.ArrayList]::New()
    
    # Build Replacements Table
    
    Write-Verbose "Building Replacements Table for Input Data to Sanitize"
    # -- Configuration Manager Specific --
    If($log.logType -in ([LogType]::SCCM,[LogType]::SCCM2007)) {
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

                #Package IDs by Download
                Write-Verbose "...... Processing CM Advertisement IDs (by Download Content Messages)"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)Download started for content ([A-Z]{1,3}[0-9]{5,})"; Stub="$($prefix)pkgdlid"; Quoted=$false}) | Out-Null
            }
            { $_ -band [SanitizeType]::cmProgramId } {
                # Program Names by "Program:'xxx'>"
                Write-Verbose "...... Processing CM Program IDs"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)Program:(?: |)(.*?)[\b|\]|,]"; Stub="$($prefix)pgrm"; Quoted=$false}) | Out-Null
            }
            { $_ -band [SanitizeType]::cmMachineName } {
                # Computer Names by "Machine Name = 'xxx'"
                Write-Verbose "...... Processing CM Machine Name"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)MachineName = `"(.*?)`""; Stub="$($prefix)hostname"; Quoted=$false}) | Out-Null
            }
            { $_ -band [SanitizeType]::cmSiteCode} {
                # Site Code in Quotes
                Write-Verbose "...... Processing CM Site Codes"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)SiteCode=(`"[A-Z0-9]{1,3}`")"; Stub="$($prefix)sitecode"; Quoted=$true}) | Out-Null
            }
            { $_ -band [SanitizeType]::cmADSite} {
                # AD Site Name
                Write-Verbose "...... Processing CM AD Sites"
                $replacementList.Add([PSCustomObject]@{RegEx="(?msi)<ADSite(?:.*?)Name=`"(.*?)`"\/>"; Stub="$($prefix)adsite"; Quoted=$false}) | Out-Null
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
            $replacementList.Add([PSCustomObject]@{RegEx="(?msi)((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"; Stub="$($prefix)ip"; Quoted=$true}) | Out-Null
        }
        { $_ -band [SanitizeType]::sid } {
            # SID Format
            Write-Verbose "...... Processing SIDs"
            $replacementList.Add([PSCustomObject]@{RegEx="(?msi)(S-1-[0-9]{1,2}-\d{1,2}-(\d{8,10}-){3}\d{8,10})"; Stub="$($prefix)sid"; Quoted=$false}) | Out-Null
        }
    } # // End of Switch (Generic)

    Write-Verbose "Starting Sanitization of Data based on Replacement ArrayList"
    
    [System.Collections.ArrayList]$fieldsToSanitize = @()
    Switch($log.logType) {
        "SCCM" {
            Write-Verbose "Adding Fields to Sanitize to be only 'Text' (SCCM Log)"
            $fieldsToSanitize.Add("Text") | Out-Null   
            break
        }
        "SCCM2007" {
            Write-Verbose "Adding Fields to Sanitize to be only 'Text' (SCCM2007 Log)"
            $fieldsToSanitize.Add("Text") | Out-Null   
            break
        }
        default {
            Write-Verbose "Default - Sanitize All Fields"
            $log.logdata[0].PSObject.Members.where{$_.MemberType -eq "NoteProperty"}.ForEach{
                Write-Verbose "Adding Field '$($_.Name)' to Fields to Sanitize List"
                $fieldsToSanitize.Add($_.Name) | Out-Null
            }
        }
    }

    # Build a big blob of text based on all the fields we have to sanitize.  We do these together so that
    # we get the same replacement values across all fields in the object.


    Write-Verbose "Gathering Data to Sanitize"
    [string]$inputData = ""

    ForEach($field in $fieldsToSanitize) {
        [string]$text = $($log.logData | Select-Object -ExpandProperty $field) -join "`r`n"
        $inputData = -join($inputData,$text)
    }
    
    # ReplacementList contains a list of regex rules that need to be run
    # in order to replace data in one or more fields with their sanitized values

    # SantiizedTextRules contains a list of the output of the rules to show that some value 
    # needs to be replaced with some other value
    $sanitizedTextRules = [System.Collections.ArrayList]::New(@())

    ForEach($itemToReplace in $replacementList) {
        $rule = SanitizeByMatch -inputData $inputData -rx $itemToReplace.regex -stub $itemToReplace.Stub -quoted:$itemToReplace.quoted
        $rule | Out-Host
        if($rule) {
            $sanitizedTextRules.AddRange($rule) | Out-Null
        }
    }

    # We now know the text that needs to be replaced ($sanitizedTextRules) and the fields they need to be replaced in ($fieldsToSanitize)
    # that was based on the $inputData (a collection of the text in $fieldsToSanitize). All that's left is to do the replacements across
    # those fields.

    Write-Verbose "Looping over rules to replace text"

    $sanitizedTextRules.ForEach{
        Write-Verbose "$(Get-Date) $($_.OriginalText)"
    }
    break

    ForEach($replRule in $sanitizedTextRules) {
        ForEach($field in $fieldsToSanitize) {
            Write-Verbose "... Replacing '$($replRule.OriginalText)' with '$($replRule.ReplacementText)' in field '$field'"
            $log.logData.ForEach{
                $_.$field = $_.$field -replace [regex]::Escape($replRule.OriginalText),$replRule.ReplacementText
            }
        }

        # Add this rule to our sanitized array for output.  We only need this once regardless of how many fields.
        $log.SanitizedReplacements.Add(
            [PSCustomObject]@{
                OriginalText = $replRule.OriginalText
                ReplacementText = $replRule.ReplacementText
            }
        ) | Out-Null
        ### TODO: We can probably just add the SanitizedRules here instead of building this out in the loop.
    }
    Write-Verbose "Done Looping over rules to replace text"

    Write-Verbose "Function is complete and returning"
    Return $log
}


Function Import-LogSCCM {
    
    [CmdLetBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $logData
    )

    Write-Verbose "Private Import-LogSCCM Function is beginning"

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

Function Import-LogSCCM2007 {
    
    [CmdLetBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $logData
    )

    Write-Verbose "Private Import-LogSCCM2007 Function is beginning"

    $cmLogData = $logData -split "`r`n" | Where-Object { $_ -ne "" -and $_ -notin ("ROLLOVER")}

    $logArray = [System.Collections.ArrayList]::New()

    Write-Verbose "Building RegEx Variables"
    $rxLogData = [regex]::New('(.*?) \$\$<(.*?)><(.*?)><thread=(.*?)>')
    
    Write-Verbose "Completed Looping over Lines in Log Data and building custom object"
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
        $logData
    )

    Write-Verbose "Private Import-LogW3CExtended Function is beginning"

    $w3cLogData = $logData -split "`r`n" | Where-Object { $_ -ne "" }
    $headers = $w3cLogData.where{$_ -like "#Fields:*"} | Select-Object -First 1
    $headers = $headers -replace "#Fields:[ |]","" -split " "
    $logContent = $w3cLogData.where{$_ -notlike "#*" }

    $oLog = $logContent | ConvertFrom-Csv -Delimiter " " -Header $headers

    Return $oLog
}
Export-ModuleMember -Function Import-LogSloth,Import-LogSlothSanitized,Get-LogSlothType
