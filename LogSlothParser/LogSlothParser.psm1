Enum LogType {
    CLF
	CLFAccess
	CLFError
	CSV
    TSV
    SCCM
    SCCMSimple
    MECM
    W3CExtended
    Nothing
}

Enum LogSlothExportType {
    HTML
	Markdown
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
    [System.Collections.ArrayList]$LogFormatting

    [Boolean] IsSanitized() {
        Return $($this.SanitizeType -ne [SanitizeType]::None)
    }
}

Class LogSlothFormatting {
    [System.Text.RegularExpressions.RegEx]$Lookup
    [System.Drawing.Color]$TextColor
    [System.Drawing.Color]$BackgroundColor
}

Function Get-SanitizedDataByMatch {
	[CmdletBinding()]
	[OutputType([System.Collections.ArrayList])]
	Param
	(
		[Parameter(Mandatory = $true,
				   HelpMessage = 'Text to search for $RX')]
		[string]$InputData,
		[Parameter(Mandatory = $true,
				   HelpMessage = 'Regular Expression To Search $InputData for')]
		[string]$RX,
		[Parameter(Mandatory = $true,
				   HelpMessage = 'Stub to be returned as sanitized value')]
		[string]$Stub,
		[Parameter(Mandatory = $false,
				   HelpMessage = 'Define if value should be returned in quotes')]
		[switch]$Quoted = $false
	)
	
	Write-Verbose "Private Get-SanitizedDataByMatch Function is beginning"
	
	Write-Verbose "Initalizing RegEx and building Replacement ArrayList"
	$rxLookup = [regex]::new($rx)
	
	Write-Verbose "Getting Matches for Input Data"
	$matchList = $rxLookup.matches($inputData)
	
	Write-Verbose "Reducing to Unique List of Matches"
	$uniqueMatchList = New-Object -TypeName System.Collections.Generic.HashSet[String]
	[void]$matchList.ForEach{
		$uniqueMatchList.Add($_.Groups[1].Value)
	}
	
	Write-Verbose "Completed Getting Matches for Input Data"
	
	$replList = [System.Collections.ArrayList]::New()
	
	Write-Verbose "Looping Over Unique Replacement Array to gather list of Text Strings to Replace"
	$index = 0
	
	ForEach ($m In $uniqueMatchList | Where-Object {
			$_ -ne ""
		}) {
		$index++
		$replText = "$stub$index"
		If ($quoted) {
			$replText = "`"$replText`""
		}
		Write-Verbose "... Adding '$m' => '$replText' using stub '$stub'"
		$replList.Add(
			[PSCustomObject]@{
				"OriginalText"    = $m
				"ReplacementText" = $replText
				"Stub"		      = $stub
			}
		) | Out-Null
	}
	
	Write-Verbose "Private Get-SanitizedDataByMatch Function is done"
	
	Return $replList
}

Function Test-FormatRule {
	[CmdletBinding()]
	[OutputType([Boolean])]
	Param
	(
		[Parameter(Mandatory = $true,
				   HelpMessage = 'LogSlothRule Hash Table')]
		$Rule
	)
	
	Write-Verbose "Testing Formatting Rule"
	
	If (-Not ($rule.Lookup)) {
		Write-Verbose "Missing Lookup Value, returning False"
		Return $false
	}
	
	If (-not ($Rule.TextColor) -and -not ($Rule.BackgroundColor)) {
		Write-Verbose "One of TextColor or BackgroundColor is required, returning false"
		Return $false
	}
	
	Try {
		[void][regex]$Rule.Lookup
		Write-Verbose "RegEx Test Passed"
	} Catch {
		Write-Verbose "Lookup is not valid regex, returning false"
		Return $false
	}
	
	If ($rule.TextColor) {
		Try {
			[void][System.Drawing.Color]$Rule.TextColor
			Write-Verbose "TextColor Looks OK"
		} Catch {
			Write-Verbose "TextColor is not valid System.Drawing.Color, returning false"
			Return $false
		}
	}
	
	If ($rule.BackgroundColor) {
		Try {
			[void][System.Drawing.Color]$Rule.BackgroundColor
			Write-Verbose "BackgroundColor Looks OK"
		} Catch {
			Write-Verbose "BackgroundColor is not valid System.Drawing.Color, returning false"
			Return $false
		}
	}
	
	Write-Verbose "All checks passed, returning True"
	Return $true
}

Function Get-LogSlothType {
	[CmdletBinding()]
	Param
	(
		[Parameter(ParameterSetName = 'LogData',
				   Mandatory = $true,
				   ValueFromPipeline = $true,
				   HelpMessage = 'String of raw data to be processed')]
		[String]$LogData,
		[Parameter(ParameterSetName = 'LogFile',
				   Mandatory = $true,
				   ValueFromPipeline = $false,
				   HelpMessage = 'Path to Log File to Process')]
		[System.IO.FileInfo]$LogFile,
		[Parameter(HelpMessage = 'Do not display warnings in console')]
		[switch]$SkipWarning
	)
	
	Write-Verbose "Get-LogSlothType Function is beginning"
	If (-Not ($skipWarning)) {
		Write-Warning "LogSlothParser 0.3 is Currently in Beta and may not function at 100% (Get-LogSlothType)"
	}
	
	If ($logFile) {
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
	$rxCLFAccess = [regex]::New('^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)) .*? .*? \[.*?\] "(.*?)" \d{3} ')
	$rxCLFError = [regex]::new('(?i)\[.*?] \[.*?] \[pid \d{1,}:tid \d{1,}] ')

	$firstLineOfData = $($logData -split "`n") | Where-Object {
		$_ -notlike "ROLLOVER*"
	} | Select-Object -First 1
	
	Write-Verbose "Using RegEx to Determine Log Type"

	If($rxCLFAccess.IsMatch($firstLineOfData)) {
		Write-Verbose "RegEx Confirmation that Log is Common Log Format (CLF) Access.  Returning."
		Return [LogType]::CLFAccess
	}

	If($rxCLFError.IsMatch($firstLineOfData)) {
		Write-Verbose "RegEx Confirmation that Log is Common Log Format (CLF) Error.  Returning."
		Return [LogType]::CLFError
	}

	Switch ($logData) {
		# SCCM
		{
			$rxSCCM.IsMatch($firstLineOfData)
		} {
			Write-Verbose "RegEx Confirmation that Log is SCCM.  Returning."
			Return [LogType]::SCCM; Break
		}
		
		# SCCM Simple
		{
			$rxSCCMSimple.IsMatch($firstLineOfData)
		} {
			Write-Verbose "RegEx Confirmation that Log is SCCM Simple.  Returning."
			Return [LogType]::SCCMSimple; Break
		}
		
		# W3C Extended
		{
			$rxW3CExtended.IsMatch($logData)
		} {
			Write-Verbose "RegEx Confirmation that Log is W3CExtended.  Returning."
			Return [LogType]::W3CExtended; Break
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
	
	If ($csv -and $tsv) {
		$csvItems = $csv[0].PSObject.Members.Where{
			$_.MemberType -eq "NoteProperty"
		}.Count
		$tsvItems = $tsv[0].PSObject.Members.Where{
			$_.MemberType -eq "NoteProperty"
		}.Count
		If ($csvItems -gt 1 -and $csvItems -ge $tsvItems) {
			Write-Verbose "There are equal or more properties in the CSV than TSV, selecting CSV as Winner"
			Return [LogType]::CSV
		} ElseIf ($tsvItems -gt 1) {
			Write-Verbose "There are more properties in the TSV than CSV, selecting TSV as Winner"
			Return [LogType]::TSV
		} Else {
			Write-Verbose "There is no clear winner between CSV and TSV, cannot select Winner"
		}
	}
	
	Write-Verbose "Could not find a match, Returning 'Nothing'"
	Return [LogType]::Nothing
}
Function Import-LogSloth {
	[CmdletBinding(DefaultParameterSetName = 'LogFile')]
	Param
	(
		[Parameter(ParameterSetName = 'LogData',
				   Mandatory = $true,
				   ValueFromPipeline = $true,
				   HelpMessage = 'String of raw data to be processed')]
		[String]$LogData,
		[Parameter(ParameterSetName = 'LogFile',
				   Mandatory = $true,
				   ValueFromPipeline = $false,
				   HelpMessage = 'Path to Log File to Process')]
		[System.IO.FileInfo]$LogFile,
		[Parameter(HelpMessage = 'Format of Log File (else auto-detect)')]
		[LogType]$LogType = [LogType]::Nothing,
		[Parameter(HelpMessage = 'Optional headers when importing delimited logs')]
		[Array]$Headers = @(),
		[Parameter(HelpMessage = 'Optional LogFormatting Array (See extended help in Docs)')]
		[System.Collections.ArrayList]$LogFormatting,
		[Parameter(HelpMessage = 'Do not format the output data when exporting')]
		[Switch]$SkipFormatting,
		[Parameter(HelpMessage = 'Do not display warnings in console')]
		[switch]$SkipWarning
	)
	
	Write-Verbose "Import-LogSloth Function is beginning"
	If (-Not ($skipWarning)) {
		Write-Warning "LogSlothParser 0.3 is Currently in Beta and may not function at 100% (Import-LogSloth)"
	}
	
	If ($logFile) {
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
		
	If($LogType -eq [LogType]::Nothing) {
		Write-Verbose "Getting Log Type using Get-LogSlothType Function"
		$log.logType = Get-LogSlothType -LogData $logData -skipWarning
		Write-Verbose "Detected log type is $($log.logType)"
	} else {
		Write-Verbose "Using user defined LogType $LogType"		
		$log.LogType = $LogType
	}

	If ($log.logType -eq [LogType]::Nothing) {
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
				Delimiter   = ","
			}
			If ($headers) {
				$ConvertParams.Add("Header", $headers)
			}
			[System.Collections.ArrayList]$oLog = ConvertFrom-Csv @ConvertParams
		}
		"TSV" {
			Write-Verbose "Importing TSV using Built-in PowerShell Function"
			$ConvertParams = @{
				InputObject = $logData
				Delimiter   = "`t"
			}
			If ($headers) {
				$ConvertParams.Add("Header", $headers)
			}
			[System.Collections.ArrayList]$oLog = ConvertFrom-Csv @ConvertParams
		}
		"CLF" {
			Write-Verbose "Importing CLF Log using Import-LogCLF Private Function"
			[System.Collections.ArrayList]$oLog = Import-LogCLF -LogData $LogData -Headers $headers
		}
		"CLFAccess" {
			If(-Not($Headers)) {
				$Headers = @("RemoteHost","Ident","User","DateTime","Request","Status","Size")
			}

			Write-Verbose "Importing CLF Access Log using Import-LogCLF Private Function"
			[System.Collections.ArrayList]$oLog = Import-LogCLF -LogData $LogData -Headers $headers
		}
		"CLFError" {
			If(-Not($Headers)) {
				$Headers = @("DateTime","LogLevel","Process","Source","ErrorCode","Message+")
			}

			Write-Verbose "Importing CLF Error Log using Import-LogCLF Private Function"
			[System.Collections.ArrayList]$oLog = Import-LogCLF -LogData $LogData -Headers $headers
		}
		default {
			Throw "No action defined for this log type."
		}
	}
	
	Write-Verbose "Adding Log Line Numbers to Array"
	
	[int]$lineNumber = 0
	$oLog.ForEach{
		$lineNumber++
		Add-Member -InputObject $_ -MemberType NoteProperty -Name "%%LineNo" -Value $lineNumber
	}
	
	$log.logData = $oLog
	
	If (-Not ($SkipFormatting)) {
		
		If ($LogFormatting) {
			
			$newLogFormatting = [System.Collections.ArrayList]::New()
			$okToImport = $true
			ForEach ($rule In $LogFormatting) {
				If (-Not (Test-FormatRule $Rule)) {
					$okToImport = $false
				}
				If ($okToImport) {
					$newRule = [LogSlothFormatting]::New()
					$newRule.Lookup = [regex]$rule.Lookup
					If ($rule.TextColor) {
						$newRule.TextColor = [System.Drawing.Color]$rule.TextColor
					}
					If ($rule.BackgroundCOlor) {
						$newRule.BackgroundColor = [System.Drawing.Color]$rule.BackgroundColor
					}
					[void]$newLogFormatting.Add($newRule)
				}
			}
			
			If ($okToImport) {
				$log.LogFormatting = $newLogFormatting
			} Else {
				Write-Error "Invalid rule(s) passed in LogFormatting.  Reverting to Default."
				$LogFormatting = $null
			}
		}
		
		If (-Not ($LogFormatting)) {
			Write-Verbose "Apply default coloring rules"
			
			$FormatList = [System.Collections.ArrayList]::New()
			
			$LogFormat = [LogSlothFormatting]::New()
			$LogFormat.Lookup = "(?i)\bError\b"
			$LogFormat.TextColor = [System.Drawing.Color]::Red
			$FormatList.add($LogFormat) | Out-Null
			
			$LogFormat = [LogSlothFormatting]::New()
			$LogFormat.Lookup = "(?i)\bFail(?:ing|ure|)\b"
			$LogFormat.TextColor = [System.Drawing.Color]::Red
			$FormatList.add($LogFormat) | Out-Null
			
			$log.LogFormatting = $FormatList
		}
	}
	
	Write-Verbose "Function is complete, Returning."
	Return $log
}

Function Import-LogSlothSanitized {
	Param
	(
		[Parameter(ParameterSetName = 'LogClass',
				   Mandatory = $true,
				   ValueFromPipeline = $true,
				   HelpMessage = 'Object returned by Import-LogData')]
		[LogSloth]$LogObject,
		[Parameter(ParameterSetName = 'LogData',
				   Mandatory = $true,
				   ValueFromPipeline = $true,
				   HelpMessage = 'String of raw data to be processed')]
		[String]$LogData,
		[Parameter(ParameterSetName = 'LogFile',
				   Mandatory = $true,
				   ValueFromPipeline = $false,
				   HelpMessage = 'Path to Log File to Process')]
		[System.IO.FileInfo]$LogFile,
		[Parameter(ParameterSetName = 'LogClass',
				   Mandatory = $false,
				   HelpMessage = 'List of sanitizations to apply to log data')]
		[Parameter(ParameterSetName = 'LogData',
				   Mandatory = $false)]
		[Parameter(ParameterSetName = 'LogFile',
				   Mandatory = $false)]
		[Parameter(HelpMessage = 'Format of Log File (else auto-detect)')]
		[LogType]$LogType = [LogType]::Nothing,
				   [SanitizeType]$Sanitize = [SanitizeType]::All,
		[Parameter(ParameterSetName = 'LogClass',
				   Mandatory = $false,
				   HelpMessage = 'Sanitization prefix (default: "sanitized")')]
		[Parameter(ParameterSetName = 'LogData',
				   Mandatory = $false)]
		[Parameter(ParameterSetName = 'LogFile',
				   Mandatory = $false)]
		[ValidateScript({
				If ($_ -match "(?i)^[a-z]+$") {
					$true
				} Else {
					Throw "You must use only letters A-Z."
				}
			})]
		[string]$Prefix = "sanitized",
		[Parameter(HelpMessage = 'Optional headers when importing delimited logs')]
		[Array]$Headers = @(),
		[Parameter(ParameterSetName = 'LogData',
				   Mandatory = $false,
				   HelpMessage = 'Optional LogFormatting Array (See extended help in Docs)')]
		[Parameter(ParameterSetName = 'LogFile',
				   Mandatory = $false)]
		[System.Collections.ArrayList]$LogFormatting,
		[Parameter(ParameterSetName = 'LogData',
				   Mandatory = $false,
				   HelpMessage = 'Do not format the output data when exporting')]
		[Parameter(ParameterSetName = 'LogFile',
				   Mandatory = $false)]
		[Switch]$SkipFormatting,
		[Parameter(HelpMessage = 'Do not display warnings in console')]
		[switch]$SkipWarning
	)
	
	Write-Verbose "Import-LogSlothSanitized Function is beginning"
	

	If (-Not ($skipWarning)) {
		Write-Warning "LogSlothParser 0.3 is Currently in Beta and may not function at 100% (Import-LogSlothSanitized)"
	}
	
	If ($logFile) {
		Try {
			Write-Verbose "LogFile Parameter Defined, Importing $logFile"
			$logData = Get-Content $logFile -Raw -ErrorAction Stop
		} Catch {
			Throw "Error reading $logFile $($_.Exception.Message)"
		}
	} ElseIf ($LogObject) {
		Write-Verbose "LogClass Passed, Capturing Raw Data"
		$logData = $LogObject.LogDataRaw
	}
	
	If($LogType -eq [LogType]::Nothing) {
		Write-Verbose "Getting Log Type using Get-LogSlothType Function"
		$LogType = Get-LogSlothType -LogData $logData -skipWarning
		Write-Verbose "Detected log type is $($LogType)"
	} else {
		Write-Verbose "Using user defined LogType $LogType"		
	}
	
	If ($LogType -eq [LogType]::Nothing) {
		Throw "Missing LogType"
	}
	
	$LogDataUnsanitized = $LogData
	
	$replacementList = [System.Collections.ArrayList]::New()
	
	# Build Replacements Table
	
	Write-Verbose "Building Replacements Table for Input Data to Sanitize"
	# -- Configuration Manager Specific --
	If ($logType -eq [LogType]::SCCM -or $logType -eq [LogType]::SCCMSimple) {
		Write-Verbose "... Processing Configuration Manager (CM) Sanitization"
		Switch ($sanitize) {
			{
				$_ -band [SanitizeType]::cmDistributionPoint
			} {
				# Download URLs
				Write-Verbose "...... Processing CM Distribution Points (Download URLs)"
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)Matching DP location found [0-9]{1,} - (http(?:|s):\/\/.*?) "; Stub = "$($prefix)dpurl"; Quoted = $false
					}) | Out-Null
				
				# CMG URL
				Write-Verbose "...... Processing CM Distribution Points (CMG URLs)"
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)https:\/\/([^. ]+).cloudapp\.net"; Stub = "$($prefix)cmghost"; Quoted = $false
					}) | Out-Null
			}
			{
				$_ -band [SanitizeType]::cmAdvertisementId
			} {
				#Advertisement ID by "ADV:#"
				Write-Verbose "...... Processing CM Advertisement IDs"
				$replacementList.Add([PSCustomObject]@{
						RegEx = "Ad(?:vert|):(?: |)([A-Z]{1,3}[0-9A-F]{5,}\b)"; Stub = "$($prefix)adv"; Quoted = $false
					}) | Out-Null
			}
			{
				$_ -band [SanitizeType]::cmPackageId
			} {
				#Package IDs by "Package:#"
				Write-Verbose "...... Processing CM Package IDs"
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)Package:(?: |)([A-Z]{1,3}[0-9A-F]{5,}\b)"; Stub = "$($prefix)pkgid"; Quoted = $false
					}) | Out-Null
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)Download started for content ([A-Z]{1,3}[0-9]{5,})"; Stub = "$($prefix)pkgiddl"; Quoted = $false
					}) | Out-Null
			}
			{
				$_ -band [SanitizeType]::cmProgramId
			} {
				# Program Names by "Program:'xxx'>"
				Write-Verbose "...... Processing CM Program IDs"
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)Program:(?: |)(.*?)(?:[\b|\]|,]| \w+ with exit code)"; Stub = "$($prefix)prgm"; Quoted = $false
					}) | Out-Null
			}
			{
				$_ -band [SanitizeType]::cmMachineName
			} {
				# Computer Names by "Machine Name = 'xxx'"
				Write-Verbose "...... Processing CM Machine Name"
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)MachineName = `"(.*?)`""; Stub = "$($prefix)hostname"; Quoted = $false
					}) | Out-Null
			}
			{
				$_ -band [SanitizeType]::cmSiteCode
			} {
				# Site Code in Quotes
				Write-Verbose "...... Processing CM Site Codes"
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)SiteCode(?: |)=(?: |)`"([A-Z0-9]{1,3})`""; Stub = "$($prefix)sitecodeA"; Quoted = $false
					}) | Out-Null
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)Site Code -> ([A-Z0-9]{1,3})"; Stub = "$($prefix)sitecodeB"; Quoted = $false
					}) | Out-Null
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)(?:^| )SITE=(.*?)(?:,|\]| )"; Stub = "$($prefix)cmsrvC"; Quoted = $false
					}) | Out-Null
			}
			{
				$_ -band [SanitizeType]::cmADSite
			} {
				# AD Site Name
				Write-Verbose "...... Processing CM AD Sites"
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)<ADSite(?:.*?)Name=`"(.*?)`"\/>"; Stub = "$($prefix)adsite"; Quoted = $false
					}) | Out-Null
			}
			{
				$_ -band [SanitizeType]::cmServerName
			} {
				# CM SQL Server Name
				Write-Verbose "...... Processing CM Server Names"
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)sqlServerName(?: |)=(?: |)(.*?)(?:,| |\])"; Stub = "$($prefix)cmsrvA"; Quoted = $false
					}) | Out-Null
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)Server Name: (.*?)(?:,|\]| )"; Stub = "$($prefix)cmsrvB"; Quoted = $false
					}) | Out-Null
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)Setting Site Server -> (.*?)(?:,|\]| )"; Stub = "$($prefix)cmsrvC"; Quoted = $false
					}) | Out-Null
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)(?:^| )SYS=(.*?)(?:,|\]| )"; Stub = "$($prefix)cmsrvD"; Quoted = $false
					}) | Out-Null
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)(?:^| )Server: (.*?)(?:,|\]| )"; Stub = "$($prefix)cmsrvE"; Quoted = $false
					}) | Out-Null
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)(?:^| )MP: (.*?)(?:,|\]| )"; Stub = "$($prefix)cmsrvF"; Quoted = $false
					}) | Out-Null
			}
			{
				$_ -band [SanitizeType]::cmDatabaseName
			} {
				# CM Database Name
				Write-Verbose "...... Processing CM Database Names"
				$replacementList.Add([PSCustomObject]@{
						RegEx = "(?msi)databaseName(?: |)=(?: |)(.*?)(?:,| |\]|\.)"; Stub = "$($prefix)cmdb"; Quoted = $false
					}) | Out-Null
			}
		} # // End of Switch
	} # // End of Log Type SCCM
	
	# -- Generic Replacements --
	Write-Verbose "... Processing Generic Sanitization"
	Switch ($Sanitize) {
		{
			$_ -band [SanitizeType]::urlHost
		} {
			# URL Host
			Write-Verbose "...... Processing URL Hosts"
			$replacementList.Add([PSCustomObject]@{
					RegEx = "(?msi)http(?:|s):\/\/(.*?)\/"; Stub = "$($prefix)urlhost"; Quoted = $false
				}) | Out-Null
		}
		{
			$_ -band [SanitizeType]::guid
		} {
			# GUIDs in 8-4-4-4-12 Format
			Write-Verbose "...... Processing GUIDs"
			$replacementList.Add([PSCustomObject]@{
					RegEx = "(?msi)([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})"; Stub = "$($prefix)guid"; Quoted = $false
				}) | Out-Null
		}
		{
			$_ -band [SanitizeType]::hash64
		} {
			# Hashes (64 Character Long Hex)
			Write-Verbose "...... Processing 64 Character Hashes"
			$replacementList.Add([PSCustomObject]@{
					RegEx = "(?msi)([A-Z0-9]{64})"; Stub = "$($prefix)hash"; Quoted = $false
				}) | Out-Null
		}
		{
			$_ -band [SanitizeType]::ipv4
		} {
			# IP Addresses
			Write-Verbose "...... Processing IPv4 Addresses"
			$replacementList.Add([PSCustomObject]@{
					RegEx = "(?msi)((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"; Stub = "$($prefix)ip"; Quoted = $false
				}) | Out-Null
		}
		{
			$_ -band [SanitizeType]::sid
		} {
			# SID Format
			Write-Verbose "...... Processing SIDs"
			$replacementList.Add([PSCustomObject]@{
					RegEx = "(?msi)(S-1-[0-9]{1,2}-\d{1,2}-(\d{8,10}-){3}\d{8,10})"; Stub = "$($prefix)sid"; Quoted = $false
				}) | Out-Null
		}
	} # // End of Switch (Generic)
	
	Write-Verbose "Building List of Data to Sanitize"
	
	$replacementArray = [System.Collections.ArrayList]::New()
	
	ForEach ($rule In $replacementList) {
		$uniqueStringMatches = [System.Collections.Generic.HashSet[string]]::New([StringComparer]::InvariantCultureIgnoreCase)
		$rxMatches = [regex]::Matches($LogData, $rule.regex)
		ForEach ($m In $rxMatches) {
			$uniqueStringMatches.Add($m.groups[1].value) | Out-Null
		}
		
		$index = 0
		ForEach ($find In $uniqueStringMatches) {
			$index++
			$replace = "$($rule.Stub)$index"
			If ($rule.Quoted) {
				$replace = "`"$replace`""
			}
			$replacementArray.Add(
				[PSCustomObject]@{
					Text    = $find
					Replace = $replace
				}
			) | Out-Null
		}
	}
	
	Write-Verbose "Starting Sanitization of Data based on Replacement ArrayList"
	
	ForEach ($replacement In $replacementArray) {
		$logData = $LogData -replace [RegEx]::Escape($replacement.text), $replacement.Replace
	}
	
	Write-Verbose "Calling Import-LogSloth to Format Data Properly"
	$log = Import-LogSloth -LogData $LogData -SkipWarning -LogFormatting $LogFormatting -SkipFormatting:$SkipFormatting -Headers $headers
	
	Write-Verbose "Writing Sanitization Metadata to Log Class"
	$log.SanitizeType = $Sanitize
	$log.SanitizedReplacements = $replacementArray
	$log.LogDataUnsanitized = $LogDataUnsanitized
	
	Write-Verbose "Function is complete and returning"
	
	Return $log
}

Function Import-LogSCCM {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true,
				   HelpMessage = 'String of log data to import')]
		[string]$LogData
	)
	
	Write-Verbose "Private Import-LogSCCM Function is beginning"
	
	## Fixes issue where CM adds unnecessary CRs when dumping data from an error report into a log
	$logData = $logData -replace '(?<!">)\r\n', "`n"
	
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
	ForEach ($item In $cmLogData) {
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
		Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Component -Value $logComponent.Groups[1].Value
		Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name DateTime -Value "$($logDate.Groups[1].Value) $($logTime.Groups[1].Value)"
		Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Thread -Value $logThread.Groups[1].Value
		Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Context -Value $logContext.Groups[1].Value
		Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name Type -Value $logType.Groups[1].Value
		Add-Member -InputObject $oLogLine -MemberType NoteProperty -Name File -Value $logFile.Groups[1].Value
		
		$logArray.add($oLogLine) | Out-Null
	}
	Write-Verbose "Completed Looping over Lines in Log Data and building custom object"
	
	Write-Verbose "Function returning Log Array"
	Return $logArray
}

Function Import-LogSCCMSimple {

    [CmdLetBinding()]
    Param(
		[Parameter(Mandatory = $true,
				   HelpMessage = 'String of log data to import')]
        [string]$LogData
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
Function Import-LogCLF {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true,
				   HelpMessage = 'String of log data to import')]
		[string]$LogData,
		[array]$headers
	)
	
    Write-Verbose "Private Import-LogCLF Function is beginning"
	Write-Verbose "Importing CLF Log File using Built-in PowerShell Function"

	# Change text in square brackets to be in quotes for better import.
	$tmpLogData = $LogData -replace '\[(.*?)\]','"$1"'

	If($headers) {
		# If the final header ends in a plus, it should cover all remaining fields, so enclose the final group of characters in a set of quotes.
		## TODO: Make this its own function for better re-usability
		## TODO: Document this "+" sign at end of last header.
		If($headers[-1].ToString() -like "*+") {
			$staticHeaderCount = $Headers.Count - 1
			$tmpLogData = [regex]::Replace($tmpLogData, "(?m)(^(?:`".*?`" |.*? ){$staticHeaderCount})(.*?)`r", '$1"$2"')

			# Remove + sign
			$headers = [System.Collections.ArrayList]$Headers
			$headers[-1] = $headers[-1].ToString().Substring(0,$headers[-1].ToString().Length-1)
		}
	}

	$ConvertParams = @{
		InputObject = $tmpLogData
		Delimiter = " "
	}

	If ($headers) {
		$ConvertParams.Add("Header", $headers)
	}

	[System.Collections.ArrayList]$logArray = ConvertFrom-Csv @ConvertParams

	Return $logArray
}

Function Import-LogW3CExtended {

    [CmdLetBinding()]
    Param(
		[Parameter(Mandatory = $true,
				   HelpMessage = 'String of log data to import')]
        [string]$LogData
    )

    Write-Verbose "Private Import-LogW3CExtended Function is beginning"

    $w3cLogData = $logData -split "`r`n" | Where-Object { $_ -ne "" }
    $headers = $w3cLogData.where{$_ -like "#Fields:*"} | Select-Object -First 1
    $headers = $headers -replace "#Fields:[ |]","" -split " "
    $logContent = $w3cLogData.where{$_ -notlike "#*" }

    $oLog = $logContent | ConvertFrom-Csv -Delimiter " " -Header $headers

    Return $oLog
}

Function Convert-Color2Hex {
	
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true,
				   HelpMessage = 'Color Name')]
		[System.Drawing.Color]$Color
    )

    $rHex = [Convert]::ToString($color.r, 16).padLeft(2, "0")
    $gHex = [Convert]::ToString($color.g, 16).padLeft(2, "0")
    $bHex = [Convert]::ToString($color.b, 16).padLeft(2, "0")

    Return "#$rHex$gHex$bHex".ToUpper()
}

Function ConvertTo-LogSlothHTML {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   HelpMessage = 'Object returned by Import-LogData or Import-LogDataSanitized')]
		[LogSloth]$LogObject,
		[Parameter(HelpMessage = 'Do not display warnings in console')]
		[switch]$SkipWarning,
		[Parameter(HelpMessage = 'Define if the raw (or sanitized) data from the original log should be included in the conversion.')]
		[switch]$IncludeRawLog
	)
	
	Write-Verbose "ConvertTo-LogSlothHTML Function is beginning"
	If (-Not ($skipWarning)) {
		Write-Warning "LogSlothParser 0.3 is Currently in Beta and may not function at 100% (Export-LogSlothLog)"
	}
	
	Write-Verbose "Excluding Meta Properties from Export"
	$LogObject.LogData = $LogObject.LogData | Select-Object -Property * -ExcludeProperty "%%*"
	
	# Build Collection of Formatting Rules
	$cssFormatRules = [System.Collections.ArrayList]::New()
	$cssIndex = 0
	ForEach ($rule In $LogObject.LogFormatting) {
		$thisRule = [PSCustomObject]@{
			RuleNum = $cssIndex
			Lookup  = $rule.Lookup
			TextColor = $null
			BackgroundColor = $null
		}
		If ($rule.TextColor -ne [System.Drawing.Color]::Empty) {
			Add-Member -InputObject $thisRule -MemberType NoteProperty -Name "TextColor" -Value (Convert-Color2Hex $rule.TextColor) -Force
		}
		If ($rule.BackgroundColor -ne [System.Drawing.Color]::Empty) {
			Add-Member -InputObject $thisRule -MemberType NoteProperty -Name "BackgroundColor" -Value (Convert-Color2Hex $rule.BackgroundColor) -Force
		}
		$cssFormatRules.Add($thisRule) | Out-Null
		$cssIndex++
	}
	
	[System.Collections.ArrayList]$css = @()
	[void]$css.Add("#LogTable td { font-family: verdana; font-size: 12px; }")
	[void]$css.Add("#LogTable th { font-family: verdana; font-size: 12px; font-weight: bold; text-align: left; }")
	
	ForEach ($rule In $cssFormatRules) {
		$ruleText = ""
		If ($rule.BackgroundColor) {
			$ruleText += "background-color: $($rule.BackgroundColor); "
		}
		If ($rule.TextColor) {
			$ruleText += "color: $($rule.TextColor); "
		}
		[void]$css.Add("#LogTable tr.rxMatch$($rule.RuleNum) { $ruleText }")
	}
	
	If ($IncludeRawLog) {
		[void]$css.Add("#LogRaw { font-family: 'courier new'; font-size: 12px; width: 100%; height: 200px; margin-top: 20px; white-space: nowrap; overflow: auto;")
	}
	
	[System.Collections.ArrayList]$links = @()
	[void]$links.Add('<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.34/css/jquery.dataTables.css">')
	
	[System.Collections.Specialized.OrderedDictionary]$dataTableOptions = @{
	}
	[void]$dataTableOptions.Add("paging", $true)
	[void]$dataTableOptions.Add("pagingType", "full_numbers")
	[void]$dataTableOptions.Add("ordering", $false)
	[void]$dataTableOptions.Add("order", @())
	[void]$dataTableOptions.Add("lengthMenu", @(25, 50, 100, 250, 500, 1000))
	[void]$dataTableOptions.Add("pageLength", 500)
	
	[System.Collections.ArrayList]$scripts = @()
	[void]$scripts.Add('<script src="https://code.jquery.com/jquery-3.6.0.min.js" integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=" crossorigin="anonymous"></script>')
	[void]$scripts.Add('<script src="https://cdn.datatables.net/1.10.34/js/jquery.dataTables.js"></script>')
	[void]$scripts.Add("<script> `$(document).ready( function () { `$('#LogTable').DataTable( $($dataTableOptions | ConvertTo-Json) ); } );</script>")
	
	[System.Collections.ArrayList]$thead = @()
	[void]$thead.AddRange(@("<thead>", "<tr>"))
	ForEach ($prop In $logObject.LogData[0].psobject.Properties.Name) {
		[void]$thead.Add("<th>$([System.Web.HttpUtility]::HTMLEncode($prop))</th>")
	}
	[void]$thead.AddRange(@("</tr>", "</thead>"))
	
	[System.Collections.ArrayList]$tbody = @()
	ForEach ($entry In $logObject.LogData) {
		#ForEach Line in the Log File
		
		# Determine if we need to apply any style to this row based on RegEx Rules
		$trClass = ""
		ForEach ($rule In $cssFormatRules) {
			ForEach ($prop In $LogObject.LogData[0].psobject.Properties.Name) {
				#ForEach Property (Field/Column)
				If ($rule.Lookup.IsMatch($entry.$prop)) {
					$trClass = "rxMatch$($rule.ruleNum)"
				}
			}
		}
		
		If ($trClass) {
			[void]$tbody.Add("<tr class=`"$trClass`">")
		} Else {
			[void]$tbody.Add("<tr>")
		}
		
		ForEach ($prop In $LogObject.LogData[0].psobject.Properties.Name) {
			#ForEach Property (Field/Column)
			[void]$tbody.Add("<td>$([System.Web.HttpUtility]::HTMLEncode($entry.$prop))</td>")
		}
		[void]$tbody.Add("</tr>")
	}
	
	[System.Collections.ArrayList]$html = @()
	[void]$html.Add("<!DOCTYPE html>")
	[void]$html.AddRange(@("<html lang=`"en`">", "<head>"))
	[void]$html.Add("<title>LogSloth Log Export</title>")
	[void]$html.AddRange($links)
	[void]$html.AddRange($scripts)
	[void]$html.AddRange(@("<style>", $css, "</style>"))
	[void]$html.Add("</head>")
	[void]$html.Add("<body>")
	[void]$html.Add('<table id="LogTable">')
	[void]$html.AddRange($thead)
	[void]$html.AddRange($tbody)
	[void]$html.Add("</table>")
	
	If ($IncludeRawLog) {
		[void]$html.Add("<textarea id=`"LogRaw`">")
		[void]$html.Add($logObject.LogDataRaw)
		[void]$html.Add("</textarea>")
	}
	
	[void]$html.Add("</body>")
	[void]$html.Add("</html>")
	
	Write-Verbose "ConvertTo-LogSlothHTML Function is returning"
	Return $html
}

Function ConvertTo-LogSlothMarkdown {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   HelpMessage = 'Object returned by Import-LogData or Import-LogDataSanitized')]
		[LogSloth]$LogObject,
		[Parameter(HelpMessage = 'Do not display warnings in console')]
		[switch]$SkipWarning
	)
	
	Write-Verbose "ConvertTo-LogSlothMarkdown Function is beginning"
	If (-Not ($skipWarning)) {
		Write-Warning "LogSlothParser 0.3 is Currently in Beta and may not function at 100% (Export-LogSlothLog)"
	}
	
	Write-Verbose "Excluding Meta Properties from Export"
	$LogObject.LogData = $LogObject.LogData | Select-Object -Property * -ExcludeProperty "%%*"
	
	$markDown = [System.Collections.ArrayList]::New()

	# Add table header
	$mdHeader = $($logObject.LogData[0].psobject.Properties.Name -replace "\|","\|") -join "|"

	# Add table border line
	$mdTableBorder = "-|"*($logObject.LogData[0].psobject.Properties.Name.Count-1) + "-"

	[void]$markDown.Add($mdHeader)
	[void]$markDown.Add($mdTableBorder)

	ForEach ($entry In $logObject.LogData) {
		$mdTableLine = $($entry.psobject.Properties.Value -replace "\|","\|") -join "|"
		[void]$markDown.Add($mdTableLine)
	}

	Write-Verbose "ConvertTo-LogSlothHTML Function is returning"
	Return $markDown
}

Function Export-LogSlothLog {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'Object returned by Import-LogData or Import-LogDataSanitized')]
		[LogSloth]$LogObject,
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $false,
				   Position = 2,
				   HelpMessage = 'Path to file to export to')]
		[System.IO.FileInfo]$Path,
		[Parameter(Mandatory = $false,
				   ValueFromPipeline = $false,
				   Position = 3,
				   HelpMessage = 'Format of the exported data')]
		[LogSlothExportType]$Format = [LogSlothExportType]::HTML,
		[Parameter(Mandatory = $false,
				   ValueFromPipeline = $false,
				   HelpMessage = 'Define if the raw (or sanitized) data from the original log should be included in the conversion.')]
		[Switch]$IncludeRawLog,
		[Parameter(HelpMessage = 'Do not display warnings in console')]
		[Switch]$SkipWarning,
		[Parameter(HelpMessage = 'Overwrite existing file if it exists')]
		[Switch]$Force
	)
	
	Write-Verbose "Export-LogSlothLog Function is beginning"
	If (-Not ($skipWarning)) {
		Write-Warning "LogSlothParser 0.3 is Currently in Beta and may not function at 100% (Export-LogSlothLog)"
	}
	
	Switch ($Format) {
		"HTML" {
			Try {
				$LogObject | ConvertTo-LogSlothHTML -IncludeRawLog:$includeRawLog -SkipWarning | Out-File $Path -Encoding utf8 -NoClobber:$(-Not $Force) -ErrorAction Stop
			} Catch {
				Throw "Unable to export file. $($_.Exception.Message)"
			}
		}
		"Markdown" {
			Try {
				$logObject | ConvertTo-LogSlothMarkdown -SkipWarning | Out-File $Path -Encoding utf8 -NoClobber:$(-Not $Force) -ErrorAction Stop
			} Catch {
				Throw "Unable to export file. $($_.Exception.Message)"
			}
		}
	}
	
	Write-Verbose "Export-LogSlothLog Function is returning"
	Return
}

# New changes here should be added to the manifest as well.
Export-ModuleMember -Function Import-LogSloth,Import-LogSlothSanitized,Get-LogSlothType,Export-LogSlothLog,ConvertTo-LogSlothHTML,ConvertTo-LogSlothMarkdown
