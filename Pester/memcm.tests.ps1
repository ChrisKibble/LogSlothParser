Import-Module $PSScriptRoot\..\LogSlothParser\LogSlothParser.psd1 -Force

$logFiles = Get-ChildItem "$PSScriptRoot\..\LogSamples\MEMCM" -Exclude ".*" -Recurse | Select-Object -ExpandProperty FullName

# Unnecessary but makes for easier reading in detailed output
$logFiles = $logFiles.ForEach{ Resolve-Path $_ -Relative }

Describe "Ensure MEMCM Log Files Import Successfully" {
    
    It "Pre-Import Verification on <_>" -TestCases $logFiles {  
        
        $rxValidCM = [regex]::New('(?msi)^<!\[LOG\[(?:.*?)]LOG]!><time="(?:.*?)" date="(?:.*?)" component="(?:.*?)" context="(?:.*?)" type="(?:.*?)" thread="(?:.*?)" file="(?:.*?)">$')    
        $rxValidCMSimple = [regex]::New('(.*?) \$\$<(.*?)><(.*?)><thread=(.*?)>')

        $logContent = Get-Content $_ -Raw

        # Fixes issue with extra new line characters when CM is importing an error into the log
        If($logContent -like '<!`[LOG`[*') {
            $logContent = $logContent -replace '(?<!">)\r\n',"`n"
        }

        $logContent = $logContent.trim()

        $logArray = $logContent -split "`r" | Where-Object { $_ -ne "ROLLOVER" }

        $bValidCMLog = $true
        ForEach($entry in $logArray) {
            If(-Not($rxValidCM.IsMatch($entry)) -and -not($rxValidCMSimple.IsMatch($entry))) {
                $bValidCMLog = $false
            }
        }

        $bValidCMLog | Should -Be $true
    }

    It "Import and Sanitization Test on <_>" -TestCases $logFiles {
        $log = Import-LogSloth -LogFile $_ -SkipWarning
        
        # Something should be returned
        $log | Should -Be $true

        # Log Type should be SCCM or SCCMSimple
        $log.LogType | Should -BeIn @("SCCM","SCCMSIMPLE")
    }
}