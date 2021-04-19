Describe "Ensure MEMCM Log Files Import Successfully" {

    $logFiles = Get-ChildItem "$PSScriptRoot\..\LogSamples\MEMCM" -Exclude ".*" -Recurse

    It "Pre-Import Verification on <_.FullName>" -TestCases $logFiles {  
        $rxValidCM = [regex]::New('(?msi)^<!\[LOG\[(?:.*?)]LOG]!><time="(?:.*?)" date="(?:.*?)" component="(?:.*?)" context="(?:.*?)" type="(?:.*?)" thread="(?:.*?)" file="(?:.*?)">$')    
        $rxValidCMSimple = [regex]::New('(.*?) \$\$<(.*?)><(.*?)><thread=(.*?)>')

        $logContent = Get-Content $_.FullName -Raw

        # Fixes issue with extra new line characters when CM is importing an error into the log
        If($logContent -like '<!`[LOG`[*') {
            $logContent = $logContent -replace '(?<!">)\r\n',"`n"
        }

        $logContent = $logContent.trim()

        $logArray = $logContent -split "`r"

        $bValidCMLog = $true
        ForEach($entry in $logArray) {
            If(-Not($rxValidCM.IsMatch($entry)) -and -not($rxValidCMSimple.IsMatch($entry))) {
                $bValidCMLog = $false
            }
        }

        $bValidCMLog | Should -Be $true
    }
}