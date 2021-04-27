Import-Module $PSScriptRoot\..\LogSlothParser\LogSlothParser.psd1 -Force

BeforeAll {
    $csvFile = $(Resolve-Path "$PSScriptRoot\..\LogSamples\CSV\Cities.csv").Path
}

Describe "Ensure CSV Log Files Import Successfully" {

    It "Validate CSV Import Works as Expected Importing File"  {
        $log = Import-LogSloth -LogFile $csvFile -SkipWarning
        $log.logData[0].'%%LineNo' | Should -BeExactly 1
        $log.logData.count | Should -BeExactly 128
        $log.logType | Should -Be "CSV"
    }

    It "Validate CSV Import Works as Expected Importing Data" {
        $logData = Get-Content $csvFile -Raw
        $log = Import-LogSLoth -LogData $logData -SkipWarning
        $log.logData[0].'%%LineNo' | Should -BeExactly 1
        $log.logData.count | Should -BeExactly 128
        $log.logType | Should -Be "CSV"
    }

    It "Validate CSV Import Works as Expected Importing Data from Pipeline" {
        $logData = Get-Content $csvFile -Raw
        $log = $logData | Import-LogSloth -SkipWarning
        $log.logData[0].'%%LineNo' | Should -BeExactly 1
        $log.logData.count | Should -BeExactly 128
        $log.logType | Should -Be "CSV"
    }

    It "Validate CSV Sanitization Import Works as Expected Importing File"  {
        $log = Import-LogSlothSanitized -LogFile $csvFile -SkipWarning
        $log.logData[0].'%%LineNo' | Should -BeExactly 1
        $log.logData.count | Should -BeExactly 128
        $log.logType | Should -Be "CSV"
    }

    It "Validate CSV Sanitized Import Works as Expected Importing Data" {
        $logData = Get-Content $csvFile -Raw
        $log = Import-LogSLothSanitized -LogData $logData -SkipWarning
        $log.logData[0].'%%LineNo' | Should -BeExactly 1
        $log.logData.count | Should -BeExactly 128
        $log.logType | Should -Be "CSV"
    }

    It "Validate CSV Sanitized Import Works as Expected Importing Data from Pipeline" {
        $logData = Get-Content $csvFile -Raw
        $log = $logData | Import-LogSlothSanitized -SkipWarning
        $log.logData[0].'%%LineNo' | Should -BeExactly 1
        $log.logData.count | Should -BeExactly 128
        $log.logType | Should -Be "CSV"
    }

    It "Validate CSV Sanitization Import Works as Expected Importing Class"  {
        $log = Import-LogSloth -LogFile $csvFile -SkipWarning
        $log = Import-LogSlothSanitized -LogObject $log -skipWarning
        $log.logData[0].'%%LineNo' | Should -BeExactly 1
        $log.logData.count | Should -BeExactly 128
        $log.logType | Should -Be "CSV"
    }

}