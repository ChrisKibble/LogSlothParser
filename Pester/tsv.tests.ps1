Import-Module $PSScriptRoot\..\LogSlothParser\LogSlothParser.psd1 -Force

BeforeAll {
    $TSVFile = $(Resolve-Path "$PSScriptRoot\..\LogSamples\TSV\Random.tsv").Path
}
Describe "Ensure TSV Log Files Import Successfully" {
    
    It "Validate TSV Import Works as Expected Importing File"  {          
        Write-Host $TSVFile
        $log = Import-LogSloth -LogFile $TSVFile -SkipWarning
        $log.logData.count | Should -BeExactly 5
        $log.logType | Should -Be "TSV"
    }

    It "Validate TSV Import Works as Expected Importing Data" {
        $logData = Get-Content $TSVFile -Raw
        $log = Import-LogSLoth -LogData $logData -SkipWarning
        $log.logData.count | Should -BeExactly 5    
        $log.logType | Should -Be "TSV"
    }

    It "Validate TSV Import Works as Expected Importing Data from Pipeline" {
        $logData = Get-Content $TSVFile -Raw
        $log = $logData | Import-LogSloth -SkipWarning
        $log.logData.count | Should -BeExactly 5    
        $log.logType | Should -Be "TSV"
    }

    It "Validate TSV Sanitization Import Works as Expected Importing File"  {          
        $log = Import-LogSlothSanitized -LogFile $TSVFile -SkipWarning
        $log.logData.count | Should -BeExactly 5    
        $log.logType | Should -Be "TSV"
    }

    It "Validate TSV Sanitized Import Works as Expected Importing Data" {
        $logData = Get-Content $TSVFile -Raw
        $log = Import-LogSLothSanitized -LogData $logData -SkipWarning
        $log.logData.count | Should -BeExactly 5    
        $log.logType | Should -Be "TSV"
    }

    It "Validate TSV Sanitized Import Works as Expected Importing Data from Pipeline" {
        $logData = Get-Content $TSVFile -Raw
        $log = $logData | Import-LogSlothSanitized -SkipWarning
        $log.logData.count | Should -BeExactly 5    
        $log.logType | Should -Be "TSV"
    }

    It "Validate TSV Sanitization Import Works as Expected Importing Class"  {          
        $log = Import-LogSloth -LogFile $TSVFile -SkipWarning
        $log = Import-LogSlothSanitized -LogObject $log -skipWarning
        $log.logData.count | Should -BeExactly 5    
        $log.logType | Should -Be "TSV"
    }

}