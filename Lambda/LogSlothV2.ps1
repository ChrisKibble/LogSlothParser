
# PowerShell script file to be executed as a AWS Lambda function. 
# 
# When executing in Lambda the following variables will be predefined.
#   $LambdaInput - A PSObject that contains the Lambda function input data.
#   $LambdaContext - An Amazon.Lambda.Core.ILambdaContext object that contains information about the currently running Lambda environment.
#
# The last item in the PowerShell pipeline will be returned as the result of the Lambda function.
#
# To include PowerShell modules with your Lambda function, like the AWS.Tools.S3 module, add a "#Requires" statement
# indicating the module and version. If using an AWS.Tools.* module the AWS.Tools.Common module is also required.

#Requires -Modules @{ModuleName='AWS.Tools.Common';ModuleVersion='4.1.10.0'}
#Requires -Modules LogSlothParser

Try {
    Import-Module LogSlothParser -ErrorAction Stop -Force
    
    # This is required because Lambda adds a Param block to the top of the code automatically
    # and 'using' needs to be at the top.  Thanks Chris Dent! :)
    Invoke-Expression 'using module LogSlothParser'
} Catch {
    Throw "Cannot Load LogSlothParser Module"
}

Function Send-Response {
	
    Param(
        [int]$statusCode,
        [hashtable]$headers = @{"content-type"="text/plain"},
        [string]$body
    )
    
    Write-Host "Returning Status Code $statusCode"

    <#
    @{
	    "statusCode" = $statusCode
	    "body" = $bodys
	    "headers" = $headers
	}
    #>

    @{
	    "isBase64Encoded" = $false
        "statusCode" = $statusCode
	    "body" = $body
	    "headers" = $headers
	} 

	Exit
}

<#
# Dump Debugging Information for Testing
Write-Host "Lambda Input"
Write-Host (ConvertTo-Json -InputObject $LambdaInput -Compress -Depth 5)
Write-Host "Lambda Event"
Write-Host (ConvertTo-Json -InputObject $LambdaEvent -Compress -Depth 5)
#>

# Allow local ParamBody and Resource to be set for testing locally
if($env:parambody) {
    $LambdaInput = @{
        "Resource" = $env:paramresource
        "Body" = $env:parambody
    }
}

If(-Not($LambdaInput)) {
    Throw "No Lambda Data"
}

<#
# Dump Debugging Information for Testing
Write-Host "Input is $($LambdaInput)"
Write-Host "Resource: $($LambdaInput.Resource)"
Write-Host "Body Length: $($LambdaInput.Body.Length)"
#>

$data = $lambdaInput.Body
$logType = Get-LogSlothType -logData $data -SkipWarning

if($logType -eq [LogType]::Nothing) {
    Send-Response -StatusCode 400 -headers @{ "Content-Type" = "text/plain" } -body "Unable to determine log type. Sorry."
}

Switch($LambdaInput.Resource) {
    "/log2json" {
        $logObject = Import-LogSloth -logData $data -SkipWarning
        Send-Response -statusCode 200 -headers @{ "content-type" = "application/json"; "LogSloth-LogType" = $logType } -body $($logObject.LogData | ConvertTo-Json -Depth 100)
        break
    }
    "/log2sanitizedjson" {
        $logObject = Import-LogSlothSanitized -logData $data -SkipWarning
        Send-Response -statusCode 200 -headers @{ "content-type" = "application/json"; "LogSloth-LogType" = $logType } -body $($logObject.LogData | ConvertTo-Json -Depth 100)
        break
    }
    "/log2html" {
        $logObject = Import-LogSloth -LogData $data -SkipWarning
        $logHTML = $logObject | ConvertTo-LogSlothHTML -SkipWarning -IncludeRawLog
        Send-Response -statusCode 200 -headers @{ "content-type" = "text/html"; "LogSloth-LogType" = $logType } -body $logHTML
    }
    "/log2sanitizedhtml" {
        $logObject = Import-LogSlothSanitized -LogData $data -SkipWarning
        $logHTML = $logObject | ConvertTo-LogSlothHTML -SkipWarning -IncludeRawLog
        Send-Response -statusCode 200 -headers @{ "content-type" = "text/html"; "LogSloth-LogType" = $logType } -body $logHTML
    }
    default {
        Send-Response -statusCode 400 -headers @{ "debug-logsloth-bad-resource" = $LambdaInput.Resource } -body "I don't know what that resource is."
        break
    }
}
