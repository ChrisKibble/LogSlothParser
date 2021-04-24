# ConvertTo-LogSlothHTML Function

This function is used to convert a log object into an HTML page. The value passed to this function must be a log object created by `Import-LogSloth` or `Import-LogSlothSanitized`, you cannot pass a file or file data to this function.

This function returns the raw HTML that you can save to a file. If you aren't going to manipulate the data before exporting, you can use [Export-LogSlothLog](export-logslothlog.md) with the `-HTML` parameter instead to get the same result.

## Sample Usage

```
# Pass log using parameter name
$log = Import-LogSloth -LogFile ExecMgr.log
$html = ConvertTo-LogSlothHTML -LogObject $log

# Pass via the pipeline
$log = Import-LogSloth -LogFile ExecMgr.log
$html = $log | ConvertTo-LogSlothHTML
```

## Including the raw log

If you'd like to include the text content of the original log file in the HTML at the bottom (in a textbox), use the `-IncludeRawLog` parameter. If the log has been sanitized, it will be the sanitized data included in the output and not the original content.

```
$log = Import-LogSloth -LogFile ExecMgr.log
$html = ConvertTo-LogSlothHTML -LogObject $log -IncludeRawLog
```

## Pre-Release Warnings
In pre-release versions of LogSlothParser, a warning will be generated when you call `ConvertTo-LogSlothHTML` that the module you're using is in beta.  To suppress this warning, call LogSloth as follows:

```
$log | ConvertTo-LogSlothHTML -SkipWarning
```
