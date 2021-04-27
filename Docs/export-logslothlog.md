# Export-LogSlothLog Function

This function is used to export a log in another format for better viewing or sharing.  Currently, this function only supports HTML export.

The value passed to this function must be a log object created by `Import-LogSloth` or `Import-LogSlothSanitized`, you cannot pass a file or file data to this function.

## Note on External Resources

The HTML output of this function uses Javascript resources from various CDNs (specifically, at this time, jQuery and DataTables).  You will need Internet access to properly load these files. If there's a need for it, I may allow the user to point to local files, or use a simpler table export without all of the bells and whistles, at some point in the future.

## Sample Usage

```
# Pass log using parameter name
$log = Import-LogSloth -LogFile ExecMgr.log
Export-LogSlothLog -LogObject $log -Path Log.html -Format HTML

# Pass via the pipeline
$log = Import-LogSloth -LogFile ExecMgr.log
$log | Export-LogSlothLog -Path Log.html -Format HTML
```

## Including the raw log

If you'd like to include the text content of the original log file, use the `-IncludeRawLog` parameter. If the log has been sanitized, it will be the sanitized data included in the output and not the original content.

```
$log = Import-LogSloth -LogFile ExecMgr.log
$log | Export-LogSlothLog -Path Log.html -Format HTML -IncludeRawLog
```

## Overwriting (Clobbering) Existing Files

By default, this function will throw an error if the file specified by the `-Path` parameter already exists.  To overwrite an existing file, use the `-Force` parameter.

```
$log = Import-LogSloth -LogFile ExecMgr.log
$log | Export-LogSlothLog -Path Log.html -Format HTML -Force
```

## Pre-Release Warnings
In pre-release versions of LogSlothParser, a warning will be generated when you call `Export-LogSlothLog` that the module you're using is in beta.  To suppress this warning, call LogSloth as follows:

```
$log | Export-LogSlothLog -Path Log.html -Format HTML -SkipWarning
```
