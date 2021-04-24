# Import-LogSloth Function

This function is used to import a log file into PowerShell for manipulation or viewing.

There are three ways to import a log file:

- Importing from a file
- Importing from an existing variable
- Importing from the pipeline

These three methods are shown in the sample below.

```
# Import from a File
$log = Import-LogSloth -LogFile ExecMgr.log

# Import from an existing variable
$someVar = Get-Content ExecMgr.log -Raw
$log = Import-LogSloth -LogData $someVar

# Import from the pipeline
Get-Content ExecMgr.log -Raw | Import-LogSloth
```

In all scenarios, the following properties will be made available to you:

Property|Purpose
-|-
LogData|An array of objects, where each item in the array is a line of your log file, and each object contains all of the fields of those lines.
LogDataRaw|The original text parsed from the log file.
LogFormatting|Formatting rules that will be applied to your log if exported (more on this on **THIS PAGE**)
LogType|The type of log file that was detected (e.g. SCCM, CSV)

# Log Headers

If importing a CSV or TSV file, you can use the `LogHeaders` parameter to define the headers for each column of data.  If you do not define this parameter, it will be assumed that the first row of data within the log file contains the headers.

Headers should be supplied as an array and can be used like so:

```
$log = Import-LogSloth -LogFile AppExport.csv -Headers @("DateTime","LogText","Component")
```

## Log Formatting

LogSloth has built in rules for formatting warnings and error messages within log files for when they are exported to another format (see [ConvertTo-LogSlothHTML](convertto-logslothhtml.md) and [Export-LogSloth](export-logsloth.md)). **LINK TEST**

To skip creating formatting rules, call the function like so:

```
$log = Import-LogSloth -LogFile ExecMgr.log -SkipFormatting
```

If you'd like to create your own formatting rules for the log file (replacing the built-in ones), you can do so by passing an array of rules.  Each rule must be a hash table that defines the lookup rule, and then either or both of a TextColor and BackgroundColor.

The following example shows how to create two rules to format your log output.  Note that the lookup rule is in RegEx format, but don't let that scare you away from creating the rules, basic ones are quite simple.

```
# Create a new ArrayList to store your rules

$Rules = [System.Collections.ArrayList]::New()

# Create a new rule so that if it finds the letters "error" on a line in the log, it'll color the text Red.  The text `(?i)` simply means this is case-insensitive.

$errorRule = @{
    Lookup = "(?i)Error"
    TextColor = "Red"
}

# Create another rule so that if it finds the letters "warning" on a line, it'll change the background to yellow.

$warningRule = @{
    Lookup = "(?i)Warning"
    BackgroundColor = "Yellow"
}

# Add these two rules to the array
[void]$Rules.Add($errorRule)
[void]$Rules.Add($warningRule)
```

Now that you have an array with your custom rules, you can pass it to your import:

```
$log = Import-LogSloth -LogFile ExecMgr.log -LogFormatting $Rules
```

Remember, these rules only apply when exporting or converting your log file.

Tip: All of the colors available to PowerShell (or perhaps more specifically, to .NET) can be used.  For a list of available colors, see [this page](https://docs.microsoft.com/en-us/dotnet/api/system.windows.media.brushes?redirectedfrom=MSDN&view=net-5.0).
```


## Pre-Release Warnings
In pre-release versions of LogSlothParser, a warning will be generated when you call `Import-LogSloth` that the module you're using is in beta.  To suppress this warning, call LogSloth as follows:

```
Import-LogSloth -LogFile ExecMgr.log -SkipWarning
```
