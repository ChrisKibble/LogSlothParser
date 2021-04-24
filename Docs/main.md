# LogSloth Parser Module Documentation

This page will attempt to outline the most basic uses of the module.  For more in-depth views into each of the functions, including some advanced parameters, see the additional documentation linked to below.

All examples below assume you've already installed the LogSlothParser module (see the [readme](../README.md) if you haven't) and that you've imported the module into your current session (or it's been imported automatically) using a command such as:

```
Import-Module LogSlothParser
```

## Doc Pages Available

- [Import-LogSloth](import-logsloth.md)
- [Import-LogSlothSanitized](import-logslothsanitized.md)
- [Get-LogSlothType](get-logslothtype.md)
- [ConvertTo-LogSlothHTML](convertto-logslothhtml.md)
- [Export-LogSlothLog](export-logslothlog.md)

## Importing a Log

The `Import-LogSloth` command can be used to import a log file or log text. The log will be parsed and returned as a special class that you can use to explore the data within the log.

### Sample Usage

There are two main ways to import log data:

```
# Create $Log Variable and Import Log 
$log = Import-LogSloth -LogFile ExecMgr.log
```

```
# Create $Log Variable from data in memory
$fileContent = Get-Content ExecMgr.Log
# <Do something with the data if you please>
$log = Import-LogSloth -LogData $fileContent
```

In both scenarios, you'll be able to view your Log File by viewing `$log.LogData`, which you could output to the console, or to a grid, like so:

```
$log.LogData | Out-GridView
```

The LogData property is one of many properties you'll have available to view, for the full list, see [import-logsloth](import-logsloth.md).

## Using the Sanitization Capabilities

You can sanitize your log data using rules built into the parser to filter out common private information. For a list of all potential options, see **THIS PAGE**.  Below are basic samples only.

You can use the `Import-LogSlothSanitized` function similarly to how you use the `Import-LogSloth` function above. That is, you can import a log file directly, or using data already imported into PowerShell.

```
# Create $Log Variable and Import Log 
$log = Import-LogSlothSanitized -LogFile ExecMgr.log
```

```
# Create $Log Variable from data in memory
$fileContent = Get-Content ExecMgr.Log
# <Do something with the data if you please>
$log = Import-LogSlothSanitized -LogData $fileContent
```

A third method available is to import a LogObject is already in memory, like so:

```
# Create $Log Variable and Import Log 
$log = Import-LogSlothSanitized -LogFile ExecMgr.log
$log = Import-LogSlothSanitized -LogObject $log
```

Regardless of which method you use, you'll get your `$log` variable will return the same properties as when using `Import-LogSloth`, plus these additional properties:

- LogData - A sanitized array of objects, where each item in the array is a line of your log file, and each object contains all of the fields of those lines.
- LogDataUnsanitized - The pre-sanitizied version of your log.
- SanitizedReplacements - The content that was replaced in the sanitized output of your log data
- SantitizeType - The rules used to sanitize the log file (see [Import-LogSlothSanitized](import-logslothsanitized.md) for more information)