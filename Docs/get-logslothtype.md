# Get-LogSlothType Function

This function is used to determine what type of log that LogSloth things a specific file is.  It's used internally to build sanitization rules during import, but can also be used by module users.

## Sample Usage

```
# Check File Directly
Get-LogSlothType -LogFile ExecMgr.log

# Check Data in Memory
$someVar = Get-Content ExecMgr.log -Raw
Get-LogSlothType -LogData $someVar
```

## Pre-Release Warnings
In pre-release versions of LogSlothParser, a warning will be generated when you call `Get-LogSlothType` that the module you're using is in beta.  To suppress this warning, call LogSloth as follows:

```
Get-LogSlothType -LogFile ExecMgr.log -SkipWarning
```
