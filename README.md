# LogSlothParser

LogSloth Parser aims to import a variety of log files (e.g. SCCM, CSV, Text Based, etc.) and convert them into a normalized PowerShell Object for easy referencing.  

Additionally, this module works to sanitize log inputs so that the logs can be safely shared online. This is a work in progress and could never possibly account for all situations - review your logs carefully before sharing them anywhere public.

Eventually, this module will replace the code currently running the [LogSloth Website](https://www.logsloth.com/).

# Installation Instructions

The latest release of this module will be maintained in the [PowerShellGallary](https://www.powershellgallery.com/packages/LogSlothParser/).

To Install, you can use the `Install-Module` function within PowerShell.  PowerShell version 5.1 or greater (including core) are supported.

```
Install-Module -Name LogSlothParser -AllowPrerelease	
```

This module has been tested on PowerShell versions up through v7.1.3, however future versions should work as well.
