[CmdletBinding()]
Param(
	[string]$Target = "Default",
    [Parameter(Position=0,Mandatory=$false,ValueFromRemainingArguments=$true)]
    [string[]]$ScriptArgs
)

Write-Host "Running Cake bootstrapper with target '$Target'..."
try
{
	Invoke-Expression "& ./bootstrapper.ps1 -target $Target $ScriptArgs"
}
catch 
{
	throw "Error when building"
}
exit $LASTEXITCODE