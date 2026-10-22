# Read-only hardware inventory. No network access and no credentials.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$exitCode = 0

$localDir = Join-Path $env:ProgramData 'CorpInventory\RAM'
# KSC versions use both forms in UI/documentation.
$diagDirs = @(
    $env:KLACDT_SAVE_SETTINGS
    $env:KLACDT_SAVE_SETTING
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique


function Write-Utf8NoBomFile {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText(
        $Path, $Text, (New-Object System.Text.UTF8Encoding($false))
    )
}

try {
    New-Item -ItemType Directory -Path $localDir -Force | Out-Null
    $computerName = $env:COMPUTERNAME.ToUpperInvariant()
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $modules = @(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop)
    if ($modules.Count -eq 0) {
        throw 'Win32_PhysicalMemory did not return any physical memory modules.'
    }

    $items = @(
        foreach ($module in $modules) {
            $typeCode = [int]$module.SMBIOSMemoryType
            $typeName = switch ($typeCode) {
                20 {'DDR'}
                21 {'DDR2'}
                24 {'DDR3'}
                26 {'DDR4'}
                34 {'DDR5'}
                35 {'LPDDR5'}
                default { if ($typeCode -gt 0) { "SMBIOS-$typeCode" } else { 'Unknown' } }
            }
            [ordered]@{
                Slot          = [string]$module.DeviceLocator
                Bank          = [string]$module.BankLabel
                Manufacturer  = ([string]$module.Manufacturer).Trim()
                PartNumber    = ([string]$module.PartNumber).Trim()
                CapacityGiB   = [math]::Round(([double]$module.Capacity / 1GB), 2)
                MemoryType    = $typeName
                SpeedMTs      = [int]$module.Speed
                ConfiguredMTs = [int]$module.ConfiguredClockSpeed
            }
        }
    )

    $sumBytes = ($modules | Measure-Object -Property Capacity -Sum).Sum
    $report = [ordered]@{
        ComputerName = $computerName
        CollectedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        TotalRAMGiB = [math]::Round(([double]$sumBytes / 1GB), 2)
        Modules     = $items
    }
    $json = ConvertTo-Json -InputObject $report -Depth 6
    $fileName = "ram-$computerName-$stamp.json"
    $localPath = Join-Path $localDir $fileName
    Write-Utf8NoBomFile -Path $localPath -Text $json

    $summary = "OK computer=$computerName modules=$($modules.Count) totalGiB=$($report.TotalRAMGiB) local=$localPath"
    Write-Output $summary

    foreach ($diagDir in $diagDirs) {
        if (-not (Test-Path -LiteralPath $diagDir -PathType Container)) {
            Write-Warning "KSC results directory is not available: $diagDir"
            continue
        }
        Write-Utf8NoBomFile -Path (Join-Path $diagDir $fileName) -Text $json
        Write-Utf8NoBomFile -Path (Join-Path $diagDir 'ram-collection-status.txt') -Text $summary
        Write-Output "KSC_RESULT_DIRECTORY=$diagDir"
    }
    Write-Output "RAM_JSON_BEGIN"
    Write-Output $json
    Write-Output "RAM_JSON_END"
} catch {
    $exitCode = 1
    $message = "ERROR computer=$($env:COMPUTERNAME) type=$($_.Exception.GetType().Name) message=$($_.Exception.Message)"
    [Console]::Error.WriteLine($message)
    try {
        if (Test-Path -LiteralPath $localDir -PathType Container) {
            Write-Utf8NoBomFile -Path (Join-Path $localDir 'ram-collection-error.txt') -Text $message
        }
        foreach ($diagDir in $diagDirs) {
            if (Test-Path -LiteralPath $diagDir -PathType Container) {
                Write-Utf8NoBomFile -Path (Join-Path $diagDir 'ram-collection-error.txt') -Text $message
            }
        }
    } catch { }
}
exit $exitCode
