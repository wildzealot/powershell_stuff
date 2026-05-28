<#
.SYNOPSIS
    UAL Parser v2.5 - Robust M365 Unified Audit Log Parser

.DESCRIPTION
    Parses M365 UAL exports (CSV or XLSX), extracts nested JSON from AuditData,
    and exports comprehensive Excel workbook with operation-specific sheets.
    Features clickable navigation hyperlinks, inbox rule parsing with rule logic,
    SessionId/UserAgent/ALL_IPs IOC columns propagated to every sheet,
    and full MailItemsAccessed InternetMessageId extraction across all Folders/FolderItems.

.PARAMETER InputFile
    Path to UAL file (CSV or XLSX)

.PARAMETER OutputFile
    Output Excel path (optional - defaults to InputFile_PARSED.xlsx)

.EXAMPLE
    .\Parse-UAL.ps1 -InputFile "C:\Exports\UAL_Export.xlsx"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$InputFile,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile
)

$ErrorActionPreference = "Continue"
$startTime = Get-Date

#region Initialization
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "UAL PARSER v2.5" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan

# Validate input file
if (-not (Test-Path $InputFile)) {
    Write-Error "File not found: $InputFile"
    exit 1
}

# Setup output paths
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($InputFile)
$baseDir  = [System.IO.Path]::GetDirectoryName($InputFile)
if ([string]::IsNullOrEmpty($baseDir)) { $baseDir = Get-Location }

if (-not $OutputFile) {
    $OutputFile = Join-Path $baseDir "$($baseName)_PARSED.xlsx"
}
$debugLog = Join-Path $baseDir "$($baseName)_DEBUG.txt"

# Initialize debug log
@"
========================================
UAL PARSER v2.5 DEBUG LOG
========================================
Started: $startTime
PowerShell: $($PSVersionTable.PSVersion)
Input: $InputFile
Output: $OutputFile
========================================

"@ | Out-File $debugLog -Force

function Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "HH:mm:ss.fff"
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $debugLog -Value $line

    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "DEBUG" { "DarkGray" }
        default { "Gray" }
    }
    Write-Host $line -ForegroundColor $color
}

Log "Script initialized"

# Ensure ImportExcel module
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Log "Installing ImportExcel module..." "WARN"
    try {
        Install-Module -Name ImportExcel -Force -Scope CurrentUser -ErrorAction Stop
        Log "ImportExcel installed successfully"
    } catch {
        Log "Failed to install ImportExcel: $($_.Exception.Message)" "ERROR"
        exit 1
    }
}
Import-Module ImportExcel -ErrorAction Stop
Log "ImportExcel module loaded"
#endregion

#region Load Data
Log "Loading data from file..."

$records = $null
$fileExt = [System.IO.Path]::GetExtension($InputFile).ToLower()

try {
    if ($fileExt -eq ".xlsx" -or $fileExt -eq ".xls") {
        Log "Detected Excel format, using Import-Excel..."
        $records = Import-Excel -Path $InputFile -ErrorAction Stop
        Log "Loaded $($records.Count) records from Excel"
    } else {
        Log "Detected CSV format, using Import-Csv..."
        try {
            $records = Import-Csv -Path $InputFile -Encoding UTF8 -ErrorAction Stop
        } catch {
            $records = Import-Csv -Path $InputFile -ErrorAction Stop
        }
        Log "Loaded $($records.Count) records from CSV"
    }
} catch {
    Log "Failed to load file: $($_.Exception.Message)" "ERROR"
    exit 1
}

if ($null -eq $records -or $records.Count -eq 0) {
    Log "No records loaded from file!" "ERROR"
    exit 1
}

$totalRecords = $records.Count
Log "Total records: $totalRecords"

# Identify columns
$firstRecord = $records[0]
$columns     = @($firstRecord.PSObject.Properties.Name)
Log "Columns found ($($columns.Count)): $($columns -join ', ')"

# Log sample of first record
Log "=== FIRST RECORD SAMPLE ===" "DEBUG"
foreach ($col in $columns) {
    $val = $firstRecord.$col
    if ($null -ne $val) {
        $str     = [string]$val
        $preview = if ($str.Length -gt 100) { $str.Substring(0, 100) + "..." } else { $str }
        Log "  $col = $preview" "DEBUG"
    } else {
        Log "  $col = [NULL]" "DEBUG"
    }
}
Log "=== END SAMPLE ===" "DEBUG"

# Verify AuditData column exists
$auditDataColumn = $columns | Where-Object { $_ -eq "AuditData" } | Select-Object -First 1
if ($auditDataColumn) {
    Log "AuditData column found: '$auditDataColumn'"
} else {
    Log "WARNING: AuditData column not found! Available columns: $($columns -join ', ')" "WARN"
    foreach ($col in $columns) {
        $val = $firstRecord.$col
        if ($val -and [string]$val -match '^\s*\{') {
            Log "Found JSON-like data in column '$col'" "WARN"
            $auditDataColumn = $col
            break
        }
    }
}
#endregion

#region JSON Parsing Functions
function Flatten-JsonObject {
    param(
        $Object,
        [string]$Prefix   = "",
        [int]$Depth        = 0,
        [int]$MaxDepth     = 10
    )

    $result = @{}

    if ($Depth -ge $MaxDepth -or $null -eq $Object) {
        return $result
    }

    # Handle arrays
    if ($Object -is [System.Array]) {
        for ($i = 0; $i -lt $Object.Count; $i++) {
            $key = if ($Prefix) { "${Prefix}[$i]" } else { "[$i]" }
            $sub = Flatten-JsonObject -Object $Object[$i] -Prefix $key -Depth ($Depth + 1) -MaxDepth $MaxDepth
            foreach ($k in $sub.Keys) { $result[$k] = $sub[$k] }
        }
        if ($Prefix -and $Object.Count -gt 0) {
            $result["${Prefix}_Count"] = $Object.Count
        }
        return $result
    }

    # Handle PSCustomObject (parsed JSON)
    if ($Object -is [PSCustomObject]) {
        foreach ($prop in $Object.PSObject.Properties) {
            $key = if ($Prefix) { "${Prefix}.$($prop.Name)" } else { $prop.Name }

            if ($null -eq $prop.Value) {
                $result[$key] = $null
            } elseif ($prop.Value -is [PSCustomObject] -or $prop.Value -is [System.Array]) {
                $sub = Flatten-JsonObject -Object $prop.Value -Prefix $key -Depth ($Depth + 1) -MaxDepth $MaxDepth
                foreach ($k in $sub.Keys) { $result[$k] = $sub[$k] }
            } else {
                $result[$key] = $prop.Value
            }
        }
        return $result
    }

    # Primitive value
    if ($Prefix) {
        $result[$Prefix] = $Object
    }

    return $result
}

function Parse-AuditDataJson {
    param([string]$JsonString)

    $result = @{}

    if ([string]::IsNullOrWhiteSpace($JsonString)) {
        return $result
    }

    try {
        $parsed = ConvertFrom-Json -InputObject $JsonString -ErrorAction Stop
        $result = Flatten-JsonObject -Object $parsed
    } catch {
        $result["_ParseError"] = $_.Exception.Message
    }

    return $result
}

function Resolve-SessionId {
    <#
    .SYNOPSIS
        Extracts SessionId from all known UAL AuditData locations.
        Returns the first non-empty value found, searching in priority order.
    #>
    param([hashtable]$FlatJson)

    if ($null -eq $FlatJson -or $FlatJson.Count -eq 0) { return $null }

    # 1. Top-level SessionId (Exchange mailbox audit records)
    $val = $FlatJson["SessionId"]
    if (-not [string]::IsNullOrWhiteSpace($val)) { return $val }

    # 2. ExtendedProperties array - Name/Value pairs (AzureAD / login events)
    $epCount = $FlatJson["ExtendedProperties_Count"]
    if ($epCount -and $epCount -gt 0) {
        for ($i = 0; $i -lt $epCount; $i++) {
            $name = $FlatJson["ExtendedProperties[$i].Name"]
            if ($name -and $name -match '^(SessionId|RequestId)$') {
                $epVal = $FlatJson["ExtendedProperties[$i].Value"]
                if (-not [string]::IsNullOrWhiteSpace($epVal)) { return $epVal }
            }
        }
    }

    # 3. DeviceProperties array - same Name/Value pattern
    $dpCount = $FlatJson["DeviceProperties_Count"]
    if ($dpCount -and $dpCount -gt 0) {
        for ($i = 0; $i -lt $dpCount; $i++) {
            $name = $FlatJson["DeviceProperties[$i].Name"]
            if ($name -and $name -match '^(SessionId|RequestId)$') {
                $dpVal = $FlatJson["DeviceProperties[$i].Value"]
                if (-not [string]::IsNullOrWhiteSpace($dpVal)) { return $dpVal }
            }
        }
    }

    # 4. AppAccessContext.AADSessionId (MailItemsAccessed / Exchange workload records)
    #    These records carry no top-level SessionId; the session GUID lives here.
    $val = $FlatJson["AppAccessContext.AADSessionId"]
    if (-not [string]::IsNullOrWhiteSpace($val)) { return $val }

    return $null
}

function Resolve-AllIPs {
    <#
    .SYNOPSIS
        Coalesces all IP addresses for a record into a single semicolon-delimited string.
        Checks top-level ClientIP, ClientIPAddress, ActorIpAddress, and
        ExtendedProperties Name=clientIP / clientIpAddress entries.
        Returns deduplicated, non-empty values joined with "; ".
    #>
    param([hashtable]$FlatJson)

    if ($null -eq $FlatJson -or $FlatJson.Count -eq 0) { return $null }

    $ips = [System.Collections.Generic.List[string]]::new()

    # Helper: add if non-empty and not already present
    $addIp = {
        param([string]$ip)
        $ip = $ip.Trim()
        if (-not [string]::IsNullOrWhiteSpace($ip) -and -not $ips.Contains($ip)) {
            $ips.Add($ip)
        }
    }

    # 1. Top-level fields
    foreach ($field in @("ClientIP", "ClientIPAddress", "ActorIpAddress")) {
        $v = $FlatJson[$field]
        if ($v) { & $addIp ([string]$v) }
    }

    # 2. ExtendedProperties Name/Value pairs
    $epCount = $FlatJson["ExtendedProperties_Count"]
    if ($epCount -and $epCount -gt 0) {
        for ($i = 0; $i -lt $epCount; $i++) {
            $epName = $FlatJson["ExtendedProperties[$i].Name"]
            if ($epName -and $epName -match '^(clientIP|clientIpAddress|ipaddr|IpAddress)$') {
                $epVal = $FlatJson["ExtendedProperties[$i].Value"]
                if ($epVal) { & $addIp ([string]$epVal) }
            }
        }
    }

    if ($ips.Count -eq 0) { return $null }
    return ($ips -join "; ")
}

function Get-MailItemsAccessedIds {
    <#
    .SYNOPSIS
        Extracts all InternetMessageIds from a MailItemsAccessed AuditData JSON.
        Handles both Bind events (FolderItems with MessageId) and
        Sync events (folder-level only, no per-message IDs).
        Returns a semicolon-delimited string of unique IDs, or $null if none found.
        Also returns the operation subtype (Bind/Sync) for the record.
    #>
    param(
        [hashtable]$FlatJson,
        [ref]$SubType
    )

    $SubType.Value = "Unknown"
    $ids = [System.Collections.Generic.List[string]]::new()

    if ($null -eq $FlatJson -or $FlatJson.Count -eq 0) { return $null }

    $folderCount = $FlatJson["Folders_Count"]
    if (-not $folderCount -or $folderCount -eq 0) { return $null }

    for ($f = 0; $f -lt $folderCount; $f++) {
        $itemCount = $FlatJson["Folders[$f].FolderItems_Count"]
        if ($itemCount -and $itemCount -gt 0) {
            # Bind event: has FolderItems with per-message data
            $SubType.Value = "Bind"
            for ($m = 0; $m -lt $itemCount; $m++) {
                $msgId = $FlatJson["Folders[$f].FolderItems[$m].InternetMessageId"]
                if ($msgId -and -not [string]::IsNullOrWhiteSpace($msgId)) {
                    $msgId = $msgId.Trim()
                    if (-not $ids.Contains($msgId)) { $ids.Add($msgId) }
                }
            }
        } else {
            # Sync event: folder-level only, no per-message IDs
            if ($SubType.Value -ne "Bind") { $SubType.Value = "Sync" }
        }
    }

    if ($ids.Count -eq 0) { return $null }
    return ($ids -join "; ")
}
#endregion

#region Main Processing
Log "Starting record processing..."

# Initialize collections
$allParsedRecords      = [System.Collections.ArrayList]::new()
$operationGroups       = @{}
$affectedItemsList     = [System.Collections.ArrayList]::new()
$mailItemsAccessedList = [System.Collections.ArrayList]::new()
$discoveredFields      = @{}
$parseErrors           = [System.Collections.ArrayList]::new()

$processedCount = 0

foreach ($record in $records) {
    $processedCount++

    if ($processedCount % 1000 -eq 0) {
        $pct = [math]::Round(($processedCount / $totalRecords) * 100, 1)
        Write-Progress -Activity "Parsing UAL Records" -Status "$processedCount / $totalRecords ($pct%)" -PercentComplete $pct
    }

    try {
        $recId         = $record.RecordId
        $creationDate  = $record.CreationDate
        $recordType    = $record.RecordType
        $operation     = $record.Operation
        $userId        = $record.UserId
        $auditDataRaw  = if ($auditDataColumn) { $record.$auditDataColumn } else { $null }

        # Parse AuditData JSON
        $parsedJson = @{}
        if ($auditDataRaw) {
            $parsedJson = Parse-AuditDataJson -JsonString ([string]$auditDataRaw)
        }

        # Track discovered fields
        foreach ($key in $parsedJson.Keys) {
            if ($key -notmatch "^_") {
                if (-not $discoveredFields.ContainsKey($key)) { $discoveredFields[$key] = 0 }
                $discoveredFields[$key]++
            }
        }

        # Fallback to JSON values if CSV columns empty
        if ([string]::IsNullOrWhiteSpace($operation))    { $operation    = $parsedJson["Operation"] }
        if ([string]::IsNullOrWhiteSpace($operation))    { $operation    = "Unknown" }
        if ([string]::IsNullOrWhiteSpace($creationDate)) { $creationDate = $parsedJson["CreationTime"] }
        if ([string]::IsNullOrWhiteSpace($userId))       { $userId       = $parsedJson["UserId"] }

        # Resolve IOC values
        $resolvedSessionId = Resolve-SessionId -FlatJson $parsedJson
        $resolvedAllIPs    = Resolve-AllIPs    -FlatJson $parsedJson
        $resolvedUserAgent = $parsedJson["UserAgent"]

        # Build comprehensive output record
        $outputRecord = [ordered]@{
            "CreationDate"   = $creationDate
            "Operation"      = $operation
            "UserId"         = $userId
            "RecordId"       = $recId
            "RecordType"     = $recordType
            "SessionId"      = $resolvedSessionId
            "ALL_IPs"        = $resolvedAllIPs
            "UserAgent"      = $resolvedUserAgent
            "Workload"       = $parsedJson["Workload"]
            "OrganizationId" = $parsedJson["OrganizationId"]
            "ResultStatus"   = $parsedJson["ResultStatus"]
            "ClientIP"       = $parsedJson["ClientIP"]
            "UserType"       = $parsedJson["UserType"]
            "UserKey"        = $parsedJson["UserKey"]
        }

        # Operation-specific fields
        switch -Wildcard ($operation) {
            "Send" {
                $outputRecord["Subject"]           = $parsedJson["Item.Subject"]
                $outputRecord["SizeInBytes"]       = $parsedJson["Item.SizeInBytes"]
                $outputRecord["Attachments"]       = $parsedJson["Item.Attachments"]
                $outputRecord["InternetMessageId"] = $parsedJson["Item.InternetMessageId"]
            }
            "MoveToDeletedItems" {
                $outputRecord["Subject"]       = $parsedJson["AffectedItems[0].Subject"]
                $outputRecord["SourceFolder"]  = $parsedJson["AffectedItems[0].ParentFolder.Path"]
                $outputRecord["AffectedCount"] = $parsedJson["AffectedItems_Count"]
                $outputRecord["DestFolder"]    = $parsedJson["DestFolder.Path"]
            }
            "*Delete*" {
                $outputRecord["Subject"]       = $parsedJson["AffectedItems[0].Subject"]
                $outputRecord["SourceFolder"]  = $parsedJson["AffectedItems[0].ParentFolder.Path"]
                $outputRecord["AffectedCount"] = $parsedJson["AffectedItems_Count"]
                $outputRecord["FileName"]      = $parsedJson["SourceFileName"]
                $outputRecord["ObjectId"]      = $parsedJson["ObjectId"]
            }
            "Create" {
                $outputRecord["Subject"] = $parsedJson["Item.Subject"]
                $outputRecord["Folder"]  = $parsedJson["Item.ParentFolder.Path"]
            }
            "*File*" {
                $outputRecord["FileName"] = $parsedJson["SourceFileName"]
                $outputRecord["FilePath"] = $parsedJson["ObjectId"]
                $outputRecord["SiteUrl"]  = $parsedJson["SiteUrl"]
                $outputRecord["FileSize"] = $parsedJson["FileSizeBytes"]
            }
            "MailItemsAccessed" {
                $subTypeRef = [ref]"Unknown"
                $msgIds = Get-MailItemsAccessedIds -FlatJson $parsedJson -SubType $subTypeRef

                $outputRecord["AccessType"]         = $subTypeRef.Value
                $outputRecord["FolderCount"]        = $parsedJson["Folders_Count"]
                $outputRecord["OperationCount"]     = $parsedJson["OperationCount"]
                $outputRecord["InternetMessageIds"] = $msgIds

                # Write dedicated MailItemsAccessed row
                $miaRow = [ordered]@{
                    "Timestamp"          = $creationDate
                    "UserId"             = $userId
                    "SessionId"          = $resolvedSessionId
                    "ALL_IPs"            = $resolvedAllIPs
                    "UserAgent"          = $resolvedUserAgent
                    "ClientIP"           = $parsedJson["ClientIP"]
                    "AccessType"         = $subTypeRef.Value
                    "FolderCount"        = $parsedJson["Folders_Count"]
                    "OperationCount"     = $parsedJson["OperationCount"]
                    "InternetMessageIds" = $msgIds
                    "RecordId"           = $recId
                }
                [void]$mailItemsAccessedList.Add([PSCustomObject]$miaRow)
            }
            "*Login*" {
                $outputRecord["LogonType"]  = $parsedJson["LogonType"]
                $outputRecord["LogonError"] = $parsedJson["LogonError"]
            }
            "*DLP*" {
                $outputRecord["PolicyName"] = $parsedJson["PolicyDetails[0].PolicyName"]
                $outputRecord["RuleName"]   = $parsedJson["PolicyDetails[0].Rules[0].RuleName"]
                $outputRecord["Severity"]   = $parsedJson["PolicyDetails[0].Rules[0].Severity"]
            }
            { $_ -match "InboxRule" } {
                $ruleParams = @{}
                $paramCount = $parsedJson["Parameters_Count"]
                if ($paramCount -and $paramCount -gt 0) {
                    for ($p = 0; $p -lt $paramCount; $p++) {
                        $paramName  = $parsedJson["Parameters[$p].Name"]
                        $paramValue = $parsedJson["Parameters[$p].Value"]
                        if ($paramName) { $ruleParams[$paramName] = $paramValue }
                    }
                }

                $outputRecord["RuleName"]                   = $ruleParams["Name"]
                $outputRecord["MoveToFolder"]               = $ruleParams["MoveToFolder"]
                $outputRecord["DeleteMessage"]              = $ruleParams["DeleteMessage"]
                $outputRecord["ForwardTo"]                  = $ruleParams["ForwardTo"]
                $outputRecord["ForwardAsAttachmentTo"]      = $ruleParams["ForwardAsAttachmentTo"]
                $outputRecord["RedirectTo"]                 = $ruleParams["RedirectTo"]
                $outputRecord["FromAddressContainsWords"]   = $ruleParams["FromAddressContainsWords"]
                $outputRecord["SubjectContainsWords"]       = $ruleParams["SubjectContainsWords"]
                $outputRecord["SubjectOrBodyContainsWords"] = $ruleParams["SubjectOrBodyContainsWords"]
                $outputRecord["BodyContainsWords"]          = $ruleParams["BodyContainsWords"]
                $outputRecord["From"]                       = $ruleParams["From"]
                $outputRecord["SentTo"]                     = $ruleParams["SentTo"]
                $outputRecord["MarkAsRead"]                 = $ruleParams["MarkAsRead"]
                $outputRecord["MarkImportance"]             = $ruleParams["MarkImportance"]
                $outputRecord["StopProcessingRules"]        = $ruleParams["StopProcessingRules"]

                # Build human-readable rule logic summary
                $ruleLogic  = @()
                $conditions = @()
                $actions    = @()

                if ($ruleParams["Name"])                       { $ruleLogic  += "RULE: '$($ruleParams["Name"])'" }
                if ($ruleParams["FromAddressContainsWords"])   { $conditions += "From contains '$($ruleParams["FromAddressContainsWords"])'" }
                if ($ruleParams["From"])                       { $conditions += "From: $($ruleParams["From"])" }
                if ($ruleParams["SubjectContainsWords"])       { $conditions += "Subject contains '$($ruleParams["SubjectContainsWords"])'" }
                if ($ruleParams["SubjectOrBodyContainsWords"]) { $conditions += "Subject/Body contains '$($ruleParams["SubjectOrBodyContainsWords"])'" }
                if ($ruleParams["BodyContainsWords"])          { $conditions += "Body contains '$($ruleParams["BodyContainsWords"])'" }
                if ($ruleParams["SentTo"])                     { $conditions += "Sent to: $($ruleParams["SentTo"])" }
                if ($conditions.Count -gt 0)                  { $ruleLogic  += "IF: " + ($conditions -join " AND ") }

                if ($ruleParams["MoveToFolder"])                   { $actions += "Move to '$($ruleParams["MoveToFolder"])'" }
                if ($ruleParams["DeleteMessage"] -eq "True")       { $actions += "DELETE MESSAGE" }
                if ($ruleParams["ForwardTo"])                      { $actions += "Forward to '$($ruleParams["ForwardTo"])'" }
                if ($ruleParams["ForwardAsAttachmentTo"])          { $actions += "Forward as attachment to '$($ruleParams["ForwardAsAttachmentTo"])'" }
                if ($ruleParams["RedirectTo"])                     { $actions += "Redirect to '$($ruleParams["RedirectTo"])'" }
                if ($ruleParams["MarkAsRead"] -eq "True")          { $actions += "Mark as read" }
                if ($ruleParams["MarkImportance"])                 { $actions += "Set importance: $($ruleParams["MarkImportance"])" }
                if ($ruleParams["StopProcessingRules"] -eq "True") { $actions += "Stop processing more rules" }
                if ($actions.Count -gt 0)                         { $ruleLogic += "THEN: " + ($actions -join "; ") }

                $outputRecord["RuleLogicSummary"] = $ruleLogic -join " | "
            }
        }

        # Append ALL parsed JSON fields with JSON_ prefix
        foreach ($key in $parsedJson.Keys) {
            if ($key -notmatch "^_") {
                $safeKey = "JSON_" + ($key -replace '[^\w\.]', '_')
                if (-not $outputRecord.Contains($safeKey)) {
                    $outputRecord[$safeKey] = $parsedJson[$key]
                }
            }
        }

        [void]$allParsedRecords.Add([PSCustomObject]$outputRecord)

        # Group by operation - include IOC columns on every sheet
        if (-not [string]::IsNullOrWhiteSpace($operation)) {
            if (-not $operationGroups.ContainsKey($operation)) {
                $operationGroups[$operation] = [System.Collections.ArrayList]::new()
            }

            $opRecord = [ordered]@{
                "CreationDate" = $creationDate
                "UserId"       = $userId
                "RecordId"     = $recId
                "SessionId"    = $resolvedSessionId
                "ALL_IPs"      = $resolvedAllIPs
                "UserAgent"    = $resolvedUserAgent
                "ClientIP"     = $parsedJson["ClientIP"]
                "ResultStatus" = $parsedJson["ResultStatus"]
            }

            foreach ($field in @("Subject", "SourceFolder", "DestFolder", "FileName", "FilePath",
                                  "SiteUrl", "AffectedCount", "PolicyName", "LogonType",
                                  "RuleName", "RuleLogicSummary", "MoveToFolder", "ForwardTo",
                                  "RedirectTo", "DeleteMessage", "AccessType",
                                  "FolderCount", "OperationCount", "InternetMessageIds")) {
                if ($outputRecord[$field]) { $opRecord[$field] = $outputRecord[$field] }
            }

            [void]$operationGroups[$operation].Add([PSCustomObject]$opRecord)
        }

        # Extract AffectedItems for any operation that has them
        $affectedCount = $parsedJson["AffectedItems_Count"]
        if ($affectedCount -and $affectedCount -gt 0) {
            for ($i = 0; $i -lt $affectedCount; $i++) {
                $affItem = [ordered]@{
                    "Timestamp"         = $creationDate
                    "Operation"         = $operation
                    "UserId"            = $userId
                    "SessionId"         = $resolvedSessionId
                    "ALL_IPs"           = $resolvedAllIPs
                    "UserAgent"         = $resolvedUserAgent
                    "ClientIP"          = $parsedJson["ClientIP"]
                    "Subject"           = $parsedJson["AffectedItems[$i].Subject"]
                    "ParentFolder"      = $parsedJson["AffectedItems[$i].ParentFolder.Path"]
                    "InternetMessageId" = $parsedJson["AffectedItems[$i].InternetMessageId"]
                    "RecordId"          = $recId
                }
                [void]$affectedItemsList.Add([PSCustomObject]$affItem)
            }
        }

        # Track parse errors
        if ($parsedJson["_ParseError"]) {
            [void]$parseErrors.Add([PSCustomObject]@{
                RecordNum = $processedCount
                RecordId  = $recId
                Operation = $operation
                Error     = $parsedJson["_ParseError"]
            })
        }

    } catch {
        Log "Error processing record $processedCount : $($_.Exception.Message)" "ERROR"
        [void]$parseErrors.Add([PSCustomObject]@{
            RecordNum = $processedCount
            RecordId  = "N/A"
            Operation = "PROCESSING_ERROR"
            Error     = $_.Exception.Message
        })
    }
}

Write-Progress -Activity "Parsing UAL Records" -Completed

Log "Processing complete!"
Log "  Total parsed:           $($allParsedRecords.Count)"
Log "  Unique operations:      $($operationGroups.Count)"
Log "  JSON fields discovered: $($discoveredFields.Count)"
Log "  Affected items:         $($affectedItemsList.Count)"
Log "  MailItemsAccessed rows: $($mailItemsAccessedList.Count)"
Log "  Parse errors:           $($parseErrors.Count)"

Log "=== OPERATION BREAKDOWN ==="
$operationGroups.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | ForEach-Object {
    Log "  $($_.Key): $($_.Value.Count)"
}
#endregion

#region Export to Excel
Log "Exporting to Excel: $OutputFile"

$tempFile = Join-Path $env:TEMP "UAL_Parse_$([guid]::NewGuid().ToString('N')).xlsx"
Log "Using temp file: $tempFile"

if (Test-Path $OutputFile) {
    Remove-Item $OutputFile -Force -ErrorAction SilentlyContinue
}

try {
    $createdSheets = [System.Collections.ArrayList]::new()

    # Build summary rows
    $summaryRows = @(
        @{ Metric = "Total Records";             Value = $totalRecords;                SheetLink = $null }
        @{ Metric = "Unique Operations";         Value = $operationGroups.Count;       SheetLink = $null }
        @{ Metric = "JSON Fields Discovered";    Value = $discoveredFields.Count;      SheetLink = $null }
        @{ Metric = "Affected Items Extracted";  Value = $affectedItemsList.Count;     SheetLink = "Affected_Items" }
        @{ Metric = "MailItemsAccessed Rows";    Value = $mailItemsAccessedList.Count; SheetLink = "MailItemsAccessed" }
        @{ Metric = "Parse Errors";              Value = $parseErrors.Count;           SheetLink = "Parse_Errors" }
        @{ Metric = "Source File";               Value = $InputFile;                   SheetLink = $null }
        @{ Metric = "Debug Log";                 Value = $debugLog;                    SheetLink = $null }
        @{ Metric = "---";                       Value = "---";                        SheetLink = $null }
    )

    $excludedOperations = @("ArchiveCreated", "AttachmentAccess", "ClientViewSignaled")
    foreach ($op in ($operationGroups.Keys | Sort-Object)) {
        $sheetName = $null
        if ($excludedOperations -notcontains $op) {
            $sheetName = "Op_" + ($op -replace '[\\\/\*\?\[\]:]+', '_')
            if ($sheetName.Length -gt 31) { $sheetName = $sheetName.Substring(0, 31) }
        }
        $summaryRows += @{ Metric = "Op: $op"; Value = $operationGroups[$op].Count; SheetLink = $sheetName }
    }

    $summaryData = $summaryRows | ForEach-Object {
        [PSCustomObject]@{ Metric = $_.Metric; Value = $_.Value }
    }

    Write-Host "[*] Creating Excel workbook..." -ForegroundColor Yellow
    $excel = $summaryData | Export-Excel -Path $tempFile -WorksheetName "Summary" -AutoSize -BoldTopRow -FreezeTopRow -PassThru
    [void]$createdSheets.Add("Summary")
    Log "  Created: Summary"

    Write-Host "[*] Adding All_Records ($($allParsedRecords.Count) rows)..." -ForegroundColor Yellow
    $null = $allParsedRecords | Export-Excel -ExcelPackage $excel -WorksheetName "All_Records" -AutoSize -BoldTopRow -FreezeTopRow -PassThru
    [void]$createdSheets.Add("All_Records")
    Log "  Created: All_Records"

    if ($affectedItemsList.Count -gt 0) {
        Write-Host "[*] Adding Affected_Items ($($affectedItemsList.Count) rows)..." -ForegroundColor Yellow
        $null = $affectedItemsList | Export-Excel -ExcelPackage $excel -WorksheetName "Affected_Items" -AutoSize -BoldTopRow -FreezeTopRow -PassThru
        [void]$createdSheets.Add("Affected_Items")
        Log "  Created: Affected_Items"
    }

    if ($mailItemsAccessedList.Count -gt 0) {
        Write-Host "[*] Adding MailItemsAccessed ($($mailItemsAccessedList.Count) rows)..." -ForegroundColor Yellow
        $null = $mailItemsAccessedList | Export-Excel -ExcelPackage $excel -WorksheetName "MailItemsAccessed" -AutoSize -BoldTopRow -FreezeTopRow -PassThru
        [void]$createdSheets.Add("MailItemsAccessed")
        Log "  Created: MailItemsAccessed"
    }

    $opCount = 0
    foreach ($op in ($operationGroups.Keys | Sort-Object)) {
        if ($excludedOperations -contains $op) { Log "  Skipped: Op_$op (excluded)"; continue }
        $opData = $operationGroups[$op]
        if ($opData.Count -gt 0) {
            $opCount++
            $sheetName = "Op_" + ($op -replace '[\\\/\*\?\[\]:]+', '_')
            if ($sheetName.Length -gt 31) { $sheetName = $sheetName.Substring(0, 31) }
            Write-Host "[*] Adding $sheetName ($($opData.Count) rows)..." -ForegroundColor Gray
            $null = $opData | Export-Excel -ExcelPackage $excel -WorksheetName $sheetName -AutoSize -BoldTopRow -FreezeTopRow -PassThru
            [void]$createdSheets.Add($sheetName)
        }
    }
    Log "  Created: $opCount operation sheets"

    if ($parseErrors.Count -gt 0) {
        Write-Host "[*] Adding Parse_Errors ($($parseErrors.Count) rows)..." -ForegroundColor Yellow
        $null = $parseErrors | Export-Excel -ExcelPackage $excel -WorksheetName "Parse_Errors" -AutoSize -BoldTopRow -FreezeTopRow -PassThru
        [void]$createdSheets.Add("Parse_Errors")
        Log "  Created: Parse_Errors"
    }

    # === ADD NAVIGATION HYPERLINKS ===
    Write-Host "[*] Adding navigation hyperlinks..." -ForegroundColor Yellow

    $summaryWs = $excel.Workbook.Worksheets["Summary"]
    $rowNum = 2
    foreach ($row in $summaryRows) {
        if ($row.SheetLink -and $createdSheets -contains $row.SheetLink) {
            $cell = $summaryWs.Cells[$rowNum, 1]
            $cell.Hyperlink = New-Object -TypeName OfficeOpenXml.ExcelHyperLink -ArgumentList ("#'$($row.SheetLink)'!A1", $row.Metric)
            $cell.Style.Font.UnderLine = $true
            $cell.Style.Font.Color.SetColor([System.Drawing.Color]::Blue)
        }
        $rowNum++
    }
    Log "  Added hyperlinks to Summary sheet"

    foreach ($sheetName in $createdSheets) {
        if ($sheetName -eq "Summary") { continue }
        $ws = $excel.Workbook.Worksheets[$sheetName]
        if ($null -eq $ws) { continue }

        $ws.InsertColumn(1, 1)
        $ws.Cells[1, 1].Value = "[<< Summary]"
        $ws.Cells[1, 1].Hyperlink = New-Object -TypeName OfficeOpenXml.ExcelHyperLink -ArgumentList ("#'Summary'!A1", "Back to Summary")
        $ws.Cells[1, 1].Style.Font.UnderLine = $true
        $ws.Cells[1, 1].Style.Font.Color.SetColor([System.Drawing.Color]::Blue)
        $ws.Cells[1, 1].Style.Font.Bold = $true
        $ws.Column(1).Width = 14
    }
    Log "  Added 'Back to Summary' links to all sheets"

    Write-Host "[*] Saving workbook..." -ForegroundColor Yellow
    Close-ExcelPackage $excel
    Log "  Workbook saved to temp file"

    Write-Host "[*] Copying to final destination..." -ForegroundColor Yellow
    Copy-Item -Path $tempFile -Destination $OutputFile -Force
    Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    Log "  Copied to: $OutputFile"

    Log "Excel export complete!"

} catch {
    Log "Excel export failed: $($_.Exception.Message)" "ERROR"
    Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"

    if ($excel) { try { Close-ExcelPackage $excel -NoSave } catch {} }
    if (Test-Path $tempFile) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }

    throw
}
#endregion

#region Final Summary
$endTime = Get-Date
$runtime = ($endTime - $startTime).TotalSeconds

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Green
Write-Host "UAL PARSING COMPLETE" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Green
Write-Host "[+] Output File:          $OutputFile" -ForegroundColor Green
Write-Host "[+] Debug Log:            $debugLog" -ForegroundColor Green
Write-Host "[+] Total Records:        $totalRecords" -ForegroundColor Green
Write-Host "[+] Operations:           $($operationGroups.Count)" -ForegroundColor Green
Write-Host "[+] JSON Fields:          $($discoveredFields.Count)" -ForegroundColor Green
Write-Host "[+] MailItemsAccessed:    $($mailItemsAccessedList.Count)" -ForegroundColor Green
Write-Host "[+] Runtime:              $([math]::Round($runtime, 2)) seconds" -ForegroundColor Green

if ($parseErrors.Count -gt 0) {
    Write-Host "[!] Parse Errors:  $($parseErrors.Count) (see Parse_Errors sheet)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Top 10 Operations:" -ForegroundColor Cyan
$operationGroups.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 10 | ForEach-Object {
    Write-Host "  $($_.Key): $($_.Value.Count)" -ForegroundColor White
}

Log "=== SCRIPT COMPLETE ==="
Log "Total runtime: $([math]::Round($runtime, 2)) seconds"
#endregion