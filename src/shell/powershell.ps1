[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
while (($__ss_line = [Console]::In.ReadLine()) -ne $null) {
    $__ss_separator = $__ss_line.IndexOf('|')
    if ($__ss_separator -le 0) { continue }
    $__ss_marker = $__ss_line.Substring(0, $__ss_separator)
    $__ss_encoded = $__ss_line.Substring($__ss_separator + 1)
    $__ss_ec = 0
    try {
        $__ss_s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__ss_encoded))
        $global:LASTEXITCODE = 0
        $__ss_errors = $global:Error.Count
        . ([ScriptBlock]::Create($__ss_s)) *>&1 | Out-String -Stream -Width 32767 | ForEach-Object { [Console]::Out.WriteLine($_) }
        $__ss_ec = if ($LASTEXITCODE -ne 0) {
            [int]$LASTEXITCODE
        } elseif ($global:Error.Count -gt $__ss_errors) {
            1
        } else {
            0
        }
    } catch {
        $__ss_ec = 1
        [Console]::Out.Write(($_ | Out-String -Width 32767))
    }
    [Console]::Out.Write([string][char]30 + $__ss_marker + '|' + $__ss_ec + [char]31)
    [Console]::Out.Flush()
}
