[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
while (($__localshelld_line = [Console]::In.ReadLine()) -ne $null) {
    $__localshelld_separator = $__localshelld_line.IndexOf('|')
    if ($__localshelld_separator -le 0) { continue }
    $__localshelld_marker = $__localshelld_line.Substring(0, $__localshelld_separator)
    $__localshelld_encoded = $__localshelld_line.Substring($__localshelld_separator + 1)
    $__localshelld_ec = 0
    try {
        $__localshelld_s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__localshelld_encoded))
        $global:LASTEXITCODE = 0
        $__localshelld_errors = $global:Error.Count
        . ([ScriptBlock]::Create($__localshelld_s)) *>&1 | Out-String -Stream -Width 32767 | ForEach-Object { [Console]::Out.WriteLine($_) }
        $__localshelld_ec = if ($LASTEXITCODE -ne 0) {
            [int]$LASTEXITCODE
        } elseif ($global:Error.Count -gt $__localshelld_errors) {
            1
        } else {
            0
        }
    } catch {
        $__localshelld_ec = 1
        [Console]::Out.Write(($_ | Out-String -Width 32767))
    }
    [Console]::Out.Write([string][char]30 + $__localshelld_marker + '|' + $__localshelld_ec + [char]31)
    [Console]::Out.Flush()
}
