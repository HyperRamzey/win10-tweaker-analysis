param([int]$Start, [int]$End, [string]$File = "G:\projects\w10t_work\koi_fixed_decompiled.cs")
$zw = [char[]](0x200b,0x200c,0x200d,0x2060,0x206a,0x206b,0x206c,0x206d,0x206e,0x206f,0x202a,0x202b,0x202c,0x202d,0x202e,0x2061,0x2062,0x2063,0x2064,0xfeff,0x00ad,0x034f,0x061c,0x17b4,0x17b5,0x1806,0x180e)
$lines = Get-Content $File -Encoding Unicode
for ($i = $Start - 1; $i -lt [Math]::Min($End, $lines.Count); $i++) {
    $t = $lines[$i]
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $t.ToCharArray()) {
        if ($zw -notcontains $ch) { [void]$sb.Append($ch) }
    }
    $clean = $sb.ToString().TrimEnd()
    if ($clean -ne "") { "$($i+1): $clean" }
}
