$c = New-Object System.Net.Sockets.TCPClient('localhost', 80)
$c.Connected
$c.Close()
