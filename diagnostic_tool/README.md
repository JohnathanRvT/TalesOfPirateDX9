# diagnostic_tool

Diagnostic client for GateServer to test command routing.

## Handshake Process
The client replicates the exact handshake as defined in the server's `ToClient.cpp`:
1.  **Server Public Key**: Upon connection, the server sends its RSA public key (`CMD_MC_SEND_SERVER_PUBLIC_KEY` = 943). The key is sent in a binary format: `[Cmd(2)][Short(len)][Data]`.
2.  **AES Key Exchange**: The client generates a random 16-byte AES key, encrypts it using the server's RSA public key (OAEP SHA-1), Base64 encodes the result, and sends it back (`CMD_CM_SEND_PRIVATE_KEY` = 355). This packet includes a 4-byte WPE counter because the command ID is <= 500.

## Packet Framing
Each packet is prefixed with a 2-byte Big-Endian length header (inclusive of the header itself).

## Encryption
Post-handshake packets are encrypted using AES-GCM:
1.  The packet body (Command ID + Counter + Data) is encrypted with the 16-byte AES key.
2.  The resulting ciphertext and 12-byte tag are combined and Base64 encoded.
3.  The final payload consists of the Base64 string, a null byte (`\0`), and a 16-byte random Initialization Vector (IV).
4.  Note: .NET's `AesGcm` uses 12-byte nonces. The tool uses the first 12 bytes of the 16-byte IV for the GCM nonce to ensure compatibility.

## Target Command
The tool sends `CMD_CM_KITBAGTEMPlocks` (ID 36) with a 4-byte counter, a 16-bit integer `0`, and a null-terminated empty string prefixed by its 2-byte length (which will be 1).

## How to Run
Prerequisites: .NET 8 SDK.

```bash
cd diagnostic_tool
dotnet run [IP] [Port]
```

If no arguments are provided, it attempts to read `GateServer.cfg` from `../server/GateServer/` or defaults to `127.0.0.1:1973`.
