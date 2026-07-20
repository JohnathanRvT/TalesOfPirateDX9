# Tales of Pirate DX9: Network Protocol and Encryption Analysis

This document provides a highly detailed analysis of the network protocol, packet structure, security mechanisms, and handshake/encryption processes implemented in the *Tales of Pirate DX9* (ToP DX9) client/server architecture.

It is designed to serve as a comprehensive blueprint for developers recreating a new custom client for this game.

---

## 1. Network Protocol Overview

The networking system of Tales of Pirate DX9 is built on the `InfoNet` and `DBC` (Dabo.Zhang's Communication Library) libraries. It uses standard TCP sockets for client-to-server and server-to-server communication. The primary server dealing directly with the game client is the **GateServer** (located in `sources/Server/GateServer`).

---

## 2. Packet Framing (Base Packet Structure)

All network traffic sent over TCP is framed so that the receiver knows exactly where each packet starts and ends.

### Unencrypted Base Packet Layout (Before Key Exchange / Handshake)

| Field | Size | Description |
|---|---|---|
| **Length (Header)** | 2 bytes or 4 bytes | The packet length in bytes, encoded in network byte order (Big Endian). The size depends on configuration (usually 2 bytes / `uShort`). |
| **Command (`CMD`)** | 2 bytes | A unique packet identifier (e.g., `CMD_CM_LOGIN`). Written in Big Endian (`htons`). |
| **Payload Data** | Variable | The serialized packet arguments (strings, integers, floats, characters). |

---

## 3. Handshake and Cryptographic Key Exchange

When a client establishes a connection to the GateServer, symmetric encryption is not enabled immediately. Instead, a public-key cryptographic handshake occurs to exchange a unique symmetric session key (AES-256) securely.

### Step-by-Step Handshake Flow

#### Step 1: Server Public Key Advertisement (`CMD_MC_SEND_SERVER_PUBLIC_KEY` - CMD 13013)
Upon connection, the server generates a random 3072-bit RSA private key (`srvPrivateKey`) and extracts its corresponding RSA public key (`srvPublicKey`).
The server then transmits this public key to the client using a packet:
* **CMD**: `CMD_MC_SEND_SERVER_PUBLIC_KEY` (`13013`)
* **Payload**:
  * Public Key length (2 bytes / `uShort`)
  * RSA Public Key (DER/BER serialized format sequence)

#### Step 2: Client Symmetric Key Generation and Sending (`CMD_CM_SEND_PRIVATE_KEY` - CMD 5055)
The client receives the server's public key, loads it, and generates/selects its own 32-byte (256-bit) AES private key (`cliPrivateKey` / `g_NetIF->cliPrivateKey`).
The client then encrypts this symmetric key with the server's RSA public key using the **RSAES-OAEP-SHA** algorithm:
* The raw encrypted private key is Base64-encoded.
* The client sends this Base64 string to the server in a packet:
  * **CMD**: `CMD_CM_SEND_PRIVATE_KEY` (`5055`)
  * **Payload**:
    * Encrypted client private key (Null-terminated Base64 String)

#### Step 3: Server Decryption and Handshake Completion
The server receives the client's public key packet, extracts the Base64 string, decodes it, and decrypts the client's 32-byte symmetric AES key using its private RSA key (`srvPrivateKey`).
* Both client and server flag `handshakeDone = true` and `_comm_enc = true`.
* The temporary RSA keys are disposed of.
* From this point on, **all subsequent packets** are encrypted and decrypted symmetrically.

---

## 4. Symmetric Encryption: AES-256 GCM

Once the handshake is completed, the game switches to symmetric encryption using **AES-256 in GCM (Galois/Counter Mode)**, with a 12-byte tag size.

### Encrypted Packet Layout (On the Wire)

Symmetric encryption is handled in the `OnEncrypt` and `OnDecrypt` hooks inside the networking layer (`NetIF::OnEncrypt`, `ToClient::OnEncrypt`). The packet length header is **not** encrypted. Only the payload (the portion starting immediately after the length header) is encrypted.

| Wire Field | Size | Description |
|---|---|---|
| **Length (Header)** | 2 bytes (or 4 bytes) | Size of the entire encrypted payload + IV (updated after encryption). |
| **Ciphertext (Base64)** | Variable | The Base64 encoded string of the encrypted payload data. |
| **Null Separator** | 1 byte | A `0x00` byte separates the ciphertext Base64 string and the initialization vector. |
| **Initialization Vector (IV)** | 16 bytes | Randomly generated IV used to encrypt this specific packet. |

### Encryption Process (Sending a Packet)
1. Generate a random 16-byte Initialization Vector (IV).
2. Set up AES-256 GCM with the 32-byte negotiated symmetric key and the 16-byte IV.
3. Encrypt the plaintext payload (the `CMD` and subsequent serialized parameters) using AES-256 GCM (12-byte MAC tag appended by default in CryptoPP's `AuthenticatedEncryptionFilter`).
4. Encode the entire encrypted ciphertext block (including the tag) using Base64.
5. Place the Base64 string into the packet stream, followed by a `0x00` separator byte, and finally the 16-byte raw IV.
6. Re-calculate the total packet length and update the length header.

### Decryption Process (Receiving a Packet)
1. Read the length header to parse the packet size.
2. Locate the 16-byte IV at the end of the payload (`buf + packet_len - 16`).
3. Extract the Base64 ciphertext, which ends before the `0x00` separator byte (`buf + packet_len - 17`).
4. Base64-decode the ciphertext block.
5. Decrypt the block using AES-256 GCM with the session key and the extracted 16-byte IV. GCM automatically validates the integrated 12-byte authentication tag.
6. If decryption or tag verification fails, drop the connection immediately (potential tamper/corruption).

---

## 5. Security Protections

The engine includes several specialized anti-exploit and anti-tamper mechanisms:

### A. Anti-WPE (Anti-Packet-Editing) and Packet Counter
If WPE protection (`g_wpe`) is enabled on the server, the client and server enforce a strict **packet sequence verification**.

#### Packet Modification (Client side)
Inside `WPacket::WriteCmd`:
* If the packet is a client-to-server command (CMD <= 500 or between 6000 and 6500), a **4-byte (32-bit) packet counter** (`m_pktn` / `count`) is automatically inserted immediately after the 2-byte CMD header.
* This counter starts at `0` upon connection / key exchange, and is incremented by 1 for every command written.

#### Packet Verification (Server side)
Inside `ToClient::OnProcessData`:
1. If `g_wpe` is enabled, the server reads the 2-byte CMD.
2. It then reads the 4-byte counter (`DWORD counter`) from the packet stream.
3. The server compares this `counter` value with its internal expected sequence counter (`datasock->m_pktn`).
4. If there is a mismatch (e.g. `counter != m_pktn`), the server flags WPE detection, prints an alert, and **disconnects the client instantly**.
5. If the counter matches, the server increments its local `m_pktn`.
6. To avoid breaking downstream handlers, the server **strips out** the 4-byte counter from the packet memory using `memmove`, shifts the remaining parameters 4 bytes left, and updates the packet length variables so the command processing logic remains transparent to this protection.

### B. Anti-DDoS Rate Limiting
If DDoS protection (`g_ddos`) is enabled:
* The server maintains `m_cmdNum` (number of commands processed within a sliding time window) and `m_lashTick`.
* If a client sends packets too rapidly (e.g., exceeding `m_checkError` commands per window or sending at a rate of > 1024 bytes per second), the server flags a DDoS suspect and disconnects the socket immediately.

---

## 6. Guidelines for Developing a Custom Client

To build a modern client (e.g., in Python, C#, Rust, Go, or TypeScript) that can interact with this server, implement the following roadmap:

### Phase 1: TCP Framing & Core Client Socket
1. Open a standard TCP connection to the GateServer port.
2. Implement a TCP stream buffer reader that reads a 2-byte Big-Endian length header, then waits for the complete payload of that length before yielding a packet.

### Phase 2: Implement Cryptography (RSA/AES-256 GCM)
1. Initialize a Crypto library of your choice (e.g., OpenSSL, BouncyCastle, Crypto++, or standard platform libraries).
2. Prepare a 32-byte cryptographically secure random sequence to act as your client's AES-256 symmetric session key (`cliPrivateKey`).
3. Handle packet `CMD_MC_SEND_SERVER_PUBLIC_KEY` (`13013`):
   - Parse the 2-byte public key length, followed by the raw DER/BER public key.
   - Load this public key as an RSA public key.
4. Respond with `CMD_CM_SEND_PRIVATE_KEY` (`5055`):
   - Encrypt your generated 32-byte `cliPrivateKey` using RSA-OAEP with SHA-1 / SHA-256 (matching server expectation, default OAEP).
   - Encode the resulting cipher block into Base64.
   - Format a `WPacket` write:
     - Write CMD `5055`.
     - Write the Base64 string (as a null-terminated string).
     - Send the packet.
5. Complete handshake on your client (enable the `OnEncrypt` / `OnDecrypt` flags so all future packets go through AES-256 GCM).

### Phase 3: Packet Layout & Anti-WPE Support
1. Implement a serialized reader/writer stream supporting:
   - `ReadChar` / `WriteChar` (1 byte)
   - `ReadShort` / `WriteShort` (2 bytes Big-Endian)
   - `ReadLong` / `WriteLong` (4 bytes Big-Endian)
   - `ReadString` / `WriteString` (Null-terminated string)
2. If the server has Anti-WPE enabled:
   - For every outbound packet with command ID <= 500 or in the 6000-6500 range, insert a 4-byte incrementing packet counter (starting at 0) directly after writing the 2-byte CMD ID.

### Phase 4: Handle Authentication
1. Construct and send `CMD_CM_LOGIN` (`CMD_CM_ROLEBASE + 1`):
   - Write Account Name (String).
   - Compute BLAKE2s digest of the password, hex-encode it, and write it (String).
   - Write MAC Address (String, e.g. "00-11-22-33-44-55").
   - Write constant integer/short identifiers (e.g., version identifier, default 911).
2. Enjoy communicating with the defunct server under a robust modern architecture!

---

## 7. Concrete Packet Example: CMD_CM_LOGIN (431)

To help visualize how the layout maps to real wire packets, let's dissect an actual unencrypted client login packet stream of length **88 bytes** (`0x58`):

### The Hex Stream
```text
00 58 80 00 00 00 01 AF 00 00 00 00 00 07 6E 6F 62 69 6C 6C 00 00 07 61 6C 74 69 6E 73 00 00 18 BC 3F 05 1B 59 04 F3 2E 2D 70 A8 7D 15 73 E9 3E 10 66 8F 8F ED 7F DF D1 00 18 43 30 2D 31 38 2D 35 30 2D 33 34 2D 38 30 2D 34 46 2D 30 30 2D 30 30 00 03 8F 00 88 18 BC
```

### Byte-by-Byte Layout Breakdown

| Byte Offset (Hex) | Byte Values | Field Name | Decoded Value & Analysis |
|---|---|---|---|
| `00 - 01` | `00 58` | **Length (Header)** | `88` (decimal). Specifies total payload bytes. |
| `02 - 05` | `80 00 00 00` | **Session ID (`SESS`)** | `0x80000000` (4 bytes). Managed by `RPCMGR`. |
| `06 - 07` | `01 AF` | **Command ID (`CMD`)** | `431` (`CMD_CM_LOGIN`). |
| `08 - 0B` | `00 00 00 00` | **WPE Packet Counter** | `0` (4-byte counter inserted since CMD <= 500). |
| `0C - 0D` | `00 07` | **Account Length** | `7` bytes (length of string including null-terminator). |
| `0E - 14` | `6E 6F 62 69 6C 6C 00` | **Account Name** | `"nobill\0"`. |
| `15 - 16` | `00 07` | **Password/Token Length** | `7` bytes. |
| `17 - 1D` | `61 6C 74 69 6E 73 00` | **Password / Token** | `"altins\0"`. |
| `1E - 1F` | `00 18` | **Hash/Passport Length** | `24` bytes (`0x0018`). |
| `20 - 37` | `BC 3F 05 1B 59 04 F3 2E 2D 70 A8 7D 15 73 E9 3E 10 66 8F 8F ED 7F DF D1` | **Hash/Passport Digest** | `24` bytes of binary/digest data. |
| `38 - 39` | `00 18` | **MAC Address Length** | `24` bytes. |
| `3A - 51` | `43 30 2D 31 38 2D 35 30 2D 33 34 2D 38 30 2D 34 46 2D 30 30 2D 30 30 00` | **MAC Address String** | `"C0-18-50-34-80-4F-00-00\0"`. |
| `52 - 53` | `03 8F` | **Short Security Marker** | `911` (`0x038F`). Standard anti-bypass indicator. |
| `54 - 55` | `00 88` | **Short Client Version** | `136` (`0x0088`). Client build version. |
| `56 - 57` | `18 BC` | **Short Alternative/Build**| `6332` (`0x18BC`). DX9 build or memory recycling padding. |

---

### Highlights for Client Recreators

1. **Length-Prefixed Strings**: Notice how every string parameter is prefixed with a 2-byte length in network byte order, and includes the trailing `\0` (null-terminator) in its character payload and length count.
2. **Backwards Parsing**: When verifying login, the server parses the version and safety checks backwards (`ReverseReadShort()`), which explains why `18 BC` (Version `6332`), `00 88` (Build `136`), and `03 8F` (`911`) sit at the very end of the packet structure.
3. **Anti-WPE insertion**: The counter `00 00 00 00` resides immediately after `CMD_CM_LOGIN`'s `01 AF`, shifting the subsequent parameter reads in the raw buffer by 4 bytes.
