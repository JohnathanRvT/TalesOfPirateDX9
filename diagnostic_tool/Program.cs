using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections.Generic;

namespace DiagnosticTool
{
    class Program
    {
        static byte[] cliPrivateKey = new byte[16];
        static uint packetCounter = 0;
        static bool handshakeDone = false;

        static void Main(string[] args)
        {
            string ip = "127.0.0.1";
            int port = 1973;

            try
            {
                string configPath = "../server/GateServer/GateServer.cfg";
                if (File.Exists(configPath))
                {
                    var lines = File.ReadAllLines(configPath);
                    bool inToClient = false;
                    foreach (var line in lines)
                    {
                        var trimmed = line.Trim();
                        if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("//")) continue;
                        if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                        {
                            inToClient = (trimmed == "[ToClient]");
                            continue;
                        }

                        if (inToClient)
                        {
                            var parts = trimmed.Split('=', 2);
                            if (parts.Length == 2)
                            {
                                string key = parts[0].Trim();
                                string value = parts[1].Trim().Split("//")[0].Trim();
                                if (key == "IP") ip = value;
                                else if (key == "Port") port = int.Parse(value);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing config: {ex.Message}. Using defaults.");
            }

            if (args.Length >= 1) ip = args[0];
            if (args.Length >= 2) port = int.Parse(args[1]);

            Console.WriteLine($"Connecting to {ip}:{port}...");

            try
            {
                using TcpClient client = new TcpClient(ip, port);
                using NetworkStream stream = client.GetStream();

                // 1. Receive Server Public Key
                byte[] response = ReadPacket(stream);
                if (response == null) return;

                // Handshake packets are binary: [Cmd(2)][Data...]
                ushort cmd = ReadUShort(response, 0);
                if (cmd != 943) // CMD_MC_SEND_SERVER_PUBLIC_KEY
                {
                    Console.WriteLine($"Unexpected first packet: {cmd}");
                    return;
                }

                // Packet structure: [Cmd(2)][Short len][Data]
                ushort keyLen = ReadUShort(response, 2);
                byte[] publicKeyBytes = new byte[keyLen];
                Array.Copy(response, 4, publicKeyBytes, 0, keyLen);

                Console.WriteLine("Received Server Public Key.");

                // 2. Generate AES key and send to server
                RandomNumberGenerator.Fill(cliPrivateKey);

                using (RSA rsa = RSA.Create())
                {
                    rsa.ImportRSAPublicKey(publicKeyBytes, out _);
                    byte[] encryptedKey = rsa.Encrypt(cliPrivateKey, RSAEncryptionPadding.OaepSHA1);
                    string base64Key = Convert.ToBase64String(encryptedKey);

                    MemoryStream ms = new MemoryStream();
                    WriteUShort(ms, 355); // CMD_CM_SEND_PRIVATE_KEY
                    // HANDSHAKE packets don't have WPE counter in WriteCmd but OnProcessData expects it if g_wpe is on.
                    // Wait, ToClient::OnProcessData for CMD_CM_SEND_PRIVATE_KEY:
                    // It reads cmd, then counter if g_wpe is on.
                    // BUT WPacket::WriteCmd adds counter if cmd <= 500. 355 <= 500, so it adds counter.
                    WriteUInt(ms, packetCounter++);
                    WriteString(ms, base64Key);

                    SendPacket(stream, ms.ToArray());
                }
                Console.WriteLine("Sent Encrypted AES Key.");
                handshakeDone = true;

                // 3. Send Target Command
                // CMD_CM_KITBAGTEMPlocks = 36
                MemoryStream cmdMs = new MemoryStream();
                WriteUShort(cmdMs, 36);
                WriteUInt(cmdMs, packetCounter++);
                WriteUShort(cmdMs, 0);
                WriteString(cmdMs, "");

                SendPacket(stream, cmdMs.ToArray());
                Console.WriteLine("Sent CMD_CM_KITBAGTEMPlocks.");

                // 4. Receive Response
                byte[] finalResponse = ReadPacket(stream);
                if (finalResponse != null)
                {
                    Console.WriteLine("Received Response:");
                    Console.WriteLine(BitConverter.ToString(finalResponse).Replace("-", " "));
                    if (finalResponse.Length >= 2)
                    {
                        ushort respCmd = ReadUShort(finalResponse, 0);
                        Console.WriteLine($"Response Command ID: {respCmd}");
                    }
                }
                else
                {
                    Console.WriteLine("No response received.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }

        static byte[] ReadPacket(NetworkStream stream)
        {
            byte[] lenBuf = new byte[2];
            int read = stream.Read(lenBuf, 0, 2);
            if (read < 2) return null;

            ushort len = (ushort)((lenBuf[0] << 8) | lenBuf[1]);
            byte[] data = new byte[len - 2];
            int totalRead = 0;
            while (totalRead < data.Length)
            {
                read = stream.Read(data, totalRead, data.Length - totalRead);
                if (read == 0) break;
                totalRead += read;
            }

            if (handshakeDone)
            {
                return DecryptAES(data);
            }
            return data;
        }

        static void SendPacket(NetworkStream stream, byte[] data)
        {
            if (handshakeDone)
            {
                data = EncryptAES(data);
            }

            ushort totalLen = (ushort)(data.Length + 2);
            byte[] fullPacket = new byte[totalLen];
            fullPacket[0] = (byte)(totalLen >> 8);
            fullPacket[1] = (byte)(totalLen & 0xFF);
            Array.Copy(data, 0, fullPacket, 2, data.Length);

            stream.Write(fullPacket, 0, fullPacket.Length);
        }

        static byte[] EncryptAES(byte[] data)
        {
            byte[] iv = new byte[16];
            RandomNumberGenerator.Fill(iv);

            // Server uses 16-byte IV with GCM. .NET's AesGcm expects 12.
            // However, Crypto++'s GCM<AES> with 16-byte IV is just using the first 12 bytes as nonce
            // and last 4 bytes as initial counter? Actually Crypto++ GCM handles non-12 byte nonces by hashing them.
            // But ToClient.cpp uses iv.data(), 16.
            // Since we can't easily do 16-byte nonce GCM in standard .NET, and the server implementation
            // is likely assuming 12-byte nonce if it's following standard GCM... wait.
            // Actually, ToClient.cpp says:
            // CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE); // IV size = 16 bytes
            // e.SetKeyWithIV(cliPrivateKey, cliPrivateKey.size(), iv.data(), CryptoPP::AES::BLOCKSIZE);

            // If the server strictly requires 16-byte nonce, we might need a different approach.
            // But let's try 12-byte nonce first as it's the GCM standard.
            // Actually, if I use 12-byte nonce in .NET, I can only send 12 bytes.

            // To match the server, we must send what it expects.
            // It expects Base64(Ciphertext+Tag) + \0 + 16-byte IV.

            // Let's use the first 12 bytes of our 16-byte IV for AesGcm.
            byte[] nonce = new byte[12];
            Array.Copy(iv, 0, nonce, 0, 12);

            using AesGcm aesGcm = new AesGcm(cliPrivateKey, 12);
            byte[] ciphertext = new byte[data.Length];
            byte[] tag = new byte[12];
            aesGcm.Encrypt(nonce, data, ciphertext, tag);

            byte[] combined = new byte[ciphertext.Length + tag.Length];
            Array.Copy(ciphertext, 0, combined, 0, ciphertext.Length);
            Array.Copy(tag, 0, combined, ciphertext.Length, tag.Length);

            string base64 = Convert.ToBase64String(combined);
            byte[] base64Bytes = Encoding.ASCII.GetBytes(base64);

            byte[] final = new byte[base64Bytes.Length + 1 + 16];
            Array.Copy(base64Bytes, 0, final, 0, base64Bytes.Length);
            final[base64Bytes.Length] = 0;
            Array.Copy(iv, 0, final, base64Bytes.Length + 1, 16);

            return final;
        }

        static byte[] DecryptAES(byte[] data)
        {
            try
            {
                int ivPos = data.Length - 16;
                byte[] iv = new byte[16];
                Array.Copy(data, ivPos, iv, 0, 16);

                int base64Len = ivPos - 1;
                string base64 = Encoding.ASCII.GetString(data, 0, base64Len);
                byte[] combined = Convert.FromBase64String(base64);

                byte[] tag = new byte[12];
                byte[] ciphertext = new byte[combined.Length - 12];
                Array.Copy(combined, combined.Length - 12, tag, 0, 12);
                Array.Copy(combined, 0, ciphertext, 0, ciphertext.Length);

                byte[] plaintext = new byte[ciphertext.Length];
                byte[] nonce = new byte[12];
                Array.Copy(iv, 0, nonce, 0, 12);

                using AesGcm aesGcm = new AesGcm(cliPrivateKey, 12);
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);

                return plaintext;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Decryption error: {ex.Message}");
                return null;
            }
        }

        static ushort ReadUShort(byte[] data, int pos)
        {
            return (ushort)((data[pos] << 8) | data[pos + 1]);
        }

        static void WriteUShort(Stream s, ushort val)
        {
            s.WriteByte((byte)(val >> 8));
            s.WriteByte((byte)(val & 0xFF));
        }

        static void WriteUInt(Stream s, uint val)
        {
            s.WriteByte((byte)(val >> 24));
            s.WriteByte((byte)(val >> 16));
            s.WriteByte((byte)(val >> 8));
            s.WriteByte((byte)(val & 0xFF));
        }

        static void WriteString(Stream s, string val)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(val);
            WriteUShort(s, (ushort)(bytes.Length + 1));
            s.Write(bytes, 0, bytes.Length);
            s.WriteByte(0); // Null terminator
        }
    }
}
