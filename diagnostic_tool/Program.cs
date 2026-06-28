using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using PacketDecoder;

namespace DiagnosticTool
{
    class Program
    {
        static byte[] cliPrivateKey = new byte[16];
        static uint packetCounter = 0;
        static bool handshakeDone = false;
        const uint SESSFLAG = 0x80000000;
        static PacketParser parser = new PacketParser();

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
                byte[] payload = ReadPacket(stream);
                if (payload == null) return;

                if (payload.Length < 6)
                {
                    Console.WriteLine("Packet too short.");
                    return;
                }

                uint sess = ReadUInt(payload, 0);
                ushort cmd = ReadUShort(payload, 4);

                byte[] cmdPayload = new byte[payload.Length - 6];
                Array.Copy(payload, 6, cmdPayload, 0, cmdPayload.Length);

                Console.WriteLine("--- Received Packet ---");
                Console.WriteLine(parser.Parse(new GamePacket { Len = (ushort)(payload.Length + 2), Cmd = cmd, Payload = cmdPayload }));

                if (cmd != 943) // CMD_MC_SEND_SERVER_PUBLIC_KEY
                {
                    return;
                }

                // Parse keyLen to find where data starts
                int pos = 6;
                ushort keyLen = (ushort)((payload[pos] << 8) | payload[pos + 1]);
                byte[] publicKeyBytes = new byte[keyLen];
                Array.Copy(payload, 8, publicKeyBytes, 0, keyLen);

                // 2. Generate AES key and send to server
                RandomNumberGenerator.Fill(cliPrivateKey);

                using (RSA rsa = RSA.Create())
                {
                    try {
                        rsa.ImportRSAPublicKey(publicKeyBytes, out _);
                    } catch {
                        rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
                    }

                    byte[] encryptedKey = rsa.Encrypt(cliPrivateKey, RSAEncryptionPadding.OaepSHA1);
                    string base64Key = Convert.ToBase64String(encryptedKey);

                    MemoryStream ms = new MemoryStream();
                    WriteUInt(ms, SESSFLAG); // SESS
                    WriteUShort(ms, 355); // CMD_CM_SEND_PRIVATE_KEY
                    WriteUInt(ms, packetCounter++); // Counter
                    WriteString(ms, base64Key);

                    SendPacket(stream, ms.ToArray());
                }
                Console.WriteLine("Sent Encrypted AES Key.");
                handshakeDone = true;

                // 3. Send Target Command
                // CMD_CM_KITBAGTEMPlocks = 36
                MemoryStream cmdMs = new MemoryStream();
                WriteUInt(cmdMs, SESSFLAG); // SESS
                WriteUShort(cmdMs, 36);
                WriteUInt(cmdMs, packetCounter++);
                WriteUShort(cmdMs, 0);
                WriteString(cmdMs, "");

                SendPacket(stream, cmdMs.ToArray());
                Console.WriteLine("Sent CMD_CM_KITBAGTEMPlocks.");

                // 4. Receive Response
                while (client.Connected)
                {
                    byte[] finalPayload = ReadPacket(stream);
                    if (finalPayload == null) break;

                    if (finalPayload.Length >= 6)
                    {
                        uint respSess = ReadUInt(finalPayload, 0);
                        ushort respCmd = ReadUShort(finalPayload, 4);
                        byte[] respData = new byte[finalPayload.Length - 6];
                        Array.Copy(finalPayload, 6, respData, 0, respData.Length);

                        Console.WriteLine("--- Received Response ---");
                        Console.WriteLine(parser.Parse(new GamePacket { Len = (ushort)(finalPayload.Length + 2), Cmd = respCmd, Payload = respData }));
                    }
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
            int read = 0;
            while (read < 2)
            {
                int r = stream.Read(lenBuf, read, 2 - read);
                if (r <= 0) return null;
                read += r;
            }

            ushort len = (ushort)((lenBuf[0] << 8) | lenBuf[1]);
            byte[] payload = new byte[len - 2];
            int totalRead = 0;
            while (totalRead < payload.Length)
            {
                read = stream.Read(payload, totalRead, payload.Length - totalRead);
                if (read < 0) break;
                if (read == 0) return null;
                totalRead += read;
            }

            if (handshakeDone && payload.Length > 4)
            {
                byte[] sess = new byte[4];
                Array.Copy(payload, 0, sess, 0, 4);

                byte[] encryptedPart = new byte[payload.Length - 4];
                Array.Copy(payload, 4, encryptedPart, 0, encryptedPart.Length);

                byte[] decrypted = DecryptAES(encryptedPart);
                if (decrypted == null) return payload;

                byte[] result = new byte[4 + decrypted.Length];
                Array.Copy(sess, 0, result, 0, 4);
                Array.Copy(decrypted, 0, result, 4, decrypted.Length);
                return result;
            }
            return payload;
        }

        static void SendPacket(NetworkStream stream, byte[] payload)
        {
            if (handshakeDone && payload.Length >= 4)
            {
                byte[] sess = new byte[4];
                Array.Copy(payload, 0, sess, 0, 4);

                byte[] plainPart = new byte[payload.Length - 4];
                Array.Copy(payload, 4, plainPart, 0, plainPart.Length);

                byte[] encryptedPart = EncryptAES(plainPart);

                byte[] newPayload = new byte[4 + encryptedPart.Length];
                Array.Copy(sess, 0, newPayload, 0, 4);
                Array.Copy(encryptedPart, 0, newPayload, 4, encryptedPart.Length);
                payload = newPayload;
            }

            ushort totalLen = (ushort)(payload.Length + 2);
            byte[] fullPacket = new byte[totalLen];
            fullPacket[0] = (byte)(totalLen >> 8);
            fullPacket[1] = (byte)(totalLen & 0xFF);
            Array.Copy(payload, 0, fullPacket, 2, payload.Length);

            stream.Write(fullPacket, 0, fullPacket.Length);
        }

        static byte[] EncryptAES(byte[] data)
        {
            byte[] iv = new byte[16];
            RandomNumberGenerator.Fill(iv);

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
                if (data.Length < 17) return null;
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

        static uint ReadUInt(byte[] data, int pos)
        {
            return (uint)((data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]);
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
