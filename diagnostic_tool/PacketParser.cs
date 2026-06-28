using System;
using System.Text;
using System.Collections.Generic;

namespace PacketDecoder
{
    public class GamePacket
    {
        public ushort Len;
        public ushort Cmd;
        public byte[] Payload = Array.Empty<byte>();
    }

    public class PacketParser
    {
        public string Parse(GamePacket pkt)
        {
            StringBuilder sb = new StringBuilder();
            string cmdName = CommandMappings.GetName(pkt.Cmd);
            sb.AppendLine($"Packet: {cmdName} (0x{pkt.Cmd:X4}), Total Len: {pkt.Len}");

            if (pkt.Payload == null || pkt.Payload.Length == 0)
            {
                sb.AppendLine("Payload: [Empty]");
                return sb.ToString();
            }

            sb.AppendLine($"Payload Len: {pkt.Payload.Length} bytes");

            try
            {
                int pos = 0;
                switch (pkt.Cmd)
                {
                    case 36: // CMD_CM_KITBAGTEMPlocks
                        ParseKitbagTempLocks(pkt.Payload, ref pos, sb);
                        break;
                    case 355: // CMD_CM_SEND_PRIVATE_KEY
                        ParseSendPrivateKey(pkt.Payload, ref pos, sb);
                        break;
                    case 943: // CMD_MC_SEND_SERVER_PUBLIC_KEY
                        ParseSendServerPublicKey(pkt.Payload, ref pos, sb);
                        break;
                    case 517: // CMD_MC_SYSINFO
                        ParseSysInfo(pkt.Payload, ref pos, sb);
                        break;
                    case 940: // CMD_MC_LOG
                        ParseLog(pkt.Payload, ref pos, sb);
                        break;
                    case 431: // CMD_CM_LOGIN
                        ParseCMLogin(pkt.Payload, ref pos, sb);
                        break;
                    case 931: // CMD_MC_LOGIN
                        ParseMCLogin(pkt.Payload, ref pos, sb);
                        break;
                    default:
                        ParseGeneric(pkt, ref pos, sb);
                        break;
                }

                if (pos < pkt.Payload.Length)
                {
                    int remaining = pkt.Payload.Length - pos;
                    sb.AppendLine($"> Remaining Unparsed Data ({remaining} bytes): " + BitConverter.ToString(pkt.Payload, pos).Replace("-", " "));
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"[Parse Error: {ex.Message}]");
            }

            return sb.ToString();
        }

        private void ParseKitbagTempLocks(byte[] data, ref int pos, StringBuilder sb)
        {
            sb.AppendLine($"> Counter: {ReadUInt(data, ref pos)}");
            sb.AppendLine($"> Value: {ReadUShort(data, ref pos)}");
            sb.AppendLine($"> String: \"{ReadString(data, ref pos)}\"");
        }

        private void ParseSendPrivateKey(byte[] data, ref int pos, StringBuilder sb)
        {
            sb.AppendLine($"> Counter: {ReadUInt(data, ref pos)}");
            sb.AppendLine($"> Encrypted AES Key (Base64): {ReadString(data, ref pos)}");
        }

        private void ParseSendServerPublicKey(byte[] data, ref int pos, StringBuilder sb)
        {
            // CMD_MC_SEND_SERVER_PUBLIC_KEY sends: l_wpk.WriteShort(publickey.size()); l_wpk.WriteSequence(...)
            // WriteSequence also writes a short len. So there are TWO shorts.
            ushort outerLen = ReadUShort(data, ref pos);
            ushort innerLen = ReadUShort(data, ref pos);
            sb.AppendLine($"> RSA Public Key Size: {outerLen} (inner: {innerLen})");

            int keyLen = Math.Min((int)innerLen, data.Length - pos);
            if (keyLen > 0)
            {
                byte[] key = new byte[keyLen];
                Array.Copy(data, pos, key, 0, keyLen);
                sb.AppendLine($"> RSA Public Key (Hex): {BitConverter.ToString(key).Replace("-", "")}");
                pos += keyLen;
            }
        }

        private void ParseSysInfo(byte[] data, ref int pos, StringBuilder sb)
        {
            sb.AppendLine($"> System Message: \"{ReadString(data, ref pos)}\"");
        }

        private void ParseLog(byte[] data, ref int pos, StringBuilder sb)
        {
            sb.AppendLine($"> Log Message: \"{ReadString(data, ref pos)}\"");
        }

        private void ParseCMLogin(byte[] data, ref int pos, StringBuilder sb)
        {
            sb.AppendLine($"> Counter: {ReadUInt(data, ref pos)}");
            sb.AppendLine($"> User: \"{ReadString(data, ref pos)}\"");
            sb.AppendLine($"> Password: \"{ReadString(data, ref pos)}\"");
            sb.AppendLine($"> Version: {ReadUShort(data, ref pos)}");
        }

        private void ParseMCLogin(byte[] data, ref int pos, StringBuilder sb)
        {
            if (data.Length - pos == 2)
            {
                sb.AppendLine($"> Error Code: {ReadUShort(data, ref pos)}");
                return;
            }
            sb.AppendLine($"> Success Flag: {data[pos++]}");
        }

        private void ParseGeneric(GamePacket pkt, ref int pos, StringBuilder sb)
        {
            sb.AppendLine("Hex Dump: " + BitConverter.ToString(pkt.Payload).Replace("-", " "));
            if (pkt.Payload.Length >= 4 && ((pkt.Cmd > 0 && pkt.Cmd <= 500) || (pkt.Cmd >= 6000 && pkt.Cmd <= 6500)))
            {
                sb.AppendLine($"> Counter: {ReadUInt(pkt.Payload, ref pos)}");
            }

            while (pos < pkt.Payload.Length)
            {
                int remain = pkt.Payload.Length - pos;
                if (remain >= 2)
                {
                    ushort strLen = (ushort)((pkt.Payload[pos] << 8) | pkt.Payload[pos + 1]);
                    if (strLen > 0 && strLen <= remain - 2)
                    {
                        string s = Encoding.UTF8.GetString(pkt.Payload, pos + 2, strLen);
                        if (s.Length > 0 && s[s.Length - 1] == '\0')
                        {
                            sb.AppendLine($"> Data String[{strLen}]: \"{s.TrimEnd('\0')}\"");
                            pos += 2 + strLen;
                            continue;
                        }
                    }

                    if (remain >= 4)
                    {
                        uint val = ReadUInt(pkt.Payload, ref pos);
                        sb.AppendLine($"> Data UInt32: {val} (0x{val:X8})");
                    }
                    else
                    {
                        ushort val = ReadUShort(pkt.Payload, ref pos);
                        sb.AppendLine($"> Data UInt16: {val} (0x{val:X4})");
                    }
                }
                else
                {
                    sb.AppendLine($"> Data Byte: {pkt.Payload[pos]} (0x{pkt.Payload[pos]:X2})");
                    pos += 1;
                }
            }
        }

        private ushort ReadUShort(byte[] data, ref int pos)
        {
            if (pos + 2 > data.Length) return 0;
            ushort val = (ushort)((data[pos] << 8) | data[pos + 1]);
            pos += 2;
            return val;
        }

        private uint ReadUInt(byte[] data, ref int pos)
        {
            if (pos + 4 > data.Length) return 0;
            uint val = (uint)((data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]);
            pos += 4;
            return val;
        }

        private string ReadString(byte[] data, ref int pos)
        {
            if (pos + 2 > data.Length) return "";
            ushort len = (ushort)((data[pos] << 8) | data[pos + 1]);
            if (pos + 2 + len > data.Length) return "";
            string s = Encoding.UTF8.GetString(data, pos + 2, len).TrimEnd('\0');
            pos += 2 + len;
            return s;
        }
    }
}
