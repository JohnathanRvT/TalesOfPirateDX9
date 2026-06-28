using System;
using System.Text;
using System.Linq;

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
                switch (pkt.Cmd)
                {
                    case 36: // CMD_CM_KITBAGTEMPlocks
                        ParseKitbagTempLocks(pkt, sb);
                        break;
                    case 355: // CMD_CM_SEND_PRIVATE_KEY
                        ParseSendPrivateKey(pkt, sb);
                        break;
                    case 943: // CMD_MC_SEND_SERVER_PUBLIC_KEY
                        ParseSendServerPublicKey(pkt, sb);
                        break;
                    case 517: // CMD_MC_SYSINFO
                        ParseSysInfo(pkt, sb);
                        break;
                    case 940: // CMD_MC_LOG (Inferred from example)
                        ParseLog(pkt, sb);
                        break;
                    default:
                        ParseGeneric(pkt, sb);
                        break;
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"[Parse Error: {ex.Message}]");
                ParseGeneric(pkt, sb);
            }

            return sb.ToString();
        }

        private void ParseKitbagTempLocks(GamePacket pkt, StringBuilder sb)
        {
            int pos = 0;
            if (pkt.Payload.Length >= 4)
            {
                uint counter = ReadUInt(pkt.Payload, ref pos);
                sb.AppendLine($"> Counter: {counter}");
            }
            if (pos + 2 <= pkt.Payload.Length)
            {
                ushort val = ReadUShort(pkt.Payload, ref pos);
                sb.AppendLine($"> Value: {val}");
            }
            string s = ReadString(pkt.Payload, ref pos);
            sb.AppendLine($"> String: \"{s}\"");
        }

        private void ParseSendPrivateKey(GamePacket pkt, StringBuilder sb)
        {
            int pos = 0;
            if (pkt.Payload.Length >= 4)
            {
                uint counter = ReadUInt(pkt.Payload, ref pos);
                sb.AppendLine($"> Counter: {counter}");
            }
            string key = ReadString(pkt.Payload, ref pos);
            sb.AppendLine($"> Encrypted AES Key (Base64): {key}");
        }

        private void ParseSendServerPublicKey(GamePacket pkt, StringBuilder sb)
        {
            int pos = 0;
            ushort keyLen = ReadUShort(pkt.Payload, ref pos);
            sb.AppendLine($"> RSA Public Key Len: {keyLen}");
            if (pos + keyLen <= pkt.Payload.Length)
            {
                byte[] key = new byte[keyLen];
                Array.Copy(pkt.Payload, pos, key, 0, keyLen);
                sb.AppendLine($"> RSA Public Key (Hex): {BitConverter.ToString(key).Replace("-", "")}");
            }
        }

        private void ParseSysInfo(GamePacket pkt, StringBuilder sb)
        {
            int pos = 0;
            string msg = ReadString(pkt.Payload, ref pos);
            sb.AppendLine($"> System Message: \"{msg}\"");
        }

        private void ParseLog(GamePacket pkt, StringBuilder sb)
        {
            int pos = 0;
            string log = ReadString(pkt.Payload, ref pos);
            sb.AppendLine($"> Log Message: \"{log}\"");
        }

        private void ParseGeneric(GamePacket pkt, StringBuilder sb)
        {
            sb.AppendLine("Hex Dump: " + BitConverter.ToString(pkt.Payload).Replace("-", " "));
            int pos = 0;
            // Many client packets have a 4-byte counter at the start
            if (pkt.Payload.Length >= 4 && ((pkt.Cmd > 0 && pkt.Cmd <= 500) || (pkt.Cmd >= 6000 && pkt.Cmd <= 6500)))
            {
                uint counter = ReadUInt(pkt.Payload, ref pos);
                sb.AppendLine($"> Counter: {counter}");
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
                        if (s.EndsWith("\0"))
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
            ushort val = (ushort)((data[pos] << 8) | data[pos + 1]);
            pos += 2;
            return val;
        }

        private uint ReadUInt(byte[] data, ref int pos)
        {
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
