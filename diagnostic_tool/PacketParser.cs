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
            sb.AppendLine("Hex Dump: " + BitConverter.ToString(pkt.Payload).Replace("-", " "));

            // Try to parse common structures
            try
            {
                int pos = 0;
                // Many client packets have a 4-byte counter at the start of the payload
                // if WPE protection is active (for IDs 1-500 and 6000-6500)
                if (pkt.Payload.Length >= 4 && ((pkt.Cmd > 0 && pkt.Cmd <= 500) || (pkt.Cmd >= 6000 && pkt.Cmd <= 6500)))
                {
                    uint counter = (uint)((pkt.Payload[0] << 24) | (pkt.Payload[1] << 16) | (pkt.Payload[2] << 8) | pkt.Payload[3]);
                    sb.AppendLine($"> Counter: {counter}");
                    pos = 4;
                }

                // Parse remaining data as generic fields
                while (pos < pkt.Payload.Length)
                {
                    int remain = pkt.Payload.Length - pos;
                    if (remain >= 2)
                    {
                        // Check if it's a string (Short length prefix + null terminated)
                        ushort strLen = (ushort)((pkt.Payload[pos] << 8) | pkt.Payload[pos + 1]);
                        if (strLen > 0 && strLen <= remain - 2)
                        {
                            try
                            {
                                string s = Encoding.UTF8.GetString(pkt.Payload, pos + 2, strLen);
                                if (s.EndsWith("\0"))
                                {
                                    sb.AppendLine($"> String[{strLen}]: \"{s.TrimEnd('\0')}\"");
                                    pos += 2 + strLen;
                                    continue;
                                }
                            }
                            catch { }
                        }

                        if (remain >= 4)
                        {
                            uint val = (uint)((pkt.Payload[pos] << 24) | (pkt.Payload[pos + 1] << 16) | (pkt.Payload[pos + 2] << 8) | pkt.Payload[pos + 3]);
                            sb.AppendLine($"> Long/UInt: {val} (0x{val:X8})");
                            pos += 4;
                        }
                        else
                        {
                            ushort val = (ushort)((pkt.Payload[pos] << 8) | pkt.Payload[pos + 1]);
                            sb.AppendLine($"> Short/UShort: {val} (0x{val:X4})");
                            pos += 2;
                        }
                    }
                    else
                    {
                        sb.AppendLine($"> Char/Byte: {pkt.Payload[pos]} (0x{pkt.Payload[pos]:X2})");
                        pos += 1;
                    }
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"[Parse Error: {ex.Message}]");
            }

            return sb.ToString();
        }
    }
}
