using System.Net;
using System.Net.Sockets;

namespace EventSniper.Hacks
{
    public static class IPAddressHacks
    {
        // hack to map to IPv4 address
        // as per: https://stackoverflow.com/questions/23608829/why-does-ipaddress-maptoipv4-throw-argumentoutofrangeexception
        public static IPAddress MapToIPv4(IPAddress ipAddress)
        {
            int IPv6AddressBytes = 16;
            int NumberOfLabels = IPv6AddressBytes / 2;
            ushort[] m_Numbers = new ushort[NumberOfLabels];

            if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                return ipAddress;
            }

            byte[] addressBytes = ipAddress.GetAddressBytes();
            
            for (int i = 0; i < NumberOfLabels; i++)
            {
                m_Numbers[i] = (ushort)(addressBytes[i * 2] * 256 + addressBytes[i * 2 + 1]);
            }

            long address = ((((uint)m_Numbers[6] & 0x0000FF00u) >> 8) | (((uint)m_Numbers[6] & 0x000000FFu) << 8)) |
                    (((((uint)m_Numbers[7] & 0x0000FF00u) >> 8) | (((uint)m_Numbers[7] & 0x000000FFu) << 8)) << 16);

            return new IPAddress(address);
        }
    }
}