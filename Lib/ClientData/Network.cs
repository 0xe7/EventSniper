using System;
using System.Net;

namespace EventSniper.ClientData
{
    public class Network
    {
        public DateTime? ConnectionTime { get; set; }

        public IPAddress SourceAddress { get; set; }

        public uint SourcePort { get; set; }

        public IPAddress DestinationAddress { get; set; }

        public uint DestinationPort { get; set; }

        public Interop.Protocol Protocol { get; set; }

        public string Direction { get; set; }

        public Network() { }

        public Network(NetworkConnection networkConn)
        {
            ConnectionTime = networkConn.TimeCreated;
            SourceAddress = networkConn.SourceAddress;
            SourcePort = networkConn.SourcePort;
            DestinationAddress = networkConn.DestinationAddress;
            DestinationPort = networkConn.DestinationPort;
            Protocol = networkConn.Protocol;
            Direction = networkConn.Direction;
        }
    }
}
