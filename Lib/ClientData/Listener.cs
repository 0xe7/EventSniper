using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace EventSniper.ClientData
{
    public class Listener
    {
        public DateTime? CreationTime { get; set; }

        public IPAddress SourceAddress { get; set; }

        public uint SourcePort { get; set; }

        public Interop.Protocol Protocol { get; set; }

        public Listener() { }

        public Listener(PortListener networkConn)
        {
            CreationTime = networkConn.TimeCreated;
            SourceAddress = networkConn.SourceAddress;
            SourcePort = networkConn.SourcePort;
            Protocol = networkConn.Protocol;
        }
    }
}
