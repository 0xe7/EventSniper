using EventSniper.Hacks;
using System;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Security.Principal;

namespace EventSniper
{
    // 5156
    public class NetworkConnection : BaseSecurityEvent
    {
        public override int EventIDNumber { get => 5156; }

        public uint ProcessID { get; set; }

        public string Application { get; set; }

        public string Direction { get; set; }

        public string SourceAddressString { get; set; }

        public IPAddress SourceAddress { get; set; }

        public uint SourcePort { get; set; }

        public string DestinationAddressString { get; set; }

        public IPAddress DestinationAddress { get; set; }

        public uint DestinationPort { get; set; }

        public Interop.Protocol Protocol { get; set; }

        public int FilterRTID { get; set; }

        public string LayerName { get; set; }

        public int LayerRTID { get; set; }

        public SecurityIdentifier RemoteUserID { get; set; }

        public SecurityIdentifier RemoteMachineID { get; set; }

        public NetworkConnection() : base() { }

        public NetworkConnection(EventRecord eventRecord) : base(eventRecord) { }

        public override void ParseMessage()
        {
            ProcessID = uint.Parse(GetFieldFromMessage("Process ID"));

            Application = GetFieldFromMessage("Application Name");

            Direction = GetFieldFromMessage("Direction");

            SourceAddressString = GetFieldFromMessage("Source Address");
            SourceAddress = IPAddress.Parse(SourceAddressString);
            if (SourceAddress.IsIPv4MappedToIPv6)
            {
                SourceAddress = IPAddressHacks.MapToIPv4(SourceAddress);
            }

            SourcePort = uint.Parse(GetFieldFromMessage("Source Port"));

            DestinationAddressString = GetFieldFromMessage("Destination Address");
            DestinationAddress = IPAddress.Parse(DestinationAddressString);
            if (DestinationAddress.IsIPv4MappedToIPv6)
            {
                DestinationAddress = IPAddressHacks.MapToIPv4(DestinationAddress);
            }

            DestinationPort = uint.Parse(GetFieldFromMessage("Destination Port"));

            Protocol = (Interop.Protocol)uint.Parse(GetFieldFromMessage("Protocol"));
        }
    }
}
