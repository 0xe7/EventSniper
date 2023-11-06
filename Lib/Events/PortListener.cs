using EventSniper.Hacks;
using System.Diagnostics.Eventing.Reader;
using System.Net;

namespace EventSniper
{
    public class PortListener : BaseSecurityEvent
    {
        public override int EventIDNumber { get => 5154; }

        public uint ProcessID { get; set; }

        public string Application { get; set; }

        public string SourceAddressString { get; set; }

        public IPAddress SourceAddress { get; set; }

        public uint SourcePort { get; set; }

        public Interop.Protocol Protocol { get; set; }

        public int FilterRTID { get; set; }

        public string LayerName { get; set; }

        public int LayerRTID { get; set; }

        public PortListener() : base() { }

        public PortListener(EventRecord eventRecord) : base(eventRecord) { }

        public override void ParseMessage()
        {
            ProcessID = uint.Parse(GetFieldFromMessage("Process ID"));

            Application = GetFieldFromMessage("Application Name");

            SourceAddressString = GetFieldFromMessage("Source Address");
            SourceAddress = IPAddress.Parse(SourceAddressString);
            if (SourceAddress.IsIPv4MappedToIPv6)
            {
                SourceAddress = IPAddressHacks.MapToIPv4(SourceAddress);
            }

            SourcePort = uint.Parse(GetFieldFromMessage("Source Port"));

            Protocol = (Interop.Protocol)uint.Parse(GetFieldFromMessage("Protocol"));
        }
    }
}
