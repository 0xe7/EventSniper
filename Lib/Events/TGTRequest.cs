using System;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using EventSniper.Hacks;

namespace EventSniper
{
    // 4768
    public class TGTRequest : BaseSecurityEvent
    {
        public override int EventIDNumber { get => 4768; }

        public string AccountName { get; set; }

        public string ShortAccountName { get; set; }

        public string SuppliedDomain { get; set; }

        public string UserID { get; set; }

        public string ServiceName { get; set; }

        public string ServiceID { get; set; }

        public string ClientAddressString { get; set; }

        public IPAddress ClientAddress { get; set; }

        public int ClientPort { get; set; }

        public string TicketOptionsHex { get; set; }

        public Interop.KdcOptions TicketOptions { get; set; }

        public Interop.EncryptionType EncryptionType { get; set; }

        public Interop.PreAuthType PreAuthenticationType { get; set; }

        public TGTRequest() : base() { }

        public TGTRequest(EventRecord eventRecord) : base(eventRecord) { }

        public override void ParseMessage()
        {
            AccountName = GetFieldFromMessage("Account Name");
            ShortAccountName = AccountName.Split('@')[0];

            SuppliedDomain = GetFieldFromMessage("Supplied Realm Name");

            UserID = GetFieldFromMessage("User ID");

            ServiceName = GetFieldFromMessage("Service Name");

            ServiceID = GetFieldFromMessage("Service ID");

            ClientAddressString = GetFieldFromMessage("Client Address");
            ClientAddress = IPAddress.Parse(ClientAddressString);
            if (ClientAddress.IsIPv4MappedToIPv6)
            {
                ClientAddress = IPAddressHacks.MapToIPv4(ClientAddress);
            }

            ClientPort = int.Parse(GetFieldFromMessage("Client Port"));

            TicketOptionsHex = GetFieldFromMessage("Ticket Options").Substring(2);
            TicketOptions = (Interop.KdcOptions)Convert.ToUInt32(TicketOptionsHex, 16);

            string encryptionTypeHex = GetFieldFromMessage("Ticket Encryption Type").Substring(2);
            EncryptionType = (Interop.EncryptionType)Convert.ToInt32(encryptionTypeHex, 16);

            PreAuthenticationType = (Interop.PreAuthType)uint.Parse(GetFieldFromMessage("Pre-Authentication Type"));
        }
    }
}
