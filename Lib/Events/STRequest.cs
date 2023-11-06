using System;
using System.Net;
using System.Diagnostics.Eventing.Reader;
using EventSniper.Hacks;

namespace EventSniper
{
    // 4769
    public class STRequest : BaseSecurityEvent
    {
        public override int EventIDNumber { get => 4769; }

        public string AccountName { get; set; }

        public string ShortAccountName { get; set; }

        public string AccountDomain { get; set; }

        public Guid? LogonGUID { get; set; }

        public string ServiceName { get; set; }

        public string ServiceID { get; set; }

        public string ClientAddressString { get; set; }

        public IPAddress ClientAddress { get; set; }

        public int ClientPort { get; set; }

        public string TicketOptionsHex { get; set; }

        public Interop.KdcOptions TicketOptions { get; set; }

        public Interop.EncryptionType EncryptionType { get; set; }

        public int FailureCode { get; set; }

        public string TransitedServices { get; set; }

        public STRequest() : base() { }

        public STRequest(EventRecord eventRecord) : base(eventRecord) { }

        public override void ParseMessage()
        {
            AccountName = GetFieldFromMessage("Account Name");
            ShortAccountName = AccountName.Split('@')[0];

            AccountDomain = GetFieldFromMessage("Account Domain");

            string accountGuid = GetFieldFromMessage("Logon GUID");
            accountGuid = accountGuid.Substring(1, accountGuid.Length - 1);
            try
            {
                LogonGUID = new Guid(accountGuid);
            }
            catch
            {
                LogonGUID = null;
            }

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

            string failureCodeHex = GetFieldFromMessage("Failure Code").Substring(2);
            FailureCode = Convert.ToInt32(failureCodeHex, 16);

            TransitedServices = GetFieldFromMessage("Transited Services");
        }
    }
}
