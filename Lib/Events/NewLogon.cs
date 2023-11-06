using EventSniper.Hacks;
using EventSniper.Lib.Hacks;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace EventSniper
{
    // 4624
    public class NewLogon : BaseSecurityEvent
    {
        public override int EventIDNumber { get => 4624; }

        public string SubjectUserID { get; set; }

        public string SubjectUserName { get; set; }

        public string SubjectDomainName { get; set; }

        public LUID SubjectLogonID { get; set; }

        public string TargetUserID { get; set; }

        public string TargetUserName { get; set; }

        public string TargetDomainName { get; set; }

        public LUID TargetLogonID { get; set; }

        public LUID TargetLinkedLogonID { get; set; }

        public Interop.LogonType LogonType { get; set; }

        public string RestrictedAdminMode { get; set; }

        public string VirtualAccount { get; set; }

        public string ElevatedToken { get; set; }

        public string ImpersonationLevel { get; set; }

        public string NetworkUserName { get; set; }

        public string NetworkDomainName { get; set; }

        public Guid LogonGuid { get; set; }

        public uint ProcessID { get; set; }

        public string ProcessName { get; set; }

        public string WorkstationName { get; set; }

        public IPAddress SourceNetworkAddress { get; set; }

        public string SourceNetworkAddressString { get; set; }

        public uint SourceNetworkPort { get; set; }

        public string LogonProcess { get; set; }

        public string AuthenticationPackage { get; set; }

        public string TransitedServices { get; set; }

        public string PackageName { get; set; }

        public uint KeyLength { get; set; }

        public NewLogon() : base() { }

        public NewLogon(EventRecord eventRecord) : base(eventRecord) { }

        public override void ParseMessage()
        {
            LogonType = (Interop.LogonType)uint.Parse(GetFieldFromMessage("Logon Type"));

            RestrictedAdminMode = GetFieldFromMessage("Restricted Admin Mode");

            VirtualAccount = GetFieldFromMessage("Virtual Account");

            ElevatedToken = GetFieldFromMessage("Elevated Token");

            ImpersonationLevel = GetFieldFromMessage("Impersonation Level");

            TargetLinkedLogonID = new LUID(GetFieldFromMessage("Linked Logon ID"));

            NetworkUserName = GetFieldFromMessage("Network Account Name");

            NetworkDomainName = GetFieldFromMessage("Network Account Domain");

            LogonGuid = new Guid(GetFieldFromMessage("Logon GUID").TrimStart('{').TrimEnd('}'));

            ProcessID = Convert.ToUInt32(GetFieldFromMessage("Process ID"), 16);

            ProcessName = GetFieldFromMessage("Process Name");

            WorkstationName = GetFieldFromMessage("Workstation Name");

            SourceNetworkAddressString = GetFieldFromMessage("Source Network Address");
            if (!string.IsNullOrWhiteSpace(SourceNetworkAddressString))
            {
                SourceNetworkAddress = IPAddress.Parse(SourceNetworkAddressString);
                if (SourceNetworkAddress.IsIPv4MappedToIPv6)
                {
                    SourceNetworkAddress = IPAddressHacks.MapToIPv4(SourceNetworkAddress);
                }
            }

            string tmpPort = GetFieldFromMessage("Source Port");
            if (!string.IsNullOrWhiteSpace(tmpPort))
            {
                SourceNetworkPort = uint.Parse(tmpPort);
            }

            LogonProcess = GetFieldFromMessage("Logon Process");

            AuthenticationPackage = GetFieldFromMessage("Authentication Package");

            TransitedServices = GetFieldFromMessage("Transited Services");

            PackageName = GetFieldFromMessage("Package Name (NTLM only)");

            KeyLength = uint.Parse(GetFieldFromMessage("Key Length"));

            ParseSubjects();
        }

        public void ParseSubjects()
        {
            string subjectSection = FullMessage.Split(new string[] { "Subject:" }, StringSplitOptions.None)[1].Split(new string[] { "Logon Information:" }, StringSplitOptions.None)[0];
            string targetSection = FullMessage.Split(new string[] { "New Logon:" }, StringSplitOptions.None)[1].Split(new string[] { "Process Information:" }, StringSplitOptions.None)[0];

            SubjectUserID = GetFieldFromBlock("Security ID", subjectSection);

            SubjectUserName = GetFieldFromBlock("Account Name", subjectSection);

            SubjectDomainName = GetFieldFromBlock("Account Domain", subjectSection);

            SubjectLogonID = new LUID(GetFieldFromBlock("Logon ID", subjectSection));

            TargetUserID = GetFieldFromBlock("Security ID", targetSection);

            TargetUserName = GetFieldFromBlock("Account Name", targetSection);

            TargetDomainName = GetFieldFromBlock("Account Domain", targetSection);

            TargetLogonID = new LUID(GetFieldFromBlock("Logon ID", targetSection));
        }
    }
}
