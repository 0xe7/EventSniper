using EventSniper.Lib.Hacks;
using System;
using System.Collections;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;

namespace EventSniper
{
    // 4688
    public class NewProcess : BaseSecurityEvent
    {
        public override int EventIDNumber { get => 4688; }

        public string SubjectUserID { get; set; }

        public string SubjectUserName { get; set; }

        public string SubjectDomainName { get; set; }

        public LUID SubjectLogonID { get; set; }

        public string TargetUserID { get; set; }

        public string TargetUserName { get; set; }

        public string TargetDomainName { get; set; }

        public LUID TargetLogonID { get; set; }

        public uint ProcessID { get; set; }

        public string ProcessName { get; set; }

        public string TokenType { get; set; }

        public string TokenTypeString { get; set; }

        public SecurityIdentifier MandatoryLabel { get; set; }

        public string MandatoryLabelString { get; set; }

        public uint ParentProcessID { get; set; }

        public string ParentProcessName { get; set; }

        public string ProcessCommandLine { get; set; }

        public NewProcess() : base() { }

        public NewProcess(EventRecord eventRecord) : base(eventRecord) { }

        public override void ParseMessage()
        {
            ProcessID = Convert.ToUInt32(GetFieldFromMessage("New Process ID"), 16);

            ProcessName = GetFieldFromMessage("New Process Name");

            TokenType = GetFieldFromMessage("Token Elevation Type");
            TokenTypeString = (string)TokenTypeHashtable[TokenType];

            MandatoryLabel = new SecurityIdentifier(GetFieldFromMessage("Mandatory Label"));
            MandatoryLabelString = (string)MandatoryLabelHashtable[MandatoryLabel.Value];

            ParentProcessID = Convert.ToUInt32(GetFieldFromMessage("Creator Process ID"), 16);

            ParentProcessName = GetFieldFromMessage("Creator Process Name");

            ProcessCommandLine = GetFieldFromMessage("Process Command Line");

            ParseSubjects();
        }

        public void ParseSubjects()
        {
            string creatorSection = FullMessage.Split(new string[] { "Creator Subject:" }, StringSplitOptions.None)[1].Split(new string[] { "Target Subject:" }, StringSplitOptions.None)[0];
            string targetSection = FullMessage.Split(new string[] { "Target Subject:" }, StringSplitOptions.None)[1].Split(new string[] { "Process Information:" }, StringSplitOptions.None)[0];

            SubjectUserID = GetFieldFromBlock("Security ID", creatorSection);

            SubjectUserName = GetFieldFromBlock("Account Name", creatorSection);

            SubjectDomainName = GetFieldFromBlock("Account Domain", creatorSection);

            SubjectLogonID = new LUID(GetFieldFromBlock("Logon ID", creatorSection));

            TargetUserID = GetFieldFromBlock("Security ID", targetSection);

            TargetUserName = GetFieldFromBlock("Account Name", targetSection);

            TargetDomainName = GetFieldFromBlock("Account Domain", targetSection);

            TargetLogonID = new LUID(GetFieldFromBlock("Logon ID", targetSection));
        }

        private Hashtable MandatoryLabelHashtable = new Hashtable(){
            {"S-1-16-0", "UNTRUSTED_RID"},
            {"S-1-16-4096", "LOW_RID"},
            {"S-1-16-8192", "MEDIUM_RID"},
            {"S-1-16-8448", "MEDIUM_PLUS_RID"},
            {"S-1-16-12288", "HIGH_RID"},
            {"S-1-16-16384", "SYSTEM_RID"},
            {"S-1-16-20480", "PROTECTED_PROCESS_RID"}
        };

        private Hashtable TokenTypeHashtable = new Hashtable(){
            {"%%1936", "FULL_TOKEN"},
            {"%%1937", "ELEVATED_TOKEN"},
            {"%%1938", "NORMAL_TOKEN"}
        };
    }
}
