using System;
using System.Diagnostics.Eventing.Reader;

namespace EventSniper
{
    public abstract class BaseSecurityEvent
    {
        public abstract int EventIDNumber { get; }

        public string EventPath { get => "Security"; }

        public string FullMessage { get; set; }

        public string LogComputer { get; set; }

        public int EventID { get; set; }

        public long? EventRecordID { get; set; }

        public DateTime? TimeCreated { get; set; }

        public string ProviderName { get; set; }

        public BaseSecurityEvent() { }

        public BaseSecurityEvent(EventRecord eventRecord)
        {
            FullMessage = eventRecord.FormatDescription();
            LogComputer = eventRecord.MachineName;
            EventID = eventRecord.Id;
            EventRecordID = eventRecord.RecordId;
            TimeCreated = eventRecord.TimeCreated;
            ProviderName = eventRecord.ProviderName;

            ParseMessage();
        }

        public string GetFieldFromMessage(string name)
        {
            return GetFieldFromBlock(name, FullMessage);
        }

        public string GetFieldFromBlock(string name, string block)
        {
            string tmp = block.Split(new string[] { $"{name}:" }, StringSplitOptions.None)[1].Split(Environment.NewLine.ToCharArray())[0].Trim();
            if ("-" == tmp)
            {
                tmp = null;
            }
            return tmp;
        }

        public abstract void ParseMessage();
    }
}
