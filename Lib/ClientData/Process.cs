using EventSniper.Lib.Hacks;
using System;
using System.Collections.Generic;

namespace EventSniper.ClientData
{
    public class Process
    {
        public uint ProcessID { get; set; }

        public string ProcessName { get; set; }

        public string ProcessCommandLine { get; set; }

        public DateTime? CreationTime { get; set; }

        public List<Network> NetworkConnections { get; set; }

        public List<Listener> Listeners { get; set; }

        public string MandatoryLabel { get; set; }

        public uint ParentProcessID { get; set; }

        public LUID SourceLogonID { get; set; }

        public string SourceUserID { get; set; }

        public string SourceUserName { get; set; }

        public string SourceDomainName { get; set; }

        public Process() { ReadyProcess(); }

        public Process(NewProcess newProcess, bool initialProcess = false)
        {
            ReadyProcess();

            ProcessID = newProcess.ProcessID;
            ProcessName = newProcess.ProcessName;
            ProcessCommandLine = newProcess.ProcessCommandLine;
            CreationTime = newProcess.TimeCreated;
            MandatoryLabel = newProcess.MandatoryLabelString;
            ParentProcessID = newProcess.ParentProcessID;

            if (initialProcess)
            {
                SourceLogonID = newProcess.SubjectLogonID;
                SourceUserID = newProcess.SubjectUserID;
                SourceUserName = newProcess.SubjectUserName;
                SourceDomainName = newProcess.SubjectDomainName;
            }
        }

        public Process(uint processID, string processName, DateTime? creationTime)
        {
            ReadyProcess();

            ProcessID = processID;
            ProcessName = processName;
            CreationTime = creationTime;
        }

        private void ReadyProcess()
        {
            CreationTime = null;
            NetworkConnections = new List<Network>();
            Listeners = new List<Listener>();
        }
    }
}
