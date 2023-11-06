using EventSniper.Lib.Hacks;
using System;
using System.Collections.Generic;

namespace EventSniper.ClientData
{
    public class Session
    {
        public string ComputerName { get; set; }

        public LUID LogonID { get; set; }

        public string UserID { get; set; }

        public string UserName { get; set; }

        public string DomainName { get; set; }

        public DateTime? CreationTime { get; set; }

        public string OutboundUserName { get; set; }

        public string OutboundDomainName { get; set; }

        public Interop.LogonType LogonType { get; set; }

        public Process TriggerProcess { get; set; }

        public Process InitialProcess { get; set; }

        public Process CreationProcess { get; set; }

        public List<Process> Processes { get; set; }

        public Session ParentSession { get; set; }

        public List<Session> ChildSessions { get; set; }

        public Session() { ReadySession(); }

        public Session(NewLogon newLogon)
        {
            ReadySession();

            UpdateSession(newLogon);
        }

        public Session(string computerName, LUID logonID, string userID, string userName, string domainName)
        {
            ReadySession();

            ComputerName = computerName;
            LogonID = logonID;
            UserID = userID;
            UserName = userName;
            DomainName = domainName;
        }

        public Session(NewProcess newProcess, bool triggerProcess = false)
        {
            ReadySession();

            var process = new Process(newProcess);

            ComputerName = newProcess.LogComputer;
            LogonID = newProcess.SubjectLogonID;
            UserID = newProcess.SubjectUserID;
            UserName = newProcess.SubjectUserName;
            DomainName = newProcess.SubjectDomainName;

            Processes.Add(process);

            if (triggerProcess)
            {
                TriggerProcess = process;
            }
        }

        private void ReadySession()
        {
            CreationTime = null;
            Processes = new List<Process>();
            ChildSessions = new List<Session>();
            TriggerProcess = null;
            InitialProcess = null;
            CreationProcess = null;
            ParentSession = null;
            LogonType = Interop.LogonType.Unknown;
        }

        public void UpdateSession(NewLogon newLogon)
        {
            ComputerName = newLogon.LogComputer;
            LogonID = newLogon.TargetLogonID;
            UserID = newLogon.TargetUserID;
            UserName = newLogon.TargetUserName;
            DomainName = newLogon.TargetDomainName;
            CreationTime = newLogon.TimeCreated;
            OutboundUserName = newLogon.NetworkUserName;
            OutboundDomainName = newLogon.NetworkDomainName;
            LogonType = newLogon.LogonType;

            CreationProcess = new Process(newLogon.ProcessID, newLogon.ProcessName, CreationTime);
            ParentSession = new Session(newLogon.LogComputer, newLogon.SubjectLogonID, newLogon.SubjectUserID, newLogon.SubjectUserName, newLogon.SubjectDomainName);
        }
    }
}
