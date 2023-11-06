using EventSniper.ClientData;
using EventSniper.Lib.Hacks;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace EventSniper
{
    public abstract class BaseDetection
    {
        public string domain = null;

        public string user = null;

        public string pass = null;

        public string server = null;

        public Dictionary<string, string> Args { get; set; }

        public abstract string EventQueryString { get; }

        public abstract string EventPath { get; }

        public Domain DomainObject { get; set; }

        public DomainControllerCollection DCs { get; set; }

        public async Task<List<Task<List<object>>>> GetReaderTasks(Func<DomainControllerCollection, Dictionary<DomainController, string>> dcFunc = null)
        {
            if (Args.ContainsKey("domain"))
            {
                domain = Args["domain"];
            }
            if (Args.ContainsKey("user"))
            {
                user = Args["user"];
            }
            if (Args.ContainsKey("pass"))
            {
                pass = Args["pass"];
            }
            if (Args.ContainsKey("server"))
            {
                server = Args["server"];
            }

            try
            {
                DomainObject = DomainInfo.GetDomain(domain, user, pass);
                DCs = DomainObject.DomainControllers;
                if (string.IsNullOrWhiteSpace(domain))
                {
                    domain = DomainObject.Name;
                }
            }
            catch (ArgumentException ex)
            {
                Output.WriteConsole($"[X] Invalid arguments: {ex.Message}");
                return null;
            }
            catch (ActiveDirectoryOperationException ex)
            {
                Output.WriteConsole($"[X] Unable to query the domain: {ex.Message}");
                return null;
            }

            if (string.IsNullOrWhiteSpace(server))
            {
                server = DCs[0].Name;
            }

            var dcQueries = new Dictionary<DomainController, string>();
            if (dcFunc != null)
            {
                dcQueries = dcFunc(DCs);
            }

            var tasks = new List<Task<List<object>>>();
            foreach (DomainController dc in DCs)
            {
                string qs = EventQueryString;
                if (dcQueries != null && dcQueries.Count > 0)
                {
                    qs = dcQueries[dc];
                }

                var reader = Events.GetEventReader(qs, dc.Name, domain, user, pass, path: EventPath);

                if (reader != null)
                {
                    var task = Task<List<object>>.Factory.StartNew(() => { return ParseEvents(reader, dc.Name); });
                    tasks.Add(task);
                }
            }

            await Task.WhenAll(tasks);

            return tasks;
        }

        public Dictionary<IPAddress, List<Tuple<object, List<Session>>>> RetrieveClientInformation(Dictionary<IPAddress, List<object>> serverEvents)
        {
            var returnEvents = new Dictionary<IPAddress, List<Tuple<object, List<Session>>>>();

            foreach (var ip in serverEvents.Keys)
            {
                if (!returnEvents.ContainsKey(ip))
                {
                    returnEvents[ip] = new List<Tuple<object, List<Session>>>();
                }

                foreach (var serverEvent in serverEvents[ip])
                {
                    int clientPort = -1, serverPort = -1;
                    DateTime? created = null;
                    string serverName = null;

                    if (serverEvent is TGTRequest tgtRequest)
                    {
                        clientPort = tgtRequest.ClientPort;
                        serverPort = 88;
                    }
                    else if (serverEvent is STRequest stRequest)
                    {
                        clientPort = stRequest.ClientPort;
                        serverPort = 88;
                    }
                    if (serverEvent is BaseSecurityEvent systemEvent)
                    {
                        created = systemEvent.TimeCreated;
                        serverName = systemEvent.LogComputer;
                    }

                    string qs = $"*[System[(EventID={new NetworkConnection().EventIDNumber})]]";
                    if (clientPort > -1 && serverPort > -1)
                    {
                        IPAddress[] serverIPs = Dns.GetHostAddresses(serverName);

                        qs += $" and *[EventData[Data[@Name='DestPort']={serverPort}]]";
                        qs += $" and *[EventData[Data[@Name='SourcePort']={clientPort}]]";
                        qs += $" and *[EventData[Data[@Name='SourceAddress']='{ip}']] and (*[EventData[Data[@Name='DestAddress']='";

                        qs += string.Join("']] or *[EventData[Data[@Name='DestAddress']='", (object[])serverIPs);

                        qs += "']])";
                    }

                    if (created != null)
                    {
                        DateTime startRange = ((DateTime)created).AddMinutes(-5);
                        DateTime endRange = ((DateTime)created).AddMinutes(5);

                        qs += $" and *[System[TimeCreated[@SystemTime >= '{startRange.ToUniversalTime():o}']]] and *[System[TimeCreated[@SystemTime <= '{endRange.ToUniversalTime():o}']]]";
                    }

                    if (Program.verbose)
                        Output.WriteConsole($"[^] Using event query: {qs}");

                    var sessions = new List<Session>();
                    var reader = Events.GetEventReader(qs, ip.ToString(), domain, user, pass, path: new NetworkConnection().EventPath);

                    if (reader != null)
                    {
                        if (Program.verbose)
                            Output.WriteConsole($"[^] Reading '{new NetworkConnection().EventIDNumber}' events from {ip}");

                        int count = 0;
                        EventRecord eventRecord = reader.ReadEvent();
                        while (eventRecord != null)
                        {
                            count += 1;
                            NetworkConnection networkEvent = new NetworkConnection(eventRecord);

                            // get process creation
                            var processEvent = GetProcessInformation(networkEvent);

                            if (null != processEvent)
                            {
                                LUID logonID = processEvent.SubjectLogonID;
                                string userName = processEvent.SubjectUserName;
                                string computerName = processEvent.LogComputer;

                                // get all session data
                                Session session = GetSessionInformation(computerName, logonID, userName);

                                if (null != session)
                                {
                                    session.TriggerProcess = new Process(processEvent);
                                }
                                else
                                {
                                    session = new Session(processEvent, triggerProcess: true);
                                }

                                sessions.Add(session);
                            }

                            eventRecord = reader.ReadEvent();
                        }

                        if (Program.verbose)
                            Output.WriteConsole($"[^] Read {count} '{new NetworkConnection().EventIDNumber}' event(s) from {ip}");
                    }

                    returnEvents[ip].Add(new Tuple<object, List<Session>>(serverEvent, sessions));
                }
            }

            return returnEvents;
        }

        public NewProcess GetProcessInformation(NetworkConnection networkEvent)
        {
            DateTime? created = networkEvent.TimeCreated;
            uint processID = networkEvent.ProcessID;
            NewProcess newProcess = null;

            string[] networkPathSplit = networkEvent.Application.Split(Path.DirectorySeparatorChar);
            string networkPath = string.Join(Path.DirectorySeparatorChar.ToString(), networkPathSplit.Skip(3));

            string qs = $"*[System[(EventID={new NewProcess().EventIDNumber})]]";
            qs += $" and *[EventData[Data[@Name='NewProcessId']={processID}]]";
            if (created != null)
            {
                qs += $" and *[System[TimeCreated[@SystemTime <= '{((DateTime)created).ToUniversalTime():o}']]]";
            }

            if (Program.verbose)
                Output.WriteConsole($"[^] Using event query: {qs}");

            var reader = Events.GetEventReader(qs, networkEvent.LogComputer, domain, user, pass, path: new NewProcess().EventPath);

            if (null != reader)
            {
                if (Program.verbose)
                    Output.WriteConsole($"[^] Reading '{new NewProcess().EventIDNumber}' events from {networkEvent.LogComputer}");

                int count = 0;
                EventRecord eventRecord = reader.ReadEvent();
                while (eventRecord != null)
                {
                    count += 1;
                    var tmpProcess = new NewProcess(eventRecord);

                    string[] processNameSplit = tmpProcess.ProcessName.Split(Path.DirectorySeparatorChar);
                    string processName = string.Join(Path.DirectorySeparatorChar.ToString(), processNameSplit.Skip(1));

                    if (processName.ToLower() == networkPath.ToLower())
                    {
                        newProcess = tmpProcess;
                        break;
                    }

                    eventRecord = reader.ReadEvent();
                }

                if (Program.verbose)
                    Output.WriteConsole($"[^] Read {count} '{new NewProcess().EventIDNumber}' event(s) from {networkEvent.LogComputer}");
            }

            return newProcess;
        }

        public Session GetSessionInformation(string computerName, LUID logonID, string userName)
        {
            Session session = null;

            string qs = "*[System[EventID={0} or EventID={1}]] and ((*[EventData[Data[@Name='TargetLogonId']='{2}']] and *[EventData[Data[@Name='TargetUserName']='{3}']]) or (*[EventData[Data[@Name='SubjectLogonId']='{2}']] and *[EventData[Data[@Name='SubjectUserName']='{3}']]))";
            qs = string.Format(qs, new NewProcess().EventIDNumber, new NewLogon().EventIDNumber, logonID, userName);

            if (Program.verbose)
                Output.WriteConsole($"[^] Using event query: {qs}");

            var reader = Events.GetEventReader(qs, computerName, domain, user, pass, path: new NewProcess().EventPath);

            if (null != reader)
            {
                session = new Session();

                if (Program.verbose)
                    Output.WriteConsole($"[^] Reading '{new NewProcess().EventIDNumber}' and '{new NewLogon().EventIDNumber}' events from {computerName}");

                int count = 0;
                EventRecord eventRecord = reader.ReadEvent();

                string networkQueryString = $"*[System[EventID={new NetworkConnection().EventIDNumber} or EventID={new PortListener().EventIDNumber}]] and (";
                var networkPIDs = new List<uint>();

                while (null != eventRecord)
                {
                    count += 1;

                    if (eventRecord.Id == new NewLogon().EventIDNumber)
                    {
                        var newLogon = new NewLogon(eventRecord);
                        var newSession = new Session(newLogon);

                        if (newSession.LogonID == logonID)
                        {
                            session.UpdateSession(newLogon);
                        }
                        else
                        {
                            session.ChildSessions.Add(newSession);
                        }
                    }
                    else if (eventRecord.Id == new NewProcess().EventIDNumber)
                    {
                        var newProcess = new NewProcess(eventRecord);

                        DateTime processTime = (DateTime)newProcess.TimeCreated;
                        uint pid = newProcess.ProcessID;
                        if (networkPIDs.Count == 0)
                        {
                            networkQueryString += $"(*[EventData[Data[@Name='ProcessID']={pid}]] and *[System[TimeCreated[@SystemTime >= '{processTime.ToUniversalTime():o}']]])";
                        }
                        else if (!networkPIDs.Contains(pid))
                        {
                            networkQueryString += $" or (*[EventData[Data[@Name='ProcessID']={pid}]] and *[System[TimeCreated[@SystemTime >= '{processTime.ToUniversalTime():o}']]])";
                        }
                        networkPIDs.Add(pid);

                        if (newProcess.SubjectLogonID == logonID)
                        {
                            session.Processes.Add(new Process(newProcess));
                        }
                        else
                        {
                            session.InitialProcess = new Process(newProcess, initialProcess: true);
                        }
                    }

                    eventRecord = reader.ReadEvent();
                }

                if (Program.verbose)
                    Output.WriteConsole($"[^] Read {count} '{new NewProcess().EventIDNumber}' and '{new NewLogon().EventIDNumber}' events from {computerName}");

                networkQueryString += ")";
                var items = GetNetworkConnections(computerName, networkQueryString);

                var networkConnections = items.Item1;
                var listeners = items.Item2;

                var sessionProcesses = session.Processes;
                session.Processes = new List<Process>();
                foreach (var process in sessionProcesses)
                {
                    if (networkConnections.ContainsKey(process.ProcessID))
                    {
                        process.NetworkConnections = networkConnections[process.ProcessID];
                    }
                    if (listeners.ContainsKey(process.ProcessID))
                    {
                        process.Listeners = listeners[process.ProcessID];
                    }
                    session.Processes.Add(process);
                }
            }

            return session;
        }

        public Tuple<Dictionary<uint, List<Network>>, Dictionary<uint, List<Listener>>> GetNetworkConnections(string computerName, string queryString)
        {
            var networkConnections = new Dictionary<uint, List<Network>>();
            var listeners = new Dictionary<uint, List<Listener>>();

            if (Program.verbose)
                Output.WriteConsole($"[^] Using event query: {queryString}");

            var reader = Events.GetEventReader(queryString, computerName, domain, user, pass, path: new NetworkConnection().EventPath);

            if (null != reader)
            {
                if (Program.verbose)
                    Output.WriteConsole($"[^] Reading '{new NetworkConnection().EventIDNumber}' and '{new PortListener().EventIDNumber}' events from {computerName}");

                int count = 0;
                EventRecord eventRecord = reader.ReadEvent();

                while (null != eventRecord)
                {
                    count += 1;

                    if (eventRecord.Id == new NetworkConnection().EventIDNumber)
                    {
                        var networkConnection = new NetworkConnection(eventRecord);

                        if (!networkConnections.ContainsKey(networkConnection.ProcessID))
                        {
                            networkConnections[networkConnection.ProcessID] = new List<Network>();
                        }
                        networkConnections[networkConnection.ProcessID].Add(new Network(networkConnection));
                    }

                    if (eventRecord.Id == new PortListener().EventIDNumber)
                    {
                        var listener = new PortListener(eventRecord);

                        if (!listeners.ContainsKey(listener.ProcessID))
                        {
                            listeners[listener.ProcessID] = new List<Listener>();
                        }
                        listeners[listener.ProcessID].Add(new Listener(listener));
                    }

                    eventRecord = reader.ReadEvent();
                }

                if (Program.verbose)
                    Output.WriteConsole($"[^] Read {count} '{new NetworkConnection().EventIDNumber}' and '{new PortListener().EventIDNumber}' events from {computerName}");
            }

            return Tuple.Create(networkConnections, listeners);
        }

        //public abstract async Task Check(Dictionary<string, string> args);

        public abstract List<object> ParseEvents(EventLogReader reader, string dc);
    }
}
