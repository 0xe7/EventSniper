using EventSniper.ClientData;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Threading.Tasks;

namespace EventSniper
{
    public class U2U : BaseDetection
    {
        public override string EventQueryString { get => $"*[System[EventID={new STRequest().EventIDNumber}]] and *[EventData[band(Data[@Name='TicketOptions'],8)]]"; }

        public override string EventPath { get => new STRequest().EventPath; }

        public async Task Check(Dictionary<string, string> parsedArgs)
        {
            Output.WriteConsole("[*] Starting User-to-User request detection\n");

            Args = parsedArgs;

            var tasks = await GetReaderTasks();

            if (null == tasks)
            {
                return;
            }
            if (Program.verbose)
                Output.WriteConsole("");

            var results = new Dictionary<string, List<STRequest>>();
            foreach (var task in tasks)
            {
                foreach (STRequest result in task.Result)
                {
                    if (!results.ContainsKey(result.ServiceName))
                    {
                        results[result.ServiceName] = new List<STRequest>();
                    }
                    results[result.ServiceName].Add(result);
                }
            }

            NetworkCredential cred = null;
            foreach (var service in results.Keys)
            {
                string ldapMessage = string.Empty;
                if (Args.ContainsKey("ldapverify"))
                {
                    if (!string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(pass) && !string.IsNullOrWhiteSpace(domain))
                    {
                        cred = new NetworkCredential(user, pass, domain);
                    }
                    var hasSPN = DomainInfo.HasSPN(service, domain, server, cred);
                    if (hasSPN != null && (bool)hasSPN)
                    {
                        continue;
                    }
                    ldapMessage += " (which has no SPN set)";
                }

                var ipStats = new Dictionary<IPAddress, List<object>>();
                foreach (var eventRecord in results[service])
                {
                    if (!ipStats.ContainsKey(eventRecord.ClientAddress))
                    {
                        ipStats[eventRecord.ClientAddress] = new List<object>();
                    }
                    ((List<object>)ipStats[eventRecord.ClientAddress]).Add(eventRecord);
                }

                var info = RetrieveClientInformation(ipStats);

                if (Program.verbose)
                    Output.WriteConsole("");
                Output.WriteConsole($"[>] Got {results[service].Count} event(s) requesting STs to '{service}'{ldapMessage} containing {Interop.KdcOptions.ENC_TKT_IN_SKEY} in the KdcOptions\n");

                foreach (var ip in info.Keys)
                {
                    foreach (var ipInfo in info[ip])
                    {
                        STRequest stRequest = (STRequest)ipInfo.Item1;
                        List<Session> sessions = ipInfo.Item2;

                        Output.WriteConsole($"[>]   Logged on DC '{stRequest.LogComputer}' for user '{stRequest.AccountName}' from client {stRequest.ClientAddress}:{stRequest.ClientPort}");

                        foreach (var session in sessions)
                        {
                            Output.PrintSessionData(session);
                        }
                    }
                }
            }
        }

        public override List<object> ParseEvents(EventLogReader reader, string dc)
        {
            var returnedRequests = new List<object>();
            int count = 0;

            if (Program.verbose)
                Output.WriteConsole($"[^] Reading '{new STRequest().EventIDNumber}' events from {dc}");

            EventRecord eventRecord = reader.ReadEvent();
            while (eventRecord != null)
            {
                count += 1;
                STRequest stRequest = new STRequest(eventRecord);

                if (stRequest.TicketOptions.HasFlag(Interop.KdcOptions.ENC_TKT_IN_SKEY) && !stRequest.ServiceName.EndsWith("$"))
                {
                    returnedRequests.Add(stRequest);
                }

                eventRecord = reader.ReadEvent();
            }

            if (Program.verbose)
                Output.WriteConsole($"[^] Read {count} '{new STRequest().EventIDNumber}' event(s) from {dc}");

            return returnedRequests;
        }
    }
}
