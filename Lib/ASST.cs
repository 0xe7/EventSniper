using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices.ActiveDirectory;
using System.Net;
using System.Threading.Tasks;

namespace EventSniper
{
    public class ASST : BaseDetection
    {
        public override string EventQueryString { get => $"*[System[EventID={new TGTRequest().EventIDNumber}]] and *[EventData[Data[@Name='ServiceName']!='krbtgt']]"; }

        public override string EventPath { get => new TGTRequest().EventPath; }

        public async Task Check(Dictionary<string, string> parsedArgs)
        {
            Output.WriteConsole("[*] Starting AS-REQ Service Ticket detection\n");

            Args = parsedArgs;

            var tasks = await GetReaderTasks(GetRODCFilter);

            if (null == tasks)
            {
                return;
            }
            Output.WriteConsole("");

            var results = new Dictionary<string, List<TGTRequest>>();
            foreach (var task in tasks)
            {
                foreach (TGTRequest result in task.Result)
                {
                    if (!results.ContainsKey(result.ShortAccountName))
                    {
                        results[result.ShortAccountName] = new List<TGTRequest>();
                    }
                    results[result.ShortAccountName].Add(result);
                }
            }

            foreach (var account in results.Keys)
            {
                Output.WriteConsole($"[>] Got {results[account].Count} event(s) for account {account} requesting STs using AS-REQ's");

                var stats = new Dictionary<IPAddress, Dictionary<string, object>>();
                foreach (var eventRecord in results[account])
                {
                    if (!stats.ContainsKey(eventRecord.ClientAddress))
                    {
                        stats[eventRecord.ClientAddress] = new Dictionary<string, object>();
                    }
                    if (!stats[eventRecord.ClientAddress].ContainsKey("count"))
                    {
                        stats[eventRecord.ClientAddress]["count"] = 0;
                    }
                    stats[eventRecord.ClientAddress]["count"] = (int)stats[eventRecord.ClientAddress]["count"] + 1;

                    if (!stats[eventRecord.ClientAddress].ContainsKey("services"))
                    {
                        stats[eventRecord.ClientAddress]["services"] = new List<string>();
                    }
                    if (!((List<string>)stats[eventRecord.ClientAddress]["services"]).Contains(eventRecord.ServiceName))
                    {
                        ((List<string>)stats[eventRecord.ClientAddress]["services"]).Add(eventRecord.ServiceName);
                    }
                }
                foreach (var ipAddress in stats.Keys)
                {
                    Output.WriteConsole($"[>]     {stats[ipAddress]["count"]} request(s) from {ipAddress} for services: {string.Join(", ", (List<string>)stats[ipAddress]["services"])}");
                }
            }
        }

        public override List<object> ParseEvents(EventLogReader reader, string dc)
        {
            var returnedRequests = new List<object>();
            int count = 0;

            Output.WriteConsole($"[*] Reading events from {dc}");

            EventRecord eventRecord = reader.ReadEvent();
            while (eventRecord != null)
            {
                count += 1;

                TGTRequest tgtRequest = new TGTRequest(eventRecord);
                returnedRequests.Add(tgtRequest);

                eventRecord = reader.ReadEvent();
            }

            Output.WriteConsole($"[*] Read {count} events from {dc}");

            return returnedRequests;
        }

        public Dictionary<DomainController, string> GetRODCFilter(DomainControllerCollection dcs)
        {
            var dcQueries = new Dictionary<DomainController, string>();
            if (!Args.ContainsKey("excluderodc"))
            {
                return null;
            }

            foreach (DomainController dc in dcs)
            {
                if (!dcQueries.ContainsKey(dc))
                {
                    dcQueries[dc] = EventQueryString;
                }

                bool? isRODC = DomainInfo.IsReadOnly(dc, user, pass, out string krbtgtUser);
                if (isRODC == null)
                {
                    Output.WriteConsole($"[!] Unable to determine if '{dc.Name}' is a Read-Only DC!");
                    continue;
                }
                if ((bool)isRODC && !string.IsNullOrWhiteSpace(krbtgtUser))
                {
                    dcQueries[dc] += $" and *[EventData[Data[@Name='ServiceName']!='{krbtgtUser}']]";
                }
            }

            return dcQueries;
        }
    }
}
