using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Security;

namespace EventSniper
{
    public static class Events
    {
        public static EventLogReader GetEventReader(string queryString, string machine, string domain, string user, string pass, string path = "Security")
        {
            EventLogSession session;

            if (!string.IsNullOrWhiteSpace(domain) && !string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(pass))
            {
                SecureString securePass = new NetworkCredential("", pass).SecurePassword;

                session = new EventLogSession(machine, domain, user, securePass, SessionAuthentication.Default);

                securePass.Dispose();
            }
            else
            {
                session = new EventLogSession(machine);
            }

            var query = new EventLogQuery(path, PathType.LogName, queryString);
            query.Session = session;

            EventLogReader reader;
            try
            {
                reader = new EventLogReader(query);
            }
            catch (EventLogException ex)
            {
                Output.WriteConsole($"[!] Unable to read events from {machine}: {ex.Message}");
                return null;
            }

            return reader;
        }
    }
}
