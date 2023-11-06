using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Net;

namespace EventSniper
{
    public static class DomainInfo
    {
        public static Domain GetDomain(string domain, string user, string pass)
        {
            DirectoryContext cxt;
            if (!string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(pass))
            {
                if (string.IsNullOrWhiteSpace(domain) && !(user.IndexOf("\\") > 0))
                {
                    throw new ArgumentException($"Alternative credentials supplied but /domain:X not passed and /user:{user} does not include the domain");
                }
                else if (string.IsNullOrWhiteSpace(domain))
                {
                    domain = user.Split('\\')[0];
                    user = user.Split('\\')[1];
                }

                cxt = new DirectoryContext(DirectoryContextType.Domain, domain, user, pass);
            }
            else if (!string.IsNullOrWhiteSpace(domain))
            {
                cxt = new DirectoryContext(DirectoryContextType.Domain, domain);
            }
            else
            {
                cxt = new DirectoryContext(DirectoryContextType.Domain);
            }

            var resolvedDomain = Domain.GetDomain(cxt);

            return resolvedDomain;
        }

        public static SearchResponse GetLDAPInformation(string searchBase, string filter, string dc, NetworkCredential cred, string[] attrs = null, SearchScope scope = SearchScope.Subtree)
        {
            LdapConnection ldapConnection;

            try
            {
                var serverId = new LdapDirectoryIdentifier(dc, 389);
                ldapConnection = new LdapConnection(serverId, cred);
                ldapConnection.Bind();
            }
            catch (Exception ex)
            {
                Output.WriteConsole($"[!] Unable to bind to {dc} on port 389, cannot search LDAP: {ex.Message}");
                return null;
            }

            var request = new SearchRequest(searchBase, filter, scope, attrs);
            return (SearchResponse)ldapConnection.SendRequest(request);
        }

        public static bool? HasSPN(string account, string domain, string dc, NetworkCredential cred)
        {
            var response = GetLDAPInformation($"DC={domain.Replace(".", ",DC=")}", $"(&(samaccountname={account})(serviceprincipalname=*))", dc, cred);
            if (response == null)
            {
                return null;
            }

            if (response.Entries.Count > 0)
            {
                return true;
            }
            return false;
        }

        public static bool? IsReadOnly(DomainController dc, string user, string pass, out string rodcAccountName)
        {
            rodcAccountName = null;

            string searchBase = $"DC={dc.Domain.Name.Replace(".", ",DC=")}";
            string filter = $"(&(dnshostname={dc.Name})(|(primarygroupid=521)(primarygroupid=516)))";
            string[] attrs = { "msds-krbtgtlink" };

            NetworkCredential cred = null;
            if (!string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(pass))
            {
                cred = new NetworkCredential(user, pass, dc.Domain.Name);
            }

            var response = GetLDAPInformation(searchBase, filter, dc.Name, cred, attrs);
            if (response == null)
            {
                return null;
            }

            if (response.Entries.Count > 1)
            {
                Output.WriteConsole($"[!] Got more than 1 result from LDAP query '{filter}'");
                return null;
            }

            if (response.Entries.Count > 0)
            {
                SearchResultEntry entry = response.Entries[0];

                string krbtgtDN;
                try
                {
                    krbtgtDN = (string)entry.Attributes["msds-krbtgtlink"].GetValues(typeof(string))[0];
                }
                catch (NullReferenceException)
                {
                    return false;
                }
                filter = $"(distinguishedname={krbtgtDN})";
                attrs = new string[] { "samaccountname" };

                var krbtgtResponse = GetLDAPInformation(krbtgtDN, filter, dc.Name, cred, attrs, SearchScope.Base);

                if (krbtgtResponse == null)
                {
                    return true;
                }

                if (krbtgtResponse.Entries.Count > 1)
                {
                    Output.WriteConsole($"[!] Got more than 1 result from LDAP query '{filter}'");
                    return true;
                }

                if (krbtgtResponse.Entries.Count > 0)
                {
                    entry = krbtgtResponse.Entries[0];
                    rodcAccountName = (string)entry.Attributes["samaccountname"].GetValues(typeof(string))[0];
                    return true;
                }
            }
            return true;
        }
    }
}
