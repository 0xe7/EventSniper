using EventSniper.ClientData;
using System;
using System.Collections.Generic;

namespace EventSniper
{
    public class Output
    {
        public static void WriteConsole(string message)
        {
            if (message.StartsWith("[X]"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
            }
            else if (message.StartsWith("[!]"))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
            }
            else if (message.StartsWith("[>]"))
            {
                Console.ForegroundColor = ConsoleColor.Green;
            }
            else if (message.StartsWith("[^]"))
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.White;
            }
            Console.WriteLine(message);
            Console.ForegroundColor = ConsoleColor.White;
        }

        public static void PrintSessionData(Session session)
        {
            int indent = 2;
            string creationTime = "UNKNOWN";
            if (null != session.CreationTime)
                creationTime = session.CreationTime.ToString();
            WriteConsole($"{new string(' ', indent)}Computer: {session.ComputerName}, Logon ID: {session.LogonID}, Username: {session.UserName}, Domain: {session.DomainName}, Creation Time: {creationTime}, Logon Type: {session.LogonType}, Outbound Username: {session.OutboundUserName}, Outbound Domain: {session.OutboundDomainName}");

            WriteConsole("\n========== PARENT SESSION ==========\n");
            WriteConsole($"{new string(' ', indent)}Logon ID: {session.ParentSession.LogonID}, Username: {session.ParentSession.UserName}, Domain: {session.ParentSession.DomainName}");
            WriteConsole($"{new string(' ', indent + 2)}Creation Time: {session.CreationProcess.CreationTime}, PID: {session.CreationProcess.ProcessID}, Name: {session.CreationProcess.ProcessName}");

            WriteConsole("\n========== INITIAL PROCESS ==========\n");
            string initialProcessCreationTime = "UNKNOWN";
            if (null != session.InitialProcess.CreationTime)
                initialProcessCreationTime = session.InitialProcess.CreationTime.ToString();

            string initialCommand = session.InitialProcess.ProcessName;
            if (null != session.InitialProcess.ProcessCommandLine)
                initialCommand = session.InitialProcess.ProcessCommandLine;
            WriteConsole($"{new string(' ', indent)}Creation Time: {initialProcessCreationTime}, PID: {session.InitialProcess.ProcessID}, Name: {session.InitialProcess.ProcessName}, PPID: {session.InitialProcess.ParentProcessID}, Mandatory Label: {session.InitialProcess.MandatoryLabel}, Command Line:\n{initialCommand}");

            indent += 2;
            WriteConsole("\n========== PROCESSES ==========\n");
            session.Processes.Sort((x, y) => Nullable.Compare(x.CreationTime, y.CreationTime));
            foreach (var process in session.Processes)
            {
                string processCreationTime = "UNKNOWN";
                if (null != process.CreationTime)
                    processCreationTime = process.CreationTime.ToString();

                string command = process.ProcessName;
                if (null != process.ProcessCommandLine)
                    command = process.ProcessCommandLine;
                WriteConsole($"{new string(' ', indent)}Creation Time: {processCreationTime}, PID: {process.ProcessID}, Name: {process.ProcessName}, PPID: {process.ParentProcessID}, Mandatory Label: {process.MandatoryLabel}, Command Line:\n{command}");

                if (process.NetworkConnections.Count > 0)
                {
                    int newIndent = indent + 2;
                    WriteConsole($"{new string(' ', newIndent)}Network Connections: [");
                    newIndent += 4;
                    foreach (var networkConnection in process.NetworkConnections)
                    {
                        string networkTime = "UNKNOWN";
                        if (null != networkConnection.ConnectionTime)
                            networkTime = networkConnection.ConnectionTime.ToString();

                        if (networkConnection.Direction == "Inbound")
                        {
                            WriteConsole($"{new string(' ', newIndent)}Time: {networkTime}, {networkConnection.DestinationAddress}:{networkConnection.DestinationPort} <-- {networkConnection.SourceAddress}:{networkConnection.SourcePort} ({networkConnection.Protocol})");
                        }
                        else
                        {
                            WriteConsole($"{new string(' ', newIndent)}Time: {networkTime}, {networkConnection.SourceAddress}:{networkConnection.SourcePort} --> {networkConnection.DestinationAddress}:{networkConnection.DestinationPort} ({networkConnection.Protocol})");
                        }
                    }
                    newIndent -= 4;
                    WriteConsole($"{new string(' ', newIndent)}]");
                    //WriteConsole("");
                }

                /*if (process.Listeners.Count > 0)
                {
                    int newIndent = indent += 2;
                    WriteConsole($"{new string(' ', newIndent)}Listeners: [");
                    newIndent += 4;
                    foreach (var listener in process.Listeners)
                    {
                        string listenerTime = "UNKNOWN";
                        if (null != listener.CreationTime)
                            listenerTime = listener.CreationTime.ToString();

                        WriteConsole($"{new string(' ', newIndent)}Time: {listenerTime}, {listener.SourceAddress}:{listener.SourcePort} ({listener.Protocol})");
                    }
                    newIndent -= 4;
                    WriteConsole($"{new string(' ', newIndent)}]");
                }*/
                WriteConsole("");
            }

            WriteConsole("\n========== SESSIONS ==========\n");
            session.ChildSessions.Sort((x, y) => Nullable.Compare(x.CreationTime, y.CreationTime));
            foreach (var childSession in session.ChildSessions)
            {
                string sessionCreationTime = "UNKNOWN";
                if (null != childSession.CreationTime)
                    sessionCreationTime = childSession.CreationTime.ToString();

                WriteConsole($"{new string(' ', indent)}Creation Time: {sessionCreationTime}, Logon ID: {childSession.LogonID}, Username: {childSession.UserName}, Domain: {childSession.DomainName}, Logon Type: {childSession.LogonType}, Outbound Username: {childSession.OutboundUserName}, Outbound Domain: {childSession.OutboundDomainName}");
            }
        }
    }
}
