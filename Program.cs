using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace EventSniper
{
    class Program
    {
        public static bool verbose;

        static async Task Main(string[] args)
        {
            Dictionary<string, string> parsedArgs;

            try
            {
                parsedArgs = Arguments.Parse(args);
            }
            catch (ArgumentException ex)
            {
                Output.WriteConsole($"[X] Unable to parse arguments: {ex.Message}");
                return;
            }

            verbose = parsedArgs.ContainsKey("verbose");

            if (parsedArgs.ContainsKey("u2u"))
            {
                U2U u2u = new U2U();
                await u2u.Check(parsedArgs);
            }
            if (parsedArgs.ContainsKey("asreq"))
            {
                ASST asst = new ASST();
                await asst.Check(parsedArgs);
            }
        }
    }
}
