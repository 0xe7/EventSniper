using System;
using System.Collections.Generic;

namespace EventSniper
{
    public static class Arguments
    {
        public static Dictionary<string, string> Parse(string[] args)
        {
            var parsedArgs = new Dictionary<string, string>();
            foreach (string arg in args)
            {
                if (!arg.StartsWith("/"))
                {
                    throw new ArgumentException($"Invalid argument {arg}");
                }

                int argEnd = arg.IndexOf(":");
                string argValue;

                if (argEnd == -1)
                {
                    argEnd = arg.IndexOf("=");
                }

                if (argEnd == -1)
                {
                    argEnd = arg.Length - 1;
                    argValue = null;
                }
                else
                {
                    argValue = arg.Substring(argEnd + 1);
                    argEnd -= 1;
                }

                string argName = arg.Substring(1, argEnd).ToLower();

                parsedArgs[argName] = argValue;
            }

            return VerifyArguments(parsedArgs);
        }

        private static Dictionary<string, string> VerifyArguments(Dictionary<string, string> args)
        {
            if (args.ContainsKey("user") && !args.ContainsKey("pass"))
            {
                args["pass"] = GetPassword();
            }
            if ((!args.ContainsKey("domain") || string.IsNullOrWhiteSpace(args["domain"])) && (args["user"].IndexOf("\\") > 0))
            {
                args["domain"] = args["user"].Split('\\')[0];
                args["user"] = args["user"].Split('\\')[1];
            }

            return args;
        }

        private static string GetPassword()
        {
            var pass = string.Empty;

            Console.Write("Enter User Password: ");
            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    Console.Write("\b \b");
                    pass = pass.Substring(0, pass.Length - 1);
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    pass += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);
            Console.WriteLine();

            return pass;
        }
    }
}
