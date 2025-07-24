using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Cryptography;

namespace SharpSuccessor
{
    internal class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Console.WriteLine("   _____ _                      _____                                        \r\n  / ____| |                    / ____|                                       \r\n | (___ | |__   __ _ _ __ _ __| (___  _   _  ___ ___ ___  ___ ___  ___  _ __ \r\n  \\___ \\| '_ \\ / _` | '__| '_ \\\\___ \\| | | |/ __/ __/ _ \\/ __/ __|/ _ \\| '__|\r\n  ____) | | | | (_| | |  | |_) |___) | |_| | (_| (_|  __/\\__ \\__ \\ (_) | |   \r\n |_____/|_| |_|\\__,_|_|  | .__/_____/ \\__,_|\\___\\___\\___||___/___/\\___/|_|   \r\n                         | |                                                 \r\n                         |_|                                                 \r\n@_logangoins\n");
                Modules.ArgParse.Execute(args);

            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Exception: " + e.Message);
            }
        }
    }
}
