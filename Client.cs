using System;
using System.Linq;
using System.Net;
using System.IO;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Threading;
using System.Runtime.InteropServices;
using System.Text;

namespace Sharpcat
{
    public class Client
    {
        public static bool Connect(String ipaddress, int port, out Socket client)
        {
            IPAddress ip = IPAddress.Parse(ipaddress);

            //Console.WriteLine("Connecting to IP address {0} and port {1}", ip.ToString(), port);

            IPEndPoint remoteEP = new IPEndPoint(ip, port);
            client = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                client.Connect(remoteEP);
            }
            catch (SocketException se)
            {
                Console.WriteLine("SocketException : {0}", se.ToString());
                return false;
            }
            catch (Exception e)
            {
                Console.WriteLine("Unexpected exception : {0}", e.ToString());
                return false;
            }
            return true;
        }

        public static void Close(Socket client)
        {
            client.Close();
        }
    }
}