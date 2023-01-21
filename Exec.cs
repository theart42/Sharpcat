using System;
using System.Linq;
using System.Net;
using System.IO;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Threading;
using System.Runtime.InteropServices;
using System.Text;

// using DInvoke.DynamicInvoke;

// Shamelessly ported from do_exec.c in the original Windows netcat

namespace Sharpcat
{
    public class Exec
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SESSION_DATA
        {
            public IntPtr ReadPipeHandle;         // Handle to shell stdout pipe
            public IntPtr WritePipeHandle;        // Handle to shell stdin pipe
            public IntPtr ProcessHandle;          // Handle to shell process

            public Socket ClientSocket;
            public IntPtr StdinPipe;
            public IntPtr StdoutPipe;
            public IntPtr StdErrPipe;
        }

        public const int BUFFER_SIZE = 200;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreatePipe(ref IntPtr hReadPipe, ref IntPtr hWritePipe, IntPtr lpPipeAttributes, int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DuplicateHandle(IntPtr hProcessSource, IntPtr hSource, IntPtr hProcessDest, ref IntPtr hDest, int DesiredAccess, bool inherit, int options);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool PeekNamedPipe(IntPtr namedPipe, byte[] buffer, int buffersize, out int bytesread, out int bytesavailable, IntPtr bytesleft);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DisconnectNamedPipe(IntPtr namedPipe);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(IntPtr filehandle, byte[] buffer, int readnumber, IntPtr bytesread, IntPtr overlapbytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteFile(IntPtr filehandle, byte[] buffer, uint writenumber, out int byteswritten, IntPtr overlapbytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int WaitForMultipleObjects(int nCount, IntPtr[] lpHandles, bool waitall, int waitms);

        // static IntPtr StartShell(String commandline, SESSION_DATA pSession, IntPtr ShellStdinPipeHandle, IntPtr ShellStdoutPipeHandle)
        static IntPtr StartShell(String commandline, SESSION_DATA pSession)
        {
            IntPtr processHandle = IntPtr.Zero;
            IntPtr currentProcess;
            STARTUPINFO         si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // Code
            // Console.WriteLine("Starting shell");

            si.cb = Marshal.SizeOf(si);
            si.lpReserved = IntPtr.Zero;
            si.lpTitle = IntPtr.Zero;
            si.lpDesktop = IntPtr.Zero;
            si.dwX = 0;
            si.dwXSize = 0;
            si.dwY = 0;
            si.dwYSize = 0;
            si.dwFlags = 0x101; //  STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
            si.wShowWindow = 0; //  W_HIDE;

            si.hStdInput = pSession.StdinPipe;
            si.hStdOutput = pSession.StdoutPipe;

            currentProcess = GetCurrentProcess();

            // Console.WriteLine("Got current process handle {0}", currentProcess);

            if (!DuplicateHandle(currentProcess, pSession.StdoutPipe, currentProcess, ref si.hStdError, 0, true, 0x2))
            {
                // Console.WriteLine("error duplicating handle");
                return IntPtr.Zero;
            } // DUPLICATE_SAME_ACCESS

            // Console.WriteLine("Duplicated ShellStdoutPipeHandle handle {0}", si.hStdError);

            if (!(CreateProcessW(null, commandline, IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, null, ref si, out pi)))
            {
                    // bailout
                    // Console.WriteLine("Error creating process, error code: {0}, bailing out", Marshal.GetLastWin32Error());
                return IntPtr.Zero;
            }

            // Console.WriteLine("Process created with PID: {0}.", pi.dwProcessId);

            processHandle = pi.hProcess;

            CloseHandle(pi.hThread);

            return processHandle;
        }

        static bool CreateSession(String commandline, ref SESSION_DATA pSession)
        {
            SECURITY_ATTRIBUTES SecurityAttributes = new SECURITY_ATTRIBUTES();
            IntPtr ShellStdinPipe = IntPtr.Zero;
            IntPtr ShellStdoutPipe = IntPtr.Zero;


            // Code
            // Console.WriteLine("Creating Session");
            SecurityAttributes.nLength = (int)System.Runtime.InteropServices.Marshal.SizeOf(SecurityAttributes);
            SecurityAttributes.lpSecurityDescriptor = IntPtr.Zero;
            SecurityAttributes.bInheritHandle = true;
            IntPtr lpattr = Marshal.AllocHGlobal(Marshal.SizeOf(SecurityAttributes));
            Marshal.StructureToPtr(SecurityAttributes, lpattr, true);

            if (!CreatePipe(ref ShellStdinPipe, ref pSession.WritePipeHandle, lpattr, 0))
            {
                //Console.WriteLine("WritePipe creation error");
                CloseHandle(ShellStdoutPipe);
                CloseHandle(pSession.ReadPipeHandle);
                return false;
            }
            pSession.StdinPipe = ShellStdinPipe;

            // Console.WriteLine("write pipe created, starting shell {0}", commandline);

            // Console.WriteLine("Creating read pipe");
            if (!CreatePipe(ref pSession.ReadPipeHandle, ref ShellStdoutPipe, lpattr, 0))
            {
                // Console.WriteLine("ReadPipe creation error");
                return false;
            }
            pSession.StdoutPipe = ShellStdoutPipe;
            // Console.WriteLine("read pipe created, continuing wth write pipe");

            //pSession.ProcessHandle = StartShell(commandline, pSession, ShellStdinPipe, ShellStdoutPipe);
            pSession.ProcessHandle = StartShell(commandline, pSession);

            CloseHandle(ShellStdoutPipe);
            CloseHandle(ShellStdinPipe);

            if (pSession.ProcessHandle == null)
            {
                Console.WriteLine("Error starting process");
                CloseHandle(pSession.ReadPipeHandle);
                CloseHandle(pSession.WritePipeHandle);
                return false;
            }

            return true;
        }

        static void CleanUp( ref SESSION_DATA pSession)
        {
            //Console.WriteLine("Cleaning up");
            if(pSession.StdinPipe != IntPtr.Zero) {
                //Console.WriteLine("Closing StdinPipe");
                DisconnectNamedPipe(pSession.StdinPipe);
                CloseHandle(pSession.StdinPipe);
            }
            if (pSession.StdoutPipe != IntPtr.Zero) {
                //Console.WriteLine("Closing StdoutPipe");
                DisconnectNamedPipe(pSession.StdoutPipe);
                CloseHandle(pSession.StdoutPipe);
            }
            if (pSession.ReadPipeHandle != IntPtr.Zero) {
                //Console.WriteLine("Closing ReadPipeHandle");
                DisconnectNamedPipe(pSession.ReadPipeHandle);
                CloseHandle(pSession.ReadPipeHandle);
            }
            if (pSession.WritePipeHandle != IntPtr.Zero)
            {
                //Console.WriteLine("Closing WritePipeHandle");
                DisconnectNamedPipe(pSession.WritePipeHandle);
                CloseHandle(pSession.WritePipeHandle);
            }
            if (pSession.ProcessHandle != IntPtr.Zero)
            {
                //Console.WriteLine("Stopping process");
                CloseHandle(pSession.ProcessHandle);
            }
            //Console.WriteLine("Cleaned up");
        }

        static void SessionReadShellThread(ref SESSION_DATA session )
        {
            var buffer = new byte[BUFFER_SIZE];
            int bufsize;
            int bytesread = 0, bytesavailable = 0;
            var buffer2 = new byte[BUFFER_SIZE * 2 + 30];
            int bytestowrite;
            SocketError senderror;

            // Code
            bytesavailable = 0;
            bufsize = BUFFER_SIZE;

            while (PeekNamedPipe(session.ReadPipeHandle, buffer, bufsize, out bytesread, out bytesavailable, IntPtr.Zero))
            {
                int buffercount;
                char prevchar = '\0';

                if( bytesread <= 0 )
                {
                    System.Threading.Thread.Sleep(50);
                }
                else
                {
                    // Console.WriteLine("Processing buffer");

                    // readFile(session.ReadPipeHandle, buffer, bytesread, out realbytesread, IntPtr.Zero);
                    ReadFile(session.ReadPipeHandle, buffer, bytesread, IntPtr.Zero, IntPtr.Zero);
                    //bytestowrite = realbytesread;
                    //if (realbytesread > 0)
                    bytestowrite = bytesread;
                    if (bytesread > 0)
                    {
                        // Console.WriteLine("read buffer bytes {0}", bytesread);
                        // Console.Write(Encoding.Default.GetString(buffer, 0, bytesread));
                        bytestowrite = 0;
                        for (buffercount = 0; buffercount < bytesread; buffercount++)
                        {
                            //Console.Write("[{0:X}]", Convert.ToUInt32(buffer[buffercount]));
                            if (buffer[buffercount] == (byte)'\n' && prevchar != (byte)'\r')
                            {
                                buffer2[bytestowrite++] = (byte)'\r';
                            }
                            buffer2[bytestowrite++] = buffer[buffercount];
                            prevchar = (char)buffer[buffercount];
                        }
                    }
                    // send data
                    // Console.WriteLine("Received data from shell [{0}]", buffer2);
                    // Console.WriteLine("Send data over socket");
                    
                    session.ClientSocket.Send(buffer2, 0, bytestowrite, 0, out senderror);
                    if (senderror != SocketError.Success)
                    {
                        //Console.WriteLine("Socket error {0}", senderror);
                        CleanUp(ref session);
                        return;
                    }
                    
                }
            }
        }

        static void SessionWriteShellThread(ref SESSION_DATA session)
        {
            var buffer  = new byte[BUFFER_SIZE+1];
            int bufcnt = 0;
            // int bufsize = BUFFER_SIZE;
            int byteswritten = 0;
            var recvbuf = new byte[1];
            SocketError recverror;

            // Code
            while(session.ClientSocket.Connected)
            {
                session.ClientSocket.Receive(recvbuf, 0, 1, 0, out recverror);
                if( recverror == SocketError.Success)
                {
                    buffer[bufcnt++] = recvbuf[0];
                    if( recvbuf[0] == (byte)'\r' )
                    {
                        buffer[bufcnt++] = (byte)'\n';
                    }

                    if( bufcnt >= BUFFER_SIZE || recvbuf[0] == (byte)'\n' || recvbuf[0] == (byte)'\r')
                    {
                        // Console.WriteLine("Sending command [{0}] to server", Encoding.Default.GetString(buffer, 0, (int)bufcnt));
                        // Check for exit command
                        String command = Encoding.Default.GetString(buffer, 0, (int)bufcnt-1);
                        //Console.WriteLine("Checking command [{0}]", command);
                        if(String.Equals(command, "exit", StringComparison.OrdinalIgnoreCase))
                        {
                            //Console.WriteLine("Exit");
                            break;
                        }
                        WriteFile(session.WritePipeHandle, buffer, (uint)bufcnt, out byteswritten, IntPtr.Zero);
                        // Console.WriteLine("{0} bytes sent", byteswritten);
                        if( bufcnt > byteswritten)
                        {
                            Array.Copy(buffer, byteswritten, buffer, 0, bufcnt - byteswritten);
                            bufcnt -= byteswritten;
                        }
                        else
                        {
                            bufcnt = 0;
                        }
                    }
                }
            }

            //Console.WriteLine("Receive socket disconnected");
            CleanUp(ref session);
            return;
        }


        //public bool DoExec(String commandline, Socket client)
        public static bool DoExec(String commandline, ref Socket client)
        {
            //
            SESSION_DATA session = new SESSION_DATA();
            var HandleArray = new IntPtr[3];

            //Console.WriteLine("DoExec with command {0}", commandline);

            // Code
            if(!CreateSession(commandline, ref session))
            {
                //Console.WriteLine("Cannot create session, bailing out");
                return false;
            }

            //Console.WriteLine("Created session");

            session.ClientSocket = client;

            //Console.WriteLine("Starting reading pipe thread");
            Thread readerThread = new Thread(() => SessionReadShellThread(ref session));
            readerThread.Start();
            //SessionReadShellThread(ref session);
            //Console.WriteLine("thread started");

            //Console.WriteLine("Starting writing pipe thread");
            Thread writerThread = new Thread(() => SessionWriteShellThread(ref session));
            writerThread.Start();
            //SessionReadShellThread(ref session);
            //Console.WriteLine("thread started");

            //System.Threading.Thread.Sleep(50000);
            //Console.WriteLine("Idling");

            HandleArray[0] = session.ReadPipeHandle;
            HandleArray[1] = session.WritePipeHandle;
            HandleArray[2] = session.ProcessHandle;

            int i = WaitForMultipleObjects(3, HandleArray, false, -1);

            //Console.WriteLine("My snowflake is triggered!");

            switch(i)
            {
                case 0:
                    //Console.WriteLine("ReadShellHandle");
                    break;
                case 1:
                    //Console.WriteLine("WriteShellHandle");
                    break;
                case 2:
                    //Console.WriteLine("ProcessHandle");
                    break;
                default:
                    //Console.WriteLine("Something else broke me");
                    break;
            }

            return true;
        }
    }
}
