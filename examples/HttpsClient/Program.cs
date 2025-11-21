using System;
using System.Linq;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using NetCoreServer;

namespace HttpsClient
{
    class Program
    {
        static void Main(string[] args)
        {
            // HTTPS server address
            string address = "localhost";
            if (args.Length > 0)
                address = args[0];

            // HTTPS server port
            int port = 8443;
            if (args.Length > 1)
                port = int.Parse(args[1]);

            Console.WriteLine($"HTTPS server address: {address}");
            Console.WriteLine($"HTTPS server port: {port}");

            Console.WriteLine();

            // Load PFX (PKCS#12) files with password — returns a loader for the cert + key + chain
            var clientLoader = X509CertificateLoader.LoadPkcs12FromFile(
                "client.pfx",
                "qwerty".AsSpan(),
                X509KeyStorageFlags.DefaultKeySet
            );

            // Create and prepare a new SSL client context
            var context = new SslContext(SslProtocols.Tls13, new X509Certificate2(clientLoader),
                                         (sender, certificate, chain, sslPolicyErrors) => true);

            // Create a new HTTPS client
            var client = new HttpsClientEx(context, Dns.GetHostAddresses(address).FirstOrDefault(), port);

            Console.WriteLine("Press Enter to stop the client or '!' to reconnect the client...");

            // Perform text input
            for (;;)
            {
                string line = Console.ReadLine();
                if (string.IsNullOrEmpty(line))
                    break;

                // Reconnect the client
                if (line == "!")
                {
                    Console.Write("Client reconnecting...");
                    if (client.IsConnected)
                        client.ReconnectAsync();
                    else
                        client.ConnectAsync();
                    Console.WriteLine("Done!");
                    continue;
                }

                var commands = line.Split(' ');
                if (commands.Length < 2)
                {
                    Console.WriteLine("HTTP method and URL must be entered!");
                    continue;
                }

                if (commands[0].Equals("HEAD", StringComparison.InvariantCultureIgnoreCase))
                {
                    var response = client.SendHeadRequest(commands[1]).Result;
                    Console.WriteLine(response);
                }
                else if (commands[0].Equals("GET", StringComparison.InvariantCultureIgnoreCase))
                {
                    var response = client.SendGetRequest(commands[1]).Result;
                    Console.WriteLine(response);
                }
                else if (commands[0].Equals("POST", StringComparison.InvariantCultureIgnoreCase))
                {
                    if (commands.Length < 3)
                    {
                        Console.WriteLine("HTTP method, URL and body must be entered!");
                        continue;
                    }

                    var response = client.SendPostRequest(commands[1], commands[2]).Result;
                    Console.WriteLine(response);
                }
                else if (commands[0].Equals("PUT", StringComparison.InvariantCultureIgnoreCase))
                {
                    if (commands.Length < 3)
                    {
                        Console.WriteLine("HTTP method, URL and body must be entered!");
                        continue;
                    }

                    var response = client.SendPutRequest(commands[1], commands[2]).Result;
                    Console.WriteLine(response);
                }
                else if (commands[0].Equals("DELETE", StringComparison.InvariantCultureIgnoreCase))
                {
                    var response = client.SendDeleteRequest(commands[1]).Result;
                    Console.WriteLine(response);
                }
                else if (commands[0].Equals("OPTIONS", StringComparison.InvariantCultureIgnoreCase))
                {
                    var response = client.SendOptionsRequest(commands[1]).Result;
                    Console.WriteLine(response);
                }
                else if (commands[0].Equals("TRACE", StringComparison.InvariantCultureIgnoreCase))
                {
                    var response = client.SendTraceRequest(commands[1]).Result;
                    Console.WriteLine(response);
                }
                else
                    Console.WriteLine("Unknown HTTP method");
            }

            // Disconnect the client
            Console.Write("Client disconnecting...");
            client.Disconnect();
            Console.WriteLine("Done!");
        }
    }
}
