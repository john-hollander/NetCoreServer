using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using NetCoreServer;
using NDesk.Options;

namespace HttpsTraceServer
{
    class HttpsTraceSession(HttpsServer server) : HttpsSession(server)
    {
        protected override void OnReceivedRequest(HttpRequest request)
        {
            // Process HTTP request methods
            if (request.Method == "TRACE")
                SendResponseAsync(Response.MakeTraceResponse(request));
            else
                SendResponseAsync(Response.MakeErrorResponse("Unsupported HTTP method: " + request.Method));
        }

        protected override void OnReceivedRequestError(HttpRequest request, string error)
        {
            Console.WriteLine($"Request error: {error}");
        }

        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"Session caught an error with code {error}");
        }
    }

    class HttpsTraceServer(SslContext context, IPAddress address, int port) : HttpsServer(context, address, port)
    {
        protected override SslSession CreateSession() { return new HttpsTraceSession(this); }

        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"Server caught an error with code {error}");
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            bool help = false;
            int port = 8443;

            var options = new OptionSet()
            {
                { "h|?|help",   v => help = v != null },
                { "p|port=", v => port = int.Parse(v) }
            };

            try
            {
                options.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("Command line error: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try `--help' to get usage information.");
                return;
            }

            if (help)
            {
                Console.WriteLine("Usage:");
                options.WriteOptionDescriptions(Console.Out);
                return;
            }

            Console.WriteLine($"Server port: {port}");

            Console.WriteLine();

            // Load PFX (PKCS#12) files with password — returns a loader for the cert + key + chain
            var serverLoader = X509CertificateLoader.LoadPkcs12FromFile(
                "server.pfx",
                "qwerty".AsSpan(),  // ReadOnlySpan<char> for password (secure, zero-copy)
                X509KeyStorageFlags.DefaultKeySet  // Optional: controls key persistence (e.g., machine vs. user store)
            );

            // Create and prepare a new SSL server context
            var context = new SslContext(SslProtocols.Tls13, new X509Certificate2(serverLoader));

            // Create a new HTTPS server
            var server = new HttpsTraceServer(context, IPAddress.Any, port)
            {
                // server.OptionNoDelay = true;
                OptionReuseAddress = true
            };

            // Start the server
            Console.Write("Server starting...");
            server.Start();
            Console.WriteLine("Done!");

            Console.WriteLine("Press Enter to stop the server or '!' to restart the server...");

            // Perform text input
            for (;;)
            {
                string line = Console.ReadLine();
                if (string.IsNullOrEmpty(line))
                    break;

                // Restart the server
                if (line == "!")
                {
                    Console.Write("Server restarting...");
                    server.Restart();
                    Console.WriteLine("Done!");
                }
            }

            // Stop the server
            Console.Write("Server stopping...");
            server.Stop();
            Console.WriteLine("Done!");
        }
    }
}
