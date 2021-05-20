using System;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace SSLSocket1
{
    class Program
    {
        static void Main(string[] args)
        {
            string serverUrl = "";
            string serverIp = "";
            int serverPort = 0;
            var isHttp = false;
            if (args.Length > 0)
            {
                var url = args[0];
                if (Regex.IsMatch(url, "^https://.*"))
                {
                    serverUrl = args[0];
                    Console.WriteLine($"serverUrl - {serverUrl}");
                    var serverUri = new Uri(serverUrl);
                    Console.WriteLine($"serverHost - {serverUri.Host}");
                    var serverHost = Dns.GetHostEntry(serverUri.Host);
                    Console.WriteLine($"serverAddresses - " + string.Join(",", serverHost.AddressList.ToList()));
                    serverIp = serverHost.AddressList.Length > 0 ? serverHost.AddressList[0].ToString() : "";
                    serverPort = serverUri.Port;
                    isHttp = true;
                }
                else if (Regex.IsMatch(url, "^\\d+\\.\\d+\\.\\d+\\.\\d+$"))
                {
                    serverIp = url;
                    if (args.Length > 1 && Regex.IsMatch(args[1], "^\\d+$"))
                        serverPort = int.Parse(args[1]);
                        
                }
                else if (Regex.IsMatch(url, "^\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+$"))
                {
                    var parts = url.Split(new[] { ':' });
                    serverIp = parts[0];
                    serverPort = int.Parse(parts[1]);
                }
            }

            Console.WriteLine($"server: IP - {serverIp}, Port - {serverPort}");

            TcpClient client = new TcpClient();
            try
            {
                client.Connect(serverIp, serverPort);
                using (SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null))
                {
                    sslStream.AuthenticateAsClient(serverIp);
                    var sslProto = sslStream.SslProtocol;
                    Console.WriteLine($"SSL Protocols - {sslProto.ToString()}");

                    if (isHttp)
                    {
                        var httpRequest = $"GET {serverUrl} HTTP/1.0\r\n\r\n";
                        sslStream.Write(Encoding.UTF8.GetBytes(httpRequest));
                        sslStream.Flush();

                        byte[] buf = new byte[1];
                        bool isHeader = true;
                        var headerString = "";
                        while (isHeader)
                        {
                            var c = sslStream.Read(buf, 0, 1);
                            if (c > 0)
                                headerString += Encoding.ASCII.GetString(buf);
                            else
                                break;

                            if (headerString.EndsWith("\r\n\r\n"))
                                break;
                        }
                        Console.WriteLine("Headers:");
                        var headers = headerString.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var header in headers)
                            Console.WriteLine($" - {header}");

                        var headerRegex = "\\r\\nContent-Length: (\\d+)\\r\\n";
                        var m = Regex.Match(headerString, headerRegex);
                        if (m.Success)
                        {
                            var contentLengthValue = m.Groups[1].Value;
                            var contentLength = int.Parse(contentLengthValue);
                            buf = new byte[contentLength];
                            sslStream.Read(buf, 0, contentLength);
                            var bodyString = Encoding.UTF8.GetString(buf);
                            Console.WriteLine("Body:");
                            Console.WriteLine(bodyString);
                        }
                        else
                        {
                            Console.WriteLine("No Content-Length header found!");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error - {ex.Message}");
            }
            finally
            {
                client.Close();
            }

            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine($"Server Certificate - {certificate.Subject}");
            return true;
        }
    }
}
