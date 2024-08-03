using Common.Logging;
using Nito.AsyncEx;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection.Metadata;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Makaretu.Dns
{
    /// <summary>
    ///   Client to a DNS server over HTTPS.
    /// </summary>
    /// <remarks>
    ///   DNS over HTTPS (DoH) is an experimental protocol for performing remote
    ///   Domain Name System (DNS) resolution via the HTTPS protocol. The goal
    ///   is to increase user privacy and security by preventing eavesdropping and
    ///   manipulation of DNS data by man-in-the-middle attacks.
    ///   <para>
    ///   The <b>DohClient</b> uses the HTTP POST method to hide as much
    ///   information as is possible.  Also, it tends to generate smaller
    ///   requests.
    ///   </para>
    /// </remarks>
    /// <seealso href="https://en.wikipedia.org/wiki/DNS_over_HTTPS"/>
    public class DohClient : DnsClientBase
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(DohClient));

        private HttpClient httpClient;
        private readonly object httpClientLock = new();
        private readonly AsyncLock dnsServerLock = new();

        private const string primaryUrl = "https://dns.google/resolve";
        private const string alternateUrl = "https://cloudflare-dns.com/dns-query";

        /// <summary>
        ///   Time to wait for a DNS response.
        /// </summary>
        /// <value>
        ///   The default is 4 seconds.
        /// </value>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(4);

        /// <summary>
        /// Use the primary URL to communicate with DNS
        /// </summary>
        ///       /// <value>
        ///   The default is true (Google DNS).
        /// </value>
        public bool UsePrimaryUrl { get; set; } = true;

        /// <summary>
        ///   The DNS server to communication with.
        /// </summary>
        /// <value>
        ///   Primary URL "https://dns.google/resolve".
        ///   Alternate URL "https://cloudflare-dns.com/dns-query".
        /// </value>
        public string ServerUrl { get; set; } = alternateUrl;

        /// <summary>
        ///   The MIME type for a DNS message encoded in UPD wire format.
        /// </summary>
        /// <remarks>
        ///   Previous drafts defined this as "application/dns-udpwireformat".
        /// </remarks>
        public const string DnsWireFormat = "application/dns-message";

        /// <summary>
        ///   The MIME type for a DNS message encoded in JSON.
        /// </summary>
        public const string DnsJsonFormat = "application/dns-json";

        /// <summary>
        ///   The client that sends HTTP requests and receives HTTP responses.
        /// </summary>
        /// <remarks>
        ///   It is best practice to use only one <see cref="HttpClient"/> in an
        ///   application.
        /// </remarks>
        public HttpClient HttpClient
        {
            get
            {
                if (httpClient == null)
                {
                    lock (httpClientLock)
                    {
                        httpClient = new HttpClient();
                    }
                }
                return httpClient;
            }
            set
            {
                httpClient = value;
            }
        }

        /// <summary>
        ///   Send a DNS query with the specified message.
        /// </summary>
        /// <param name="request">
        ///   A <see cref="Message"/> containing a <see cref="Question"/>.
        /// </param>
        /// <param name="cancel">
        ///   Is used to stop the task.  When cancelled, the <see cref="TaskCanceledException"/> is raised.
        /// </param>
        /// <returns>
        ///   A task that represents the asynchronous operation. The task's value
        ///   contains the response <see cref="Message"/>.
        /// </returns>
        /// <exception cref="IOException">
        ///   When the DNS server returns error status or no response.
        /// </exception>
        public override async Task<Message> QueryAsync(Message request, CancellationToken cancel = default)
        {
            return UsePrimaryUrl ? await QueryWithGoogleAsync(request, cancel) : await QueryWithCloudFlareAsync(request, cancel);
        }

        // use Google's DNS servers
        public async Task<Message> QueryWithGoogleAsync(Message messageRequest, CancellationToken cancel)
        {
            if (log.IsDebugEnabled)
            {
                var names = messageRequest.Questions
                    .Select(q => q.Name + " " + q.Type.ToString())
                    .Aggregate((current, next) => current + ", " + next);
                log.Debug($"query #{messageRequest.Id} for '{names}'");
            }

            // Cancel the request when either the timeout is reached or the
            // task is cancelled by the caller.
            var cts = CancellationTokenSource.CreateLinkedTokenSource(cancel, new CancellationTokenSource(Timeout).Token);

            // Post the request.
            HttpResponseMessage httpResponse;
            using (var ms = new MemoryStream())
            {
                List<string> urlStructures = new();
                foreach (var question in messageRequest.Questions)
                {
                    urlStructures.Add($"{primaryUrl}?name={question.Name}&type={question.Type}&ct={DnsWireFormat}&cd={messageRequest.CD}&do={messageRequest.DO}");
                }

                // TODO: find a better implementation
                // Only one writer at a time.
                using (await dnsServerLock.LockAsync(cancel))
                {
                    httpResponse = await HttpClient.GetAsync(urlStructures.FirstOrDefault(), cts.Token);
                }
            }

            // Check the HTTP response.
            httpResponse.EnsureSuccessStatusCode();
            var contentType = httpResponse.Content.Headers.ContentType.MediaType;
            if (DnsWireFormat != contentType)
                throw new HttpRequestException($"Expected content-type '{DnsWireFormat}' not '{contentType}'.");

            // Check the DNS response.
            var body = await httpResponse.Content.ReadAsStreamAsync();
            var dnsResponse = (Message)new Message().Read(body);
            if (ThrowResponseError)
            {
                if (dnsResponse.Status != MessageStatus.NoError)
                {
                    log.Warn($"DNS error '{dnsResponse.Status}'.");
                    throw new IOException($"DNS error '{dnsResponse.Status}'.");
                }
            }

            if (log.IsDebugEnabled)
                log.Debug($"Got response #{dnsResponse.Id}");
            if (log.IsTraceEnabled)
                log.Trace(dnsResponse);
            return dnsResponse;
        }

        // use Cloudflare's DNS servers
        public async Task<Message> QueryWithCloudFlareAsync(Message messageRequest, CancellationToken cancel = default)
        {
            if (log.IsDebugEnabled)
            {
                var names = messageRequest.Questions
                    .Select(q => q.Name + " " + q.Type.ToString())
                    .Aggregate((current, next) => current + ", " + next);
                log.Debug($"query #{messageRequest.Id} for '{names}'");
            }

            // Cancel the request when either the timeout is reached or the
            // task is cancelled by the caller.
            var cts = CancellationTokenSource.CreateLinkedTokenSource(cancel, new CancellationTokenSource(Timeout).Token);

            // Post the request.
            HttpResponseMessage httpResponse;
            using (var ms = new MemoryStream())
            {
                messageRequest.Write(ms);
                ms.Position = 0;

                // Only one writer at a time.
                using (await dnsServerLock.LockAsync(cancel))
                {
                    httpResponse = await HttpClient.GetAsync($"{alternateUrl}?dns={Convert.ToBase64String(ms.ToArray())}", cts.Token);
                }
            }

            // Check the HTTP response.
            //httpResponse.EnsureSuccessStatusCode();
            var contentType = httpResponse.Content.Headers.ContentType.MediaType;
            if (DnsWireFormat != contentType)
                throw new HttpRequestException($"Expected content-type '{DnsWireFormat}' not '{contentType}'.");

            // Check the DNS response.
            var body = await httpResponse.Content.ReadAsStreamAsync();
            var dnsResponse = (Message)new Message().Read(body);
            if (ThrowResponseError)
            {
                if (dnsResponse.Status != MessageStatus.NoError)
                {
                    log.Warn($"DNS error '{dnsResponse.Status}'.");
                    throw new IOException($"DNS error '{dnsResponse.Status}'.");
                }
            }

            if (log.IsDebugEnabled)
                log.Debug($"Got response #{dnsResponse.Id}");
            if (log.IsTraceEnabled)
                log.Trace(dnsResponse);
            return dnsResponse;
        }
    }
}