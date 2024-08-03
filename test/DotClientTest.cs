﻿using Makaretu.Dns;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Makaretu.Dns
{
    [TestClass]
    public class DotClientTest
    {
        private static bool SupportsIPv6
        {
            get
            {
                return Socket.OSSupportsIPv6

                    // See https://discuss.circleci.com/t/ipv6-support/13571
                    && Environment.GetEnvironmentVariable("CIRCLECI") == null

                    // See https://github.com/njh/travis-ipv6-test
                    && Environment.GetEnvironmentVariable("TRAVIS") == null

                    && Environment.GetEnvironmentVariable("APPVEYOR") == null
                    ;
            }
        }

        [TestMethod]
        public void PublicServers()
        {
            var dot = new DotClient();
            Assert.AreNotEqual(0, DotClient.PublicServers.Length);
        }

        [TestMethod]
        public void Resolve()
        {
            using (var dot = new DotClient())
            {
                var addresses = dot.ResolveAsync("github.com").Result.ToArray();
                Assert.AreNotEqual(0, addresses.Length);

                addresses = dot.ResolveAsync("ipfs.tech").Result.ToArray();
                Assert.AreNotEqual(0, addresses.Length);
            }
        }

        [TestMethod]
        public void Resolve_Unknown()
        {
            using (var dot = new DotClient())
            {
                ExceptionAssert.Throws<IOException>(() =>
                {
                    var _ = dot.ResolveAsync("emanon.noname").Result;
                });
            }
        }

        [TestMethod]
        public async Task Query()
        {
            using (var dot = new DotClient())
            {
                var query = new Message { RD = true, Id = 0x1234 };
                query.Questions.Add(new Question { Name = "ipfs.tech", Type = DnsType.TXT });
                var response = await dot.QueryAsync(query);
                Assert.IsNotNull(response);
                Assert.AreNotEqual(0, response.Answers.Count);
            }
        }

        [TestMethod]
        public async Task SecureQuery_Has_RRs()
        {
            var dns = new DotClient();
            var query = new Message { RD = true }.UseDnsSecurity();
            query.Questions.Add(new Question { Name = "cloudflare-dns.com", Type = DnsType.AAAA });
            var response = await dns.QueryAsync(query);
            Assert.IsNotNull(response);
            Assert.AreNotEqual(0, response.Answers.Count);

            var opt = response.AdditionalRecords.OfType<OPTRecord>().Single();
            Assert.AreEqual(true, opt.DO);

            var rrsig = response.Answers.OfType<RRSIGRecord>().Single();
            Assert.AreEqual(DnsType.AAAA, rrsig.TypeCovered);
        }

        [TestMethod]
        public async Task Query_Stream_Closes()
        {
            using (var dot = new DotClient())
            {
                var query = new Message { RD = true, Id = 0x1234 };
                query.Questions.Add(new Question { Name = "ipfs.tech", Type = DnsType.TXT });
                var response = await dot.QueryAsync(query);
                Assert.IsNotNull(response);
                Assert.AreNotEqual(0, response.Answers.Count);

                (await dot.GetDnsServerAsync()).Dispose();
                response = await dot.QueryAsync(query);
                Assert.IsNotNull(response);
                Assert.AreNotEqual(0, response.Answers.Count);
            }
        }

        [TestMethod]
        public void Query_UnknownTldName()
        {
            using (var dot = new DotClient())
            {
                var query = new Message { RD = true };
                query.Questions.Add(new Question { Name = "emanon.foo", Type = DnsType.A });
                ExceptionAssert.Throws<IOException>(() =>
                {
                    var _ = dot.QueryAsync(query).Result;
                }, "DNS error 'NameError'.");
            }
        }

        [TestMethod]
        public void Query_UnknownName()
        {
            using (var dot = new DotClient())
            {
                var query = new Message { RD = true };
                query.Questions.Add(new Question { Name = "emanon.noname.google.com", Type = DnsType.A });
                ExceptionAssert.Throws<IOException>(() =>
                {
                    var _ = dot.QueryAsync(query).Result;
                }, "DNS error 'NameError'.");
            }
        }

        [TestMethod]
        public void Query_UnknownName_NoThrow()
        {
            using (var dot = new DotClient { ThrowResponseError = false })
            {
                var query = new Message { RD = true };
                query.Questions.Add(new Question { Name = "emanon.noname.google.com", Type = DnsType.A });
                var result = dot.QueryAsync(query).Result;
                Assert.AreEqual(MessageStatus.NameError, result.Status);
            }
        }

        [TestMethod]
        public void Query_InvalidServer_IPAddress()
        {
            using (var dot = new DotClient
            {
                Servers = new[]
                {
                    new DotEndPoint { Address = IPAddress.Any }
                }
            })
            {
                var query = new Message { RD = true };
                query.Questions.Add(new Question { Name = "emanon.noname.google.com", Type = DnsType.A });
                ExceptionAssert.Throws<Exception>(() =>
                {
                    var _ = dot.QueryAsync(query).Result;
                });
            }
        }

        [TestMethod]
        public void Query_InvalidServer_Hostname()
        {
            using (var dot = new DotClient
            {
                Servers = new[]
                {
                    new DotEndPoint
                    {
                        Hostname = "bad-cloudflare-dns.com", // bad
                        Address = IPAddress.Parse("1.1.1.1")
                    }
                }
            })
            {
                var query = new Message { RD = true };
                query.Questions.Add(new Question { Name = "emanon.noname.google.com", Type = DnsType.A });
                ExceptionAssert.Throws<Exception>(() =>
                {
                    var _ = dot.QueryAsync(query).Result;
                });
            }
        }

        [TestMethod]
        public async Task Query_OneDeadServer()
        {
            using var dot = new DotClient
            {
                //Servers = new[]
                //{
                //    new DotEndPoint
                //    {
                //        Address = IPAddress.Parse("127.0.0.1"),
                //        Port = 8530
                //    },
                //    new DotEndPoint
                //    {
                //        Hostname = "cloudflare-dns.com",
                //        Address = IPAddress.Parse("1.1.1.1")
                //    }
                //}
            };
            var query = new Message { RD = true };
            query.Questions.Add(new Question { Name = "ipfs.tech", Type = DnsType.TXT });
            var response = await dot.QueryAsync(query);
            Assert.IsNotNull(response);
            Assert.AreNotEqual(0, response.Answers.Count);
        }

        [TestMethod]
        public void NoSerer()
        {
            using (var dot = new DotClient
            {
                Servers = new DotEndPoint[0]
            })
            {
                var query = new Message { RD = true };
                query.Questions.Add(new Question { Name = "ipfs.tech", Type = DnsType.TXT });
                ExceptionAssert.Throws<Exception>(() =>
                {
                    var _ = dot.QueryAsync(query).Result;
                });
            }
        }

        [TestMethod]
        public async Task Reverse()
        {
            using (var dot = new DotClient())
            {
                var name = await dot.ResolveAsync(IPAddress.Parse("1.1.1.1"));
                Assert.AreEqual("one.one.one.one", name);

                name = await dot.ResolveAsync(IPAddress.Parse("2606:4700:4700::1111"));
                Assert.AreEqual("one.one.one.one", name);
            }
        }

        [TestMethod]
        public async Task Resolve_Reverse()
        {
            using (var dot = new DotClient())
            {
                var github = "github.com";
                var addresses = await dot.ResolveAsync(github);
                foreach (var address in addresses)
                {
                    var name = await dot.ResolveAsync(address);
                    StringAssert.EndsWith(name.ToString(), ".com");
                }
            }
        }

        [TestMethod]
        public async Task Query_Cloudflare_IPv6()
        {
            if (!SupportsIPv6)
            {
                Assert.Inconclusive("IPv6 not supported by OS.");
            }
            using var dot = new DotClient
            {
                //Servers = new[]
                //{
                //    new DotEndPoint
                //    {
                //        Hostname = "cloudflare-dns.com",
                //        Address = IPAddress.Parse("2606:4700:4700::1111")
                //    }
                //}
            };
            var query = new Message { RD = true };
            query.Questions.Add(new Question { Name = "ipfs.tech", Type = DnsType.TXT });
            var response = await dot.QueryAsync(query);
            Assert.IsNotNull(response);
            Assert.AreNotEqual(0, response.Answers.Count);
        }

        [TestMethod]
        public async Task Query_Quad9()
        {
            using (var dot = new DotClient
            {
                Servers = new[]
                {
                    new DotEndPoint
                    {
                        Hostname = "dns.quad9.net",
                        Address = IPAddress.Parse("9.9.9.9")
                    }
                }
            })
            {
                var query = new Message { RD = true };
                query.Questions.Add(new Question { Name = "ipfs.tech", Type = DnsType.TXT });
                var response = await dot.QueryAsync(query);
                Assert.IsNotNull(response);
                Assert.AreNotEqual(0, response.Answers.Count);
            }
        }

        [TestMethod]
        public async Task Query_Google()
        {
            using (var dot = new DotClient
            {
                Servers = new[]
                {
                    new DotEndPoint
                    {
                        Hostname = "dns.google",
                        Address = IPAddress.Parse("8.8.8.8")
                    }
                }
            })
            {
                var query = new Message { RD = true };
                query.Questions.Add(new Question { Name = "ipfs.tech", Type = DnsType.TXT });
                var response = await dot.QueryAsync(query);
                Assert.IsNotNull(response);
                Assert.AreNotEqual(0, response.Answers.Count);
            }
        }
    }
}