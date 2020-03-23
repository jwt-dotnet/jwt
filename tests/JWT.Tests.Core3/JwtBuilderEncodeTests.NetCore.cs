using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Tests.Common.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Common
{
    public partial class JwtBuilderEncodeTests
    {
        [TestMethod]
        public void Encode_With_Certificate()
        {
            using var rsa = RSA.Create();
            rsa.FromXmlString(TestData.ServerRsaPrivateKey);

            using var pubOnly = new X509Certificate2(Encoding.ASCII.GetBytes(TestData.ServerRsaPublicKey2));
            using var pubPrivEphemeral = pubOnly.CopyWithPrivateKey(rsa);
            using var cert = new X509Certificate2(pubPrivEphemeral.Export(X509ContentType.Pfx));

            var builder = new JwtBuilder();
            var algorithm = new RS256Algorithm(cert);

            var token = builder.WithAlgorithm(algorithm)
                               .AddClaim("exp", DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds())
                               .AddClaim("name", TestData.Customer.FirstName)
                               .AddClaim("iss", "test")
                               .Encode();

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the built token should have the three standard parts");
        }
    }
}