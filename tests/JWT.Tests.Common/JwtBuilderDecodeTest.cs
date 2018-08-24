using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Serializers;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtBuilderDecodeTest
    {
        private const string _sampleToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
        private const string _sampleSecret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
        private readonly string[] _sampleSecrets = { "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk", "QWORIJkmQWEDIHbjhOIHAUSDFOYnUGWEYT" };

        [Fact]
        public void DecodeToken()
        {
            var payload = new JwtBuilder()
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithoutToken_Should_Throw_Exception()
        {
            Assert.Throws<ArgumentException>(() => new JwtBuilder()
                                                 .Decode(null));
        }

        [Fact]
        public void DecodeToken_WithoutSerializer_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                                                           .WithSerializer(null)
                                                           .Decode(_sampleToken));
        }

        [Fact]
        public void DecodeToken_WithSerializer()
        {
            var payload = new JwtBuilder()
                          .WithSerializer(new JsonNetSerializer())
                          .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithoutUrlEncoder_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                                                           .WithUrlEncoder(null)
                                                           .Decode(_sampleToken));
        }

        [Fact]
        public void DecodeToken_WithUrlEncoder()
        {
            var payload = new JwtBuilder()
                          .WithUrlEncoder(new JwtBase64UrlEncoder())
                          .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithoutTimeProvider_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                                                           .WithDateTimeProvider(null)
                                                           .Decode(_sampleToken));
        }

        [Fact]
        public void DecodeToken_WithDateTimeProvider()
        {
            var payload = new JwtBuilder()
                          .WithDateTimeProvider(new UtcDateTimeProvider())
                          .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithoutValidator()
        {
            var payload = new JwtBuilder()
                          .WithValidator(null)
                          .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithExplicitValidator()
        {
            var payload = new JwtBuilder()
                          .WithValidator(new JwtValidator(new JsonNetSerializer(), new UtcDateTimeProvider()))
                          .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithVerifySignature()
        {
            var payload = new JwtBuilder()
                          .WithSecret(_sampleSecret)
                          .MustVerifySignature()
                          .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithVerifySignature_MultipleSecrets()
        {
            var payload = new JwtBuilder()
                .WithSecret(_sampleSecrets)
                .MustVerifySignature()
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithoutVerifySignature()
        {
            var payload = new JwtBuilder()
                          .DoNotVerifySignature()
                          .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_ToDictionary()
        {
            var payload = new JwtBuilder()
                          .WithSecret(_sampleSecret)
                          .MustVerifySignature()
                          .Decode<Dictionary<string, string>>(_sampleToken);

            Assert.True(payload.Count == 2 && payload["claim1"] == 0.ToString());
        }

        [Fact]
        public void DecodeToken_ToDictionary_MultipleSecrets()
        {
            var payload = new JwtBuilder()
                .WithSecret(_sampleSecrets)
                .MustVerifySignature()
                .Decode<Dictionary<string, string>>(_sampleToken);

            Assert.True(payload.Count == 2 && payload["claim1"] == 0.ToString());
        }


        [Fact]
        public void DecodeToken_ToDictionary_WithoutSerializer_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                                                           .WithSerializer(null)
                                                           .WithSecret(_sampleSecret)
                                                           .MustVerifySignature()
                                                           .Decode<Dictionary<string, string>>(_sampleToken));
        }

        [Fact]
        public void Main()
        {
            var certificateText =
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBljCCAUACCQCIDMpqK7WfWDANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJV\n" +
                "UzETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UECgwJTHV4b3R0aWNhMRowGAYD\n" +
                "VQQLDBFMdXhvdHRpY2EgZXllY2FyZTAeFw0xODA1MjMxNTE1MjdaFw0yODA1MjAx\n" +
                "NTE1MjdaMFIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMRIwEAYD\n" +
                "VQQKDAlMdXhvdHRpY2ExGjAYBgNVBAsMEUx1eG90dGljYSBleWVjYXJlMFwwDQYJ\n" +
                "KoZIhvcNAQEBBQADSwAwSAJBAKuMYcirPj81WBtMituJJenF0CG/HYLcAUOtWKl1\n" +
                "HchC0dM8VRRBI/HV+nZcweXzpjhX8ySa9s7kJneP0cuJiU8CAwEAATANBgkqhkiG\n" +
                "9w0BAQsFAANBAKEM8wQwlqKgkfqnNFcbsZM0RUxS+eWR9LvycGuMN7aL9M6GOmfp\n" +
                "QmF4MH4uvkaiZenqCkhDkyi4Cy81tz453tQ=\n" +
                "-----END CERTIFICATE-----";

            var token = @"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJuLmNoaWVmZm8iLCJleHAiOjE1MjcyMzg4ODEsImlzcyI6Imx1eCJ9.BAaYzLwokmdKqLi6zKjGIpDXd__dZxi5PUWWHS3PSLPDYAInzPbEK8o4WxunoGD7eA0qtQNaxNpzeOc3BHrd4w";

            var certificate = new X509Certificate2(Encoding.ASCII.GetBytes(certificateText));

            var jwt = new JwtParts(token);
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signature = GetBytes(jwt.Signature);
            var res = new RS256Algorithm(certificate).Verify(bytesToSign, signature);
        }

        internal static byte[] GetBytes(string input) => Encoding.UTF8.GetBytes(input);
    }
}