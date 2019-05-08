using System;
using System.Collections.Generic;
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
    }
}