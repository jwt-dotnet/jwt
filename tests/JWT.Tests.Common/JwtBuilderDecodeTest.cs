using System;
using System.Collections.Generic;
using JWT.Serializers;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtBuilderDecodeTest
    {
        private const string _sampleToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
        private const string _sampleSecret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";

        [Fact]
        public void DecodeToken_()
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
                                                         .SetSerializer(null)
                                                         .Decode(_sampleToken));
        }

        [Fact]
        public void DecodeToken_WithSerializer()
        {
            var payload = new JwtBuilder()
                .SetSerializer(new JsonNetSerializer())
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithoutUrlEncoder_Should_Throw_Exception()
        {
            Assert.Throws<Exception>(() => new JwtBuilder()
                                         .SetUrlEncoder(null)
                                         .Decode(_sampleToken));
        }

        [Fact]
        public void DecodeToken_WithUrlEncoder()
        {
            var payload = new JwtBuilder()
                .SetUrlEncoder(new JwtBase64UrlEncoder())
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithoutTimeProvider_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                                                         .SetTimeProvider(null)
                                                         .Decode(_sampleToken));
        }

        [Fact]
        public void DecodeToken_WithDateTimeProvider()
        {
            var payload = new JwtBuilder()
                .SetTimeProvider(new UtcDateTimeProvider())
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithoutValidator()
        {
            var payload = new JwtBuilder()
                .SetValidtor(null)
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithExplicitValidator()
        {
            var payload = new JwtBuilder()
                .SetValidtor(new JwtValidator(new JsonNetSerializer(), new UtcDateTimeProvider()))
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithVerify()
        {
            var payload = new JwtBuilder()
                .SetSecret(_sampleSecret)
                .MustVerifySignature()
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeToken_WithVerify_WithoutSecret_Should_Throw_Exception()
        {
            Assert.Throws<Exception>(() => new JwtBuilder()
                                         .MustVerifySignature()
                                         .Decode(_sampleToken));
        }

        [Fact]
        public void DecodeToken_WithoutVerify()
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
                .SetSecret(_sampleSecret)
                .MustVerifySignature()
                .Decode<Dictionary<string, string>>(_sampleToken);

            Assert.True(payload.Count == 2 && payload["claim1"] == 0.ToString());
        }

        [Fact]
        public void DecodeToken_ToDictionary_WithoutSerializer_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                                                         .SetSerializer(null)
                                                         .SetSecret(_sampleSecret)
                                                         .MustVerifySignature()
                                                         .Decode<Dictionary<string, string>>(_sampleToken));
        }
    }
}