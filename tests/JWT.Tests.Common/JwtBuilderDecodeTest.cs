using System;
using System.Collections.Generic;
using JWT.JwtBuilder;
using JWT.Serializers;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtBuilderDecodeToken
    {
        private const string _sampleToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
        private const string _sampleSecret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";

        [Fact]
        public void DecodeToken()
        {
            var payload = new Builder()
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeTokenWithoutToken()
        {
            Assert.Throws<ArgumentException>(() => new Builder()
                                                    .Decode(null));
        }

        [Fact]
        public void DecodeTokenWithoutSerilizer()
        {
            Assert.Throws<Exception>(() => new Builder()
                                             .SetSerializer(null)
                                             .Decode(_sampleToken));
        }

        [Fact]
        public void DecodeTokenWithExplicitSerilizer()
        {
            var payload = new Builder()
                .SetSerializer(new JsonNetSerializer())
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeTokenWithoutUrlEncoder()
        {
            Assert.Throws<Exception>(() => new Builder()
                                             .SetUrlEncoder(null)
                                             .Decode(_sampleToken));
        }

        [Fact]
        public void DecodeTokenWithExplicitUrlEncoder()
        {
            var payload = new Builder()
                .SetUrlEncoder(new JwtBase64UrlEncoder())
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeTokenWithoutTimeProvider()
        {
            Assert.Throws<Exception>(() => new Builder()
                                             .SetTimeProvider(null)
                                             .Decode(_sampleToken));
        }

        [Fact]
        public void DecodeTokenWithExplicitTimeProvider()
        {
            var payload = new Builder()
                .SetTimeProvider(new UtcDateTimeProvider())
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeTokenWithoutValidTor()
        {
            var payload = new Builder()
                .SetValidTor(null)
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeTokenWithExplicitValidTor()
        {
            var payload = new Builder()
                .SetValidTor(new JwtValidTor(new JsonNetSerializer(), new UtcDateTimeProvider()))
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeTokenWithVerifyCheck()
        {
            var payload = new Builder()
                .SetSecret(_sampleSecret)
                .MustVerify()
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeTokenWithVerifyCheckWithoutSecret()
        {
            Assert.Throws<Exception>(() => new Builder()
                                            .MustVerify()
                                            .Decode(_sampleToken));
        }

        [Fact]
        public void DecodeTokenWithoutVerifyCheck()
        {
            var payload = new Builder()
                .NotVerify()
                .Decode(_sampleToken);

            Assert.NotEmpty(payload);
        }

        [Fact]
        public void DecodeTokenToDictionary()
        {
            var payload = new Builder()
                .SetSecret(_sampleSecret)
                .MustVerify()
                .Decode<Dictionary<string, string>>(_sampleToken);

            Assert.True(payload.Count == 2 && payload["claim1"] == 0.ToString());
        }

        [Fact]
        public void DecodeTokenToDictionaryWithoutSerializier()
        {
            Assert.Throws<Exception>(() =>
                                     {
                                         new Builder()
                                             .SetSerializer(null)
                                             .SetSecret(_sampleSecret)
                                             .MustVerify()
                                             .Decode<Dictionary<string, string>>(_sampleToken);
                                     });
        }
    }
}