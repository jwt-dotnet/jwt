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

            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutToken()
        {
            string payload = null;
            Assert.Throws<ArgumentException>(() => { payload = new Builder().Decode(null); });

            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithoutSerilizer()
        {
            string payload = null;
            Assert.Throws<Exception>(() => { payload = new Builder().SetSerializer(null).Decode(_sampleToken); });
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithAnExplicitSerilizer()
        {
            var payload = new Builder().SetSerializer(new JsonNetSerializer()).Decode(_sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutUrlEncoder()
        {
            string payload = null;
            Assert.Throws<Exception>(() => { payload = new Builder().SetUrlEncoder(null).Decode(_sampleToken); });
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithAnExplicitUrlEncoder()
        {
            var payload = new Builder().SetUrlEncoder(new JwtBase64UrlEncoder()).Decode(_sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutTimeProvider()
        {
            string payload = null;
            Assert.Throws<Exception>(() => { payload = new Builder().SetTimeProvider(null).Decode(_sampleToken); });
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithAnExplicitTimeProvider()
        {
            var payload = new Builder().SetTimeProvider(new UtcDateTimeProvider()).Decode(_sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutValidator()
        {
            var payload = new Builder().SetValidator(null).Decode(_sampleToken);
            Assert.True(payload.Length > 0);

        }

        [Fact]
        public void DecodeTokenWithAnExplicitValidator()
        {
            var payload = new Builder().SetValidator(new JwtValidator(new JsonNetSerializer(), new UtcDateTimeProvider())).Decode(_sampleToken);
            Assert.True(payload.Length > 0);
        }


        [Fact]
        public void DecodeTokenWithVerifyCheck()
        {
            var payload = new Builder()
                .SetSecret(_sampleSecret)
                .MustVerify()
                .Decode(_sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithVerifyCheckWithoutSecret()
        {
            string payload = null;
            Assert.Throws<Exception>(() =>
            {
                payload = new Builder()
               .MustVerify()
               .Decode(_sampleToken);
            });
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithoutVerifyCheck()
        {
            var payload = new Builder()
                .NotVerify()
                .Decode(_sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenToADictionary()
        {
            var payload = new Builder()
                .SetSecret(_sampleSecret)
                .MustVerify()
                .Decode<Dictionary<string, string>>(_sampleToken);
            Assert.True(payload.Count == 2 && payload["claim1"] == 0.ToString());
        }

        [Fact]
        public void DecodeTokenToADictionaryWithoutSerializier()
        {
            Dictionary<string, string> payload = null;
            Assert.Throws<Exception>(() =>
            {
                payload = new Builder()
                .SetSerializer(null)
                .SetSecret(_sampleSecret)
                .MustVerify()
                .Decode<Dictionary<string, string>>(_sampleToken);
            });
            Assert.True(payload == null);
        }
    }
}