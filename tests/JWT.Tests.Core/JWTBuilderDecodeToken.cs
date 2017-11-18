using JWT.Serializers;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using JWT;

namespace JWT.Tests.Core
{
    public class JWTBuilderDecodeToken
    {
        private const string sampleToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
        private const string sampleSecret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";


        [Fact]
        public void DecodeToken()
        {
            var payload = new JwtBuilder()
                .Decode(sampleToken);

            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutToken()
        {
            string payload = null;
            Assert.Throws<ArgumentException>(() => { payload = new JwtBuilder().Decode(null); });

            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithoutSerilizer()
        {
            string payload = null;
            Assert.Throws<Exception>(() => { payload = new JwtBuilder().SetSerializer(null).Decode(sampleToken); });            
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithAnExplicitSerilizer()
        {
            var payload = new JwtBuilder().SetSerializer(new JsonNetSerializer()).Decode(sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutUrlEncoder()
        {
            string payload = null;
            Assert.Throws<Exception>(() => { payload = new JwtBuilder().SetUrlEncoder(null).Decode(sampleToken); });            
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithAnExplicitUrlEncoder()
        {
            var payload = new JwtBuilder().SetUrlEncoder(new JwtBase64UrlEncoder()).Decode(sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutTimeProvider()
        {
            string payload = null;
            Assert.Throws<Exception>(() => { payload = new JwtBuilder().SetTimeProvider(null).Decode(sampleToken); });            
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithAnExplicitTimeProvider()
        {
            var payload = new JwtBuilder().SetTimeProvider(new UtcDateTimeProvider()).Decode(sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutValidator()
        {
            var payload = new JwtBuilder().SetValidTor(null).Decode(sampleToken);
            Assert.True(payload.Length > 0);

        }

        [Fact]
        public void DecodeTokenWithAnExplicitValidator()
        {
            var payload = new JwtBuilder().SetValidTor(new JwtValidTor(new JsonNetSerializer(), new UtcDateTimeProvider())).Decode(sampleToken);
            Assert.True(payload.Length > 0);
        }


        [Fact]
        public void DecodeTokenWithVerifyCheck()
        {
            var payload = new JwtBuilder()
                .SetSecret(sampleSecret)
                .MustVerify()
                .Decode(sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithVerifyCheckWithoutSecret()
        {
            string payload = null;
            Assert.Throws<Exception>(() =>
            {
                payload = new JwtBuilder()
               .MustVerify()
               .Decode(sampleToken);
            });
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithoutVerifyCheck()
        {
            var payload = new JwtBuilder()
                .NotVerify()
                .Decode(sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenToADictionary()
        {
            var payload = new JwtBuilder()
                .SetSecret(sampleSecret)
                .MustVerify()
                .Decode<Dictionary<string, string>>(sampleToken);
            Assert.True(payload.Count == 2 && payload["claim1"] == 0.ToString());
        }

        [Fact]
        public void DecodeTokenToADictionaryWithoutSerializier()
        {
            Dictionary<string, string> payload = null;
            Assert.Throws<Exception>(() =>
            {
                payload = new JwtBuilder()
                .SetSerializer(null)
                .SetSecret(sampleSecret)
                .MustVerify()
                .Decode<Dictionary<string, string>>(sampleToken);
            });
            Assert.True(payload == null);
        }
    }
}
