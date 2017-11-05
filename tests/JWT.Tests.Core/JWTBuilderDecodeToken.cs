using JWT.Serializers;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace JWT.Tests.Core
{
    public class JWTBuilderDecodeToken
    {
        private const string sampleToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
        private const string sampleSecret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";


        [Fact]
        public void DecodeToken()
        {
            var payload = new JWTBuilder.Builder()
                .Decode(sampleToken);

            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutToken()
        {
            string payload = null;
            Assert.Throws<ArgumentException>(() => { payload = new JWTBuilder.Builder().Decode(null); });

            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithoutSerilizer()
        {
            string payload = null;
            Assert.Throws<Exception>(() => { payload = new JWTBuilder.Builder().SetSerializer(null).Decode(sampleToken); });            
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithAnExplicitSerilizer()
        {
            var payload = new JWTBuilder.Builder().SetSerializer(new JsonNetSerializer()).Decode(sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutUrlEncoder()
        {
            string payload = null;
            Assert.Throws<Exception>(() => { payload = new JWTBuilder.Builder().SetUrlEncoder(null).Decode(sampleToken); });            
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithAnExplicitUrlEncoder()
        {
            var payload = new JWTBuilder.Builder().SetUrlEncoder(new JwtBase64UrlEncoder()).Decode(sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutTimeProvider()
        {
            string payload = null;
            Assert.Throws<Exception>(() => { payload = new JWTBuilder.Builder().SetTimeProvider(null).Decode(sampleToken); });            
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithAnExplicitTimeProvider()
        {
            var payload = new JWTBuilder.Builder().SetTimeProvider(new UtcDateTimeProvider()).Decode(sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenWithoutValidator()
        {
            var payload = new JWTBuilder.Builder().SetValidator(null).Decode(sampleToken);
            Assert.True(payload.Length > 0);

        }

        [Fact]
        public void DecodeTokenWithAnExplicitValidator()
        {
            var payload = new JWTBuilder.Builder().SetValidator(new JwtValidator(new JsonNetSerializer(), new UtcDateTimeProvider())).Decode(sampleToken);
            Assert.True(payload.Length > 0);
        }


        [Fact]
        public void DecodeTokenWithVerifyCheck()
        {
            var payload = new JWTBuilder.Builder()
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
                payload = new JWTBuilder.Builder()
               .MustVerify()
               .Decode(sampleToken);
            });
            Assert.True(payload == null);
        }

        [Fact]
        public void DecodeTokenWithoutVerifyCheck()
        {
            var payload = new JWTBuilder.Builder()
                .NotVerify()
                .Decode(sampleToken);
            Assert.True(payload.Length > 0);
        }

        [Fact]
        public void DecodeTokenToADictionary()
        {
            var payload = new JWTBuilder.Builder()
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
                payload = new JWTBuilder.Builder()
                .SetSerializer(null)
                .SetSecret(sampleSecret)
                .MustVerify()
                .Decode<Dictionary<string, string>>(sampleToken);
            });
            Assert.True(payload == null);
        }
    }
}
