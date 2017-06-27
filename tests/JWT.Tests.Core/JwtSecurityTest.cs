using System;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using Xunit;
using JWT.Tests.Common;

namespace JWT.Tests.Core
{
    public class JwtSecurityTest
    {
        [Fact]
        [Trait("Category", "Security")]
        public void Algorithm_None_Should_Throw_Exception()
        {
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            Action action = () => decoder.Decode(TestData.AlgorithmNoneToken, "ABC", verify: true);

            action.ShouldThrow<ArgumentException>();
        }

        [Fact]
        [Trait("Category", "Security")]
        public void HMAC_Decoding_When_Expecting_RSA_Should_Fail()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var HMACencoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);

            var HMACEncodedToken = HMACencoder.Encode(TestData.Customer, TestData.ServerRSAPublicKey);

            // RSA Decoder
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var RSAFactory = new RSAlgorithmFactory(GetRSAPublicKeyAsCertificate);
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, RSAFactory);

            //var actualPayload = decoder.Decode(HMACEncodedToken, TestData.ServerRSAPublicKey, verify: true);

            Action action = () => decoder.Decode(HMACEncodedToken, TestData.ServerRSAPublicKey, verify: true);

            action.ShouldThrow<NotSupportedException>("because HMAC Tokens can be forged in RSA Decoder");
        }
    
        private System.Security.Cryptography.X509Certificates.X509Certificate2 GetRSAPublicKeyAsCertificate()
        {
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(TestData.ServerRSAPublicKey);
        }

    }
}
