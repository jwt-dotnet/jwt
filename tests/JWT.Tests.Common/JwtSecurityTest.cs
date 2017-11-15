using System;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtSecurityTest
    {
        [Fact]
        [Trait(TestCategory.Category, TestCategory.Security)]
        public void Decode_Should_Throw_Exception_When_Non_Algorithm_Was_Used()
        {
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            Action action = () => decoder.Decode(TestData.AlgorithmNoneToken, "ABC", verify: true);

            action.ShouldThrow<ArgumentException>();
        }

        [Fact]
        [Trait(TestCategory.Category, TestCategory.Security)]
        public void Decode_Should_Throw_Exception_When_HMA_Algorithm_Is_Used_But_RSA_Was_Expected()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);

            var encodedToken = encoder.Encode(TestData.Customer, TestData.ServerRSAPublicKey);

            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var algFactory = new RSAlgorithmFactory(() => new X509Certificate2(TestData.ServerRSAPublicKey));
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, algFactory);

            Action action = () => decoder.Decode(encodedToken, TestData.ServerRSAPublicKey, verify: true);

            action.ShouldThrow<NotSupportedException>("Because HMAC Tokens can be forged in RSA Decoder");
        }
    }
}