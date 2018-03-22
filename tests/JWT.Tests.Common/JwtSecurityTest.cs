using System;
using System.Security.Cryptography.X509Certificates;
using JWT.Algorithms;
using JWT.Serializers;
using JWT.Tests.Common.Models;
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
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            Action action = () => decoder.Decode(TestData.AlgorithmNoneToken, "ABC", verify: true);

            Assert.Throws<ArgumentException>(action);
        }

        [Fact]
        [Trait(TestCategory.Category, TestCategory.Security)]
        public void Decode_Should_Throw_Exception_When_Non_Algorithm_Was_Used_MultipleKeys()
        {
            var serializer = new JsonNetSerializer();
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            Action action = () => decoder.Decode(TestData.AlgorithmNoneToken, new[] {"ABC", "XYZ"}, verify: true);

            Assert.Throws<ArgumentException>(action);
        }

        [Fact]
        [Trait(TestCategory.Category, TestCategory.Security)]
        public void Decode_Should_Throw_Exception_When_HMA_Algorithm_Is_Used_But_RSA_Was_Expected()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);

            var encodedToken = encoder.Encode(TestData.Customer, TestData.ServerRsaPublicKey1);

            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var algFactory = new RSAlgorithmFactory(() => new X509Certificate2(TestData.ServerRsaPublicKey1));
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder, algFactory);

            Action action = () => decoder.Decode(encodedToken, TestData.ServerRsaPublicKey1, verify: true);

            Assert.Throws<NotSupportedException>(action);
        }

        [Fact]
        [Trait(TestCategory.Category, TestCategory.Security)]
        public void Decode_Should_Throw_Exception_When_HMA_Algorithm_Is_Used_But_RSA_Was_Expected_MultipleKeys()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);

            var encodedToken = encoder.Encode(TestData.Customer, TestData.ServerRsaPublicKey1);

            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var algFactory = new RSAlgorithmFactory(() => new X509Certificate2(TestData.ServerRsaPublicKey1));
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder, algFactory);

            Action action = () => decoder.Decode(encodedToken, TestData.ServerRsaPublicKeys, verify: true);

            Assert.Throws<NotSupportedException>(action);
        }
    }
}