using System;
using System.Security.Cryptography.X509Certificates;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using JWT.Tests.Common.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Common
{
    [TestClass]
    public class JwtSecurityTests
    {
        private readonly Fixture _fixture = new Fixture();

        [TestMethod]
        [TestCategory(TestCategory.Security)]
        public void Decode_Should_Throw_Exception_When_Non_Algorithm_Was_Used()
        {
            var key = _fixture.Create<string>();
            const string token = TestData.AlgorithmNoneToken;

            var serializer = new JsonNetSerializer();
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            Action decodeJwtWithNoAlgorithm =
                () => decoder.Decode(token, key, verify: true);

            decodeJwtWithNoAlgorithm.Should()
                                    .Throw<ArgumentException>("because the decoding of a JWT without algorithm should raise an exception");
        }

        [TestMethod]
        [TestCategory(TestCategory.Security)]
        public void Decode_Should_Throw_Exception_When_Non_Algorithm_Was_Used_MultipleKeys()
        {
            var keys = _fixture.Create<string[]>();
            const string token = TestData.AlgorithmNoneToken;

            var serializer = new JsonNetSerializer();
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            Action decodeJwtWithNoAlgorithm =
                () => decoder.Decode(token, keys, verify: true);

            decodeJwtWithNoAlgorithm.Should()
                                    .Throw<ArgumentException>("because the decoding of a JWT without algorithm should raise an exception");
        }

        [TestMethod]
        [TestCategory(TestCategory.Security)]
        public void Decode_Should_Throw_Exception_When_HMA_Algorithm_Is_Used_But_RSA_Was_Expected()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);

            var encodedToken = encoder.Encode(TestData.Customer, TestData.ServerRsaPublicKey1);
            const string key = TestData.ServerRsaPublicKey1;

            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var algFactory = new RSAlgorithmFactory(() => new X509Certificate2(TestData.ServerRsaPublicKey1));
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder, algFactory);

            Action decodeJwtWithHmaWhenRsaIsExpected =
                () => decoder.Decode(encodedToken, key, verify: true);

            decodeJwtWithHmaWhenRsaIsExpected.Should()
                                             .Throw<NotSupportedException>("because an encryption algorithm can't be changed another on decoding");
        }

        [TestMethod]
        [TestCategory(TestCategory.Security)]
        public void Decode_Should_Throw_Exception_When_HMA_Algorithm_Is_Used_But_RSA_Was_Expected_MultipleKeys()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);

            var encodedToken = encoder.Encode(TestData.Customer, TestData.ServerRsaPublicKey1);

            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var algFactory = new RSAlgorithmFactory(() => new X509Certificate2(TestData.ServerRsaPublicKey1));
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder, algFactory);

            Action decodeJwtWithRsaWhenHmaIsExpected =
                () => decoder.Decode(encodedToken, TestData.ServerRsaPublicKeys, verify: true);

            decodeJwtWithRsaWhenHmaIsExpected.Should()
                                             .Throw<NotSupportedException>("because an encryption algorithm can't be changed another on decoding");
        }
    }
}
