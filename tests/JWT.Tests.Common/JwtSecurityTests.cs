using System;
using System.Security.Cryptography.X509Certificates;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Common
{
    [TestClass]
    public class JwtSecurityTests
    {
        private static readonly Fixture _fixture = new Fixture();

        [TestMethod]
        [TestCategory("Security")]
        public void Decode_Should_Throw_Exception_When_Jwt_Contains_No_Algorithm()
        {
            var key = _fixture.Create<string>();
            const string token = TestData.TokenWithoutAlgorithm;

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, new HMACSHAAlgorithmFactory());

            Action decodeJwtWithNoAlgorithm =
                () => decoder.Decode(token, key, verify: true);

            decodeJwtWithNoAlgorithm.Should()
                                    .Throw<ArgumentException>("because the decoding of a JWT without algorithm should throw exception");
        }

        [TestMethod]
        [TestCategory("Security")]
        public void Decode_Should_Throw_Exception_When_Jwt_Contains_Multiple_Keys()
        {
            var keys = _fixture.Create<string[]>();
            const string token = TestData.TokenWithoutAlgorithm;

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, new HMACSHAAlgorithmFactory());

            Action decodeJwtWithMultipleKeys =
                () => decoder.Decode(token, keys, verify: true);

            decodeJwtWithMultipleKeys.Should()
                                     .Throw<ArgumentException>("because the decoding of a JWT without algorithm should throw exception");
        }

        [TestMethod]
        [TestCategory("Security")]
        public void Decode_Should_Throw_Exception_When_Jwt_Contains_HMA_Algorithm_But_RSA_Was_Expected()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);

            var encodedToken = encoder.Encode(TestData.Customer, TestData.ServerRsaPublicKey1);
            const string key = TestData.ServerRsaPublicKey1;

            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var algFactory = new RSAlgorithmFactory(() => new X509Certificate2(TestData.ServerRsaPublicKey1));
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, algFactory);

            Action decodeJwtWithHmaWhenRsaIsExpected =
                () => decoder.Decode(encodedToken, key, verify: true);

            decodeJwtWithHmaWhenRsaIsExpected.Should()
                                             .Throw<NotSupportedException>("because an encryption algorithm can't be changed on decoding");
        }

        [TestMethod]
        [TestCategory("Security")]
        public void Decode_Should_Throw_Exception_When_Jwt_Contains_HMA_Algorithm_But_RSA_Was_Expected_With_Multiple_Keys()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);

            var encodedToken = encoder.Encode(TestData.Customer, TestData.ServerRsaPublicKey1);

            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var algFactory = new RSAlgorithmFactory(() => new X509Certificate2(TestData.ServerRsaPublicKey1));
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, algFactory);

            Action decodeJwtWithRsaWhenHmaIsExpected =
                () => decoder.Decode(encodedToken, TestData.ServerRsaPublicKeys, verify: true);

            decodeJwtWithRsaWhenHmaIsExpected.Should()
                                             .Throw<NotSupportedException>("because an encryption algorithm can't be changed on decoding");
        }
    }
}
