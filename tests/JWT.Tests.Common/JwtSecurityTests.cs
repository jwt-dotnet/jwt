using System;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using static JWT.Serializers.JsonSerializerFactory;

namespace JWT.Tests
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

            var serializer = CreateSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, new HMACSHAAlgorithmFactory());

            Action action =
                () => decoder.Decode(token, key, verify: true);

            action.Should()
                  .Throw<ArgumentException>("because the decoding of a JWT without algorithm should throw exception");
        }

        [TestMethod]
        [TestCategory("Security")]
        public void Decode_Should_Throw_Exception_When_Jwt_Contains_Multiple_Keys()
        {
            var keys = _fixture.Create<string[]>();
            const string token = TestData.TokenWithoutAlgorithm;

            var serializer = CreateSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, new HMACSHAAlgorithmFactory());

            Action action =
                () => decoder.Decode(token, keys, verify: true);

            action.Should()
                  .Throw<ArgumentException>("because the decoding of a JWT without algorithm should throw exception");
        }

        [TestMethod]
        [TestCategory("Security")]
        public void Decode_Should_Throw_Exception_When_Jwt_Contains_HMA_Algorithm_But_RSA_Was_Expected()
        {
            var serializer = CreateSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);

            var encodedToken = encoder.Encode(TestData.Customer, TestData.ServerRsaPublicKey1);
            const string key = TestData.ServerRsaPublicKey1;

            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var algFactory = new RSAlgorithmFactory(() => TestData.CertificateWithPublicKey);
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, algFactory);

            Action action =
                () => decoder.Decode(encodedToken, key, verify: true);

            action.Should()
                  .Throw<NotSupportedException>("because an encryption algorithm can't be changed on decoding");
        }

        [TestMethod]
        [TestCategory("Security")]
        public void Decode_Should_Throw_Exception_When_Jwt_Contains_HMA_Algorithm_But_RSA_Was_Expected_With_Multiple_Keys()
        {
            var serializer = CreateSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);

            var encodedToken = encoder.Encode(TestData.Customer, TestData.ServerRsaPublicKey1);

            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var algFactory = new RSAlgorithmFactory(() => TestData.CertificateWithPublicKey);
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, algFactory);

            var keys = new[] { TestData.ServerRsaPublicKey1, TestData.ServerRsaPublicKey2 };

            Action action =
                () => decoder.Decode(encodedToken, keys, verify: true);

            action.Should()
                  .Throw<NotSupportedException>("because an encryption algorithm can't be changed on decoding");
        }
    }
}