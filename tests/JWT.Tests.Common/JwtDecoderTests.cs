using System;
using System.Collections.Generic;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Exceptions;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace JWT.Tests
{
    [TestClass]
    public class JwtDecoderTests
    {
        private static readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public void DecodeHeader_Should_Return_Header()
        {
            const string token = TestData.TokenByAsymmetricAlgorithm;

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);

            var header = decoder.DecodeHeader(token);

            header.Should()
                  .NotBeNullOrEmpty("because decoding header should be possible without validator or algorithm");
        }

        [TestMethod]
        public void DecodeHeaderToDictionary_Should_Return_Header()
        {
            const string token = TestData.TokenByAsymmetricAlgorithm;

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);

            var header = decoder.DecodeHeaderToDictionary(token);

            header.Should()
                  .NotBeNull("because decoding header should be possible without validator or algorithm");

            header.Should()
                  .Contain("typ", "JWT");
            header.Should()
                  .Contain("alg", "RS256");
            header.Should()
                  .Contain("kid", TestData.ServerRsaPublicThumbprint1);
        }

        [TestMethod]
        public void DecodeHeader_To_JwtHeader_Should_Return_Header()
        {
            const string token = TestData.TokenByAsymmetricAlgorithm;

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);

            var header = decoder.DecodeHeader<JwtHeader>(token);

            header.Should()
                  .NotBeNull("because decoding header should be possible without validator or algorithm");

            header.Type
                  .Should()
                  .Be("JWT");
            header.Algorithm
                  .Should()
                  .Be("RS256");
            header.KeyId
                  .Should()
                  .Be(TestData.ServerRsaPublicThumbprint1);
        }

        [TestMethod]
        public void DecodeHeader_To_Dictionary_Should_Return_Header()
        {
            const string token = TestData.TokenByAsymmetricAlgorithm;

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);

            var header = decoder.DecodeHeader<Dictionary<string, string>>(token);

            header.Should()
                  .NotBeNull("because decoding header should be possible without validator or algorithm");

            header.Should()
                  .Contain("typ", "JWT")
                  .And.Contain("alg", "RS256")
                  .And.Contain("kid", TestData.ServerRsaPublicThumbprint1);
        }

        [TestMethod]
        public void Decode_Should_Decode_Token_To_Json_String()
        {
            const string key = TestData.Secret;
            const string token = TestData.Token;
            var payload = TestData.Customer;

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var actual = decoder.Decode(token, key, verify: true);

            var expected = serializer.Serialize(payload);
            actual.Should()
                  .Be(expected, "because the provided object should be correctly serialized in the token");
        }

        [TestMethod]
        public void Decode_With_Multiple_Secrets_Should_Return_Token()
        {
            const string key = TestData.Secret;
            const string token = TestData.Token;
            var payload = TestData.Customer;

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var actual = decoder.Decode(token, new[] { key }, verify: true);

            var expected = serializer.Serialize(payload);
            actual.Should()
                  .Be(expected, "because the provided object should be correctly serialized in the token");
        }

        [TestMethod]
        public void Decode_Should_Call_Custom_AlgorithmFactory()
        {
            const string token = TestData.TokenByAsymmetricAlgorithm;

            var factory = new Mock<IAlgorithmFactory>();
            factory.Setup(f => f.Create(It.IsAny<JwtDecoderContext>()))
                   .Returns(TestData.RS256Algorithm)
                   .Verifiable("because custom algorithm factory must be called");

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, factory.Object);

            decoder.Decode(token, (byte[][])null, verify: true);

            factory.VerifyAll();
        }

        [TestMethod]
        public void Decode_Without_VerifySignature_And_Without_Algorithm_Should_Return_Token()
        {
            const string token = TestData.Token;
            var payload = TestData.Customer;

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();

            var decoder = new JwtDecoder(serializer, urlEncoder);

            var actual = decoder.Decode(token);
            var expected = serializer.Serialize(payload);

            actual.Should()
                  .Be(expected, "because the provided object should be correctly serialized in the token");
        }

        [TestMethod]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary()
        {
            var expected = TestData.DictionaryPayload;
            const string key = TestData.Secret;
            const string token = TestData.Token;

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var actual = decoder.DecodeToObject(token, key, verify: true);

            actual.Should()
                  .Equal(expected, "because the JWT should have been correctly deserialized to the correct object");
        }

        [TestMethod]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary_Multiple_Secrets()
        {
            var expected = TestData.DictionaryPayload;
            const string key = TestData.Secret;
            const string token = TestData.Token;

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var actual = decoder.DecodeToObject(token, new[] { key }, verify: true);

            actual.Should()
                  .Equal(expected, "because the JWT should have been correctly deserialized to the correct object");
        }

        [TestMethod]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type()
        {
            var expected = TestData.Customer;
            const string key = TestData.Secret;
            const string token = TestData.Token;

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var actual = decoder.DecodeToObject<Customer>(token, key, verify: true);

            actual.Should()
                  .BeEquivalentTo(expected, "because the JWT should have been correctly deserialized to the same customer object");
        }

        [TestMethod]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type_With_Multiple_Secrets()
        {
            const string key = TestData.Secret;
            const string token = TestData.Token;

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var actual = decoder.DecodeToObject<Customer>(token, new[] { key }, verify: true);

            actual.Should()
                  .BeEquivalentTo(TestData.Customer, "because the JWT should have been correctly deserialized to the same customer object");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Malformed_Token()
        {
            const string badToken = TestData.TokenWithoutHeader;
            const string key = TestData.Secret;

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            Action action =
                () => decoder.DecodeToObject<Customer>(badToken, key, verify: true);

            action.Should()
                  .Throw<InvalidTokenPartsException>("because the provided token does not contains the required three parts");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Malformed_Token_With_Multiple_Secrets()
        {
            const string badToken = TestData.TokenWithoutHeader;
            var keys = new[] { TestData.Secret, TestData.Secret2 };

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            Action action =
                () => decoder.DecodeToObject<Customer>(badToken, keys, verify: true);

            action.Should()
                  .Throw<InvalidTokenPartsException>("because the provided token does not contains the required three parts");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Key()
        {
            const string token = TestData.Token;
            var key = _fixture.Create<string>();

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            Action action =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            action.Should()
                  .Throw<SignatureVerificationException>("because providing the wrong key must raise an error when the signature is verified");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Key_Multiple_Secrets()
        {
            const string token = TestData.Token;
            var keys = _fixture.Create<string[]>();

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            Action action =
                () => decoder.DecodeToObject<Customer>(token, keys, verify: true);

            action.Should()
                  .Throw<SignatureVerificationException>("because providing the wrong key must raise an error when the signature is verified");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Expiration_Claim()
        {
            const string key = TestData.Secret;

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);
            var token = encoder.Encode(new { exp = _fixture.Create<string>() }, key);

            Action action =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            action.Should()
                  .Throw<SignatureVerificationException>("because the invalid 'exp' must result in an exception on decoding");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Expiration_Claim_MultipleKeys()
        {
            const string key = TestData.Secret;

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);
            var token = encoder.Encode(new { exp = _fixture.Create<string>() }, key);

            Action action =
                () => decoder.DecodeToObject<Customer>(token, new[] { key }, verify: true);

            action.Should()
                  .Throw<SignatureVerificationException>("because the invalid 'exp' must result in an exception on decoding");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Null_Expiration_Claim()
        {
            const string key = TestData.Secret;

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);
            var token = encoder.Encode(new { exp = (object)null }, key);

            Action action =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            action.Should()
                  .Throw<SignatureVerificationException>()
                  .WithMessage("Claim 'exp' must be a number.", "because the invalid 'exp' must result in an exception on decoding");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Null_Expiration_Claim_MultipleKeys()
        {
            const string key = TestData.Secret;

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);
            var token = encoder.Encode(new { exp = (object)null }, key);

            Action action =
                () => decoder.DecodeToObject<Customer>(token, new[] { key }, verify: true);

            action.Should()
                  .Throw<SignatureVerificationException>()
                  .WithMessage("Claim 'exp' must be a number.", "because the invalid 'exp' must result in an exception on decoding");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Expired_Claim()
        {
            const string key = TestData.Secret;
            const int timeDelta = -1;

            var dateTimeProvider = new UtcDateTimeProvider();
            var serializer = new JsonNetSerializer();

            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var now = dateTimeProvider.GetNow();
            var exp = UnixEpoch.GetSecondsSince(now.AddHours(timeDelta));

            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);
            var token = encoder.Encode(new { exp }, key);

            Action action =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            action.Should()
                  .Throw<TokenExpiredException>("because decoding an expired token should raise an exception when verified");
        }

        [TestMethod]
        public void DecodeToObject_Should_Decode_Token_On_Exp_Claim_After_Year2038()
        {
            const string key = TestData.Secret;
            var dateTimeProvider = new UtcDateTimeProvider();
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            // Why 2038? See https://en.wikipedia.org/wiki/Year_2038_problem
            var exp = new DateTimeOffset(2038, 1, 19, 3, 14, 8, 0, TimeSpan.Zero).ToUnixTimeSeconds();
            var payload = new { exp };
            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);
            var validToken = encoder.Encode(payload, key);

            var expected = serializer.Serialize(payload);
            var actual = decoder.Decode(validToken, key, true);

            expected.Should()
                    .Be(actual, "because the token should be correctly decoded");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_Before_NotBefore_Becomes_Valid()
        {
            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var now = dateTimeProvider.GetNow();
            var nbf = UnixEpoch.GetSecondsSince(now.AddHours(1));

            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);
            var token = encoder.Encode(new { nbf }, TestData.Secret);

            Action action =
                () => decoder.DecodeToObject<Customer>(token, TestData.Secret, verify: true);

            action.Should()
                  .Throw<SignatureVerificationException>();
        }

        [TestMethod]
        public void DecodeToObject_Should_Decode_Token_After_NotBefore_Becomes_Valid()
        {
            var dateTimeProvider = new UtcDateTimeProvider();
            const string key = TestData.Secret;

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var now = dateTimeProvider.GetNow();
            var nbf = UnixEpoch.GetSecondsSince(now);

            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);
            var token = encoder.Encode(new { nbf }, key);

            var dic = decoder.DecodeToObject<Dictionary<string, object>>(token, key, verify: true);

            dic.Should()
               .Contain("nbf", nbf);
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Null_NotBefore_Claim()
        {
            const string key = TestData.Secret;

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var encoder = new JwtEncoder(TestData.HMACSHA256Algorithm, serializer, urlEncoder);
            var token = encoder.Encode(new { nbf = (object)null }, key);

            Action action =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            action.Should()
                  .Throw<SignatureVerificationException>()
                  .WithMessage("Claim 'nbf' must be a number.", "because the invalid 'nbf' must result in an exception on decoding");
        }
    }
}