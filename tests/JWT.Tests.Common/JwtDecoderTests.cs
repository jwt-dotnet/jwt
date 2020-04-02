using AutoFixture;
using System;
using FluentAssertions;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Common
{
    [TestClass]
    public class JwtDecoderTests
    {
        private static readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public void Decode_Should_Decode_Token_To_Json_String()
        {
            const string key = TestData.Secret;
            const string token = TestData.Token;
            var toSerialize = TestData.Customer;

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var actual = decoder.Decode(token, key, verify: true);
            var expected = serializer.Serialize(toSerialize);

            actual.Should()
                  .Be(expected, "because the provided object should be correctly serialized in the token");
        }

        [TestMethod]
        public void Decode_Should_Decode_Token_To_Json_String_Multiple_Secrets()
        {
            const string key = TestData.Secret;
            const string token = TestData.Token;
            var toSerialize = TestData.Customer;

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var actual = decoder.Decode(token, new[] { key }, verify: true);
            var expected = serializer.Serialize(toSerialize);

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
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type_Multiple_Secrets()
        {
            var expected = TestData.Customer;
            const string key = TestData.Secret;
            const string token = TestData.Token;

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            var actual = decoder.DecodeToObject<Customer>(token, new[] { key }, verify: true);

            actual.Should()
                  .BeEquivalentTo(expected, "because the JWT should have been correctly deserialized to the same customer object");
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

            Action decodeInvalidJwt =
                () => decoder.DecodeToObject<Customer>(badToken, key, verify: true);

            decodeInvalidJwt.Should()
                            .Throw<InvalidTokenPartsException>("because the provided token does not contains the required three parts");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Malformed_Token_Multiple_Secrets()
        {
            const string badToken = TestData.TokenWithoutHeader;
            const string key = TestData.Secret;

            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            Action decodeInvalidJwtWithMultipleKeys =
                () => decoder.DecodeToObject<Customer>(badToken, new[] { key }, verify: true);

            decodeInvalidJwtWithMultipleKeys.Should()
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

            Action decodeJwtWithWrongKey =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            decodeJwtWithWrongKey.Should()
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

            Action decodeJwtWithWrongKey =
                () => decoder.DecodeToObject<Customer>(token, keys, verify: true);

            decodeJwtWithWrongKey.Should()
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

            Action encodeJwtWithWrongExpField =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            encodeJwtWithWrongExpField.Should()
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

            Action encodeJwtWithWrongExpField =
                () => decoder.DecodeToObject<Customer>(token, new[] { key }, verify: true);

            encodeJwtWithWrongExpField.Should()
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

            Action encodeJwtWithNullExpField =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            encodeJwtWithNullExpField.Should()
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

            Action encodeJwtWithNullExpField =
                () => decoder.DecodeToObject<Customer>(token, new[] { key }, verify: true);

            encodeJwtWithNullExpField.Should()
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

            Action decodeExpiredJwt =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            decodeExpiredJwt.Should()
                            .Throw<TokenExpiredException>("because decoding an expired token should raise an exception when verified");
        }

        [TestMethod]
        public void DecodeToObject_Should_DecodeToken_On_Exp_Claim_After_Year2038()
        {
            const string key = TestData.Secret;
            var dateTimeProvider = new UtcDateTimeProvider();
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, TestData.HMACSHA256Algorithm);

            // Why 2038? See https://en.wikipedia.org/wiki/Year_2038_problem
            var post2038 = new DateTime(2038, 1, 19, 3, 14, 8, DateTimeKind.Utc);
            var exp = (post2038 - new DateTime(1970, 1, 1)).TotalSeconds;
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

            Action decodeNotActiveJwt =
                () => decoder.DecodeToObject<Customer>(token, TestData.Secret, verify: true);

            decodeNotActiveJwt.Should()
                              .Throw<SignatureVerificationException>();
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

            Action encodeJwtWithNullExpField =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            encodeJwtWithNullExpField.Should()
                                     .Throw<SignatureVerificationException>()
                                     .WithMessage("Claim 'nbf' must be a number.", "because the invalid 'nbf' must result in an exception on decoding");
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

            decoder.DecodeToObject<Customer>(token, key, verify: true);
        }
    }
}
