using AutoFixture;
using System;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using JWT.Tests.Common.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Common
{
    [TestClass]
    public class JwtDecoderTests
    {
        private readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public void Decode_Should_Decode_Token_To_Json_Encoded_String()
        {
            var key = _fixture.Create<string>();
            const string token = TestData.Token;
            var toSerialize = TestData.Customer;

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actual = decoder.Decode(token, key, verify: false);
            var expected = serializer.Serialize(toSerialize);

            actual.Should()
                .Be(expected, "because the provided object should be correctly serialized in the token");
        }

        [TestMethod]
        public void Decode_Should_Decode_Token_To_Json_Encoded_String_Multiple_Secrets()
        {
            var keys = _fixture.Create<string[]>();
            const string token = TestData.Token;
            var toSerialize = TestData.Customer;

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actual = decoder.Decode(token, keys, verify: false);
            var expected = serializer.Serialize(toSerialize);

            actual.Should()
                  .Be(expected, "because the provided object should be correctly serialized in the token");
        }

        [TestMethod]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary()
        {
            var expected = TestData.DictionaryPayload;
            var key = _fixture.Create<string>();
            const string token = TestData.Token;

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actual = decoder.DecodeToObject(token, key, verify: false);

            actual.Should()
                  .Equal(expected, "because the JWT should have been correctly deserialized to the correct object");
        }

        [TestMethod]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary_Multiple_Secrets()
        {
            var expected = TestData.DictionaryPayload;
            var keys = _fixture.Create<string[]>();
            const string token = TestData.Token;

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actual = decoder.DecodeToObject(token, keys, verify: false);

            actual.Should()
                  .Equal(expected, "because the JWT should have been correctly deserialized to the correct object");
        }

        [TestMethod]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type()
        {
            var expected = TestData.Customer;
            var key = _fixture.Create<string>();
            const string token = TestData.Token;

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actual = decoder.DecodeToObject<Customer>(token, key, verify: false);

            actual.Should()
                  .BeEquivalentTo(expected, "because the JWT should have been correctly deserialized to the same customer object");
        }

        [TestMethod]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type_Multiple_Secrets()
        {
            var expected = TestData.Customer;
            var keys = _fixture.Create<string[]>();
            const string token = TestData.Token;

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actual = decoder.DecodeToObject<Customer>(token, keys, verify: false);

            actual.Should()
                  .BeEquivalentTo(expected, "because the JWT should have been correctly deserialized to the same customer object");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Malformed_Token()
        {
            const string badToken = TestData.MalformedToken;
            var key = _fixture.Create<string>();

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            Action decodeInvalidJwt =
                () => decoder.DecodeToObject<Customer>(badToken, key, verify: false);

            decodeInvalidJwt.Should()
                            .Throw<InvalidTokenPartsException>("because the provided token does not contains the required three parts");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Malformed_Token_Multiple_Secrets()
        {
            const string badToken = TestData.MalformedToken;
            var keys = _fixture.Create<string[]>();

            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            Action decodeInvalidJwtWithMultipleKeys =
                () => decoder.DecodeToObject<Customer>(badToken, keys, verify: false);

            decodeInvalidJwtWithMultipleKeys.Should()
                                            .Throw<InvalidTokenPartsException>("because the provided token does not contains the required three parts");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Key()
        {
            const string token = TestData.Token;
            var key = _fixture.Create<string>();

            var serializer = new JsonNetSerializer();
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

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
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            Action decodeJwtWithWrongKey =
                () => decoder.DecodeToObject<Customer>(token, keys, verify: true);

            decodeJwtWithWrongKey.Should()
                                 .Throw<SignatureVerificationException>("because providing the wrong key must raise an error when the signature is verified");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Expiration_Claim()
        {
            var key = _fixture.Create<string>();

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { exp = _fixture.Create<string>() }, key);

            Action encodeJwtWithWrongExpField =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            encodeJwtWithWrongExpField.Should()
                                      .Throw<SignatureVerificationException>("because the invalid 'exp' must result in an exception on decoding");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Expiration_Claim_MultipleKeys()
        {
            var key = _fixture.Create<string>();
            var keys = _fixture.Create<string[]>();
            keys[0] = key;

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { exp = _fixture.Create<string>() }, key);

            Action encodeJwtWithWrongExpField =
                () => decoder.DecodeToObject<Customer>(token, keys, verify: true);

            encodeJwtWithWrongExpField.Should()
                                      .Throw<SignatureVerificationException>("because the invalid 'exp' must result in an exception on decoding");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Null_Expiration_Claim()
        {
            var key = _fixture.Create<string>();

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
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
            var key = _fixture.Create<string>();
            var keys = _fixture.Create<string[]>();
            keys[0] = key;

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { exp = (object)null }, key);

            Action encodeJwtWithNullExpField =
                () => decoder.DecodeToObject<Customer>(token, keys, verify: true);

            encodeJwtWithNullExpField.Should()
                                     .Throw<SignatureVerificationException>()
                                     .WithMessage("Claim 'exp' must be a number.", "because the invalid 'exp' must result in an exception on decoding");
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Expired_Claim()
        {
            var key = _fixture.Create<string>();
            const int timeDelta = -1;

            var algorithm = new HMACSHA256Algorithm();
            var dateTimeProvider = new UtcDateTimeProvider();
            var serializer = new JsonNetSerializer();

            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            var now = dateTimeProvider.GetNow();
            var exp = UnixEpoch.GetSecondsSince(now.AddHours(timeDelta));

            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
            var token = encoder.Encode(new { exp }, key);

            Action decodeExpiredJwt =
                () => decoder.DecodeToObject<Customer>(token, key, verify: true);

            decodeExpiredJwt.Should()
                            .Throw<TokenExpiredException>("because decoding an expired token should raise an exception when verified");
        }

        [TestMethod]
        public void DecodeToObject_Should_DecodeToken_On_Exp_Claim_After_Year2038()
        {
            var key = _fixture.Create<string>();
            var dateTimeProvider = new UtcDateTimeProvider();
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            // Why 2038? See https://en.wikipedia.org/wiki/Year_2038_problem
            var post2038 = new DateTime(2038, 1, 19, 3, 14, 8, DateTimeKind.Utc);
            var exp = (post2038 - new DateTime(1970, 1, 1)).TotalSeconds;
            var payload = new { exp };
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
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
            var validTor = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            var now = dateTimeProvider.GetNow();
            var nbf = UnixEpoch.GetSecondsSince(now.AddHours(1));

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { nbf }, "ABC");

            Action decodeNotActiveJwt =
                () => decoder.DecodeToObject<Customer>(token, "ABC", verify: true);

            decodeNotActiveJwt.Should()
                              .Throw<SignatureVerificationException>();
        }

        [TestMethod]
        public void DecodeToObject_Should_Throw_Exception_On_Null_NotBefore_Claim()
        {
            var key = _fixture.Create<string>();

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
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
            var key = _fixture.Create<string>();

            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());

            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            var now = dateTimeProvider.GetNow();
            var nbf = UnixEpoch.GetSecondsSince(now);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { nbf }, key);

            decoder.DecodeToObject<Customer>(token, key, verify: true);
        }
    }
}
