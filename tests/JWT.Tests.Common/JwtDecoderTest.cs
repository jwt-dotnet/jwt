using System;
using JWT.Algorithms;
using JWT.Serializers;
using JWT.Tests.Common.Internal;
using JWT.Tests.Common.Models;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtDecoderTest
    {
        [Fact]
        public void Decode_Should_Decode_Token_To_Json_Encoded_String()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var expected = serializer.Serialize(TestData.Customer);

            var actual = decoder.Decode(TestData.Token, "ABC", verify: false);

            Assert.Equal(actual, expected);
        }

        [Fact]
        public void Decode_Should_Decode_Token_To_Json_Encoded_String_Multiple_Secrets()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var expected = serializer.Serialize(TestData.Customer);

            var actual = decoder.Decode(TestData.Token, new []{"ABC", "DEF"}, verify: false);

            Assert.Equal(actual, expected);
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actual = decoder.DecodeToObject(TestData.Token, "ABC", verify: false);

            Assert.Equal(actual, TestData.DictionaryPayload, new DictionaryEqualityComparer());
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary_Multiple_Secrets()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actual = decoder.DecodeToObject(TestData.Token, new []{"ABC", "DEF"}, verify: false);

            Assert.Equal(actual, TestData.DictionaryPayload, new DictionaryEqualityComparer());
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actual = decoder.DecodeToObject<Customer>(TestData.Token, "ABC", verify: false);
            Assert.Equal(actual, TestData.Customer, new CustomerEqualityComparer());
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type_Multiple_Secrets()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actual = decoder.DecodeToObject<Customer>(TestData.Token, new []{"ABC", "DEF"}, verify: false);
            Assert.Equal(actual, TestData.Customer, new CustomerEqualityComparer());
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Malformed_Token()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            Action action = () => decoder.DecodeToObject<Customer>(TestData.MalformedToken, "ABC", verify: false);

            Assert.Throws<InvalidTokenPartsException>(action);
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Malformed_Token_Multiple_Secrets()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            Action action = () => decoder.DecodeToObject<Customer>(TestData.MalformedToken, new []{"ABC", "DEF"}, verify: false);

            Assert.Throws<InvalidTokenPartsException>(action);
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Key()
        {
            var serializer = new JsonNetSerializer();
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            Action action = () => decoder.DecodeToObject<Customer>(TestData.Token, "XYZ", verify: true);

            Assert.Throws<SignatureVerificationException>(action);
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Key_Multiple_Secrets()
        {
            var serializer = new JsonNetSerializer();
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            Action action = () => decoder.DecodeToObject<Customer>(TestData.Token, new []{"XYZ", "JKL"}, verify: true);

            Assert.Throws<SignatureVerificationException>(action);
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Expiration_Claim()
        {
            var serializer = new JsonNetSerializer();
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { exp = "asdsad" }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(token, "ABC", verify: true);

            Assert.Throws<SignatureVerificationException>(action);
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Expiration_Claim_MultipleKeys()
        {
            var serializer = new JsonNetSerializer();
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { exp = "asdsad" }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(token, new []{"ABC", "DEF"}, verify: true);

            Assert.Throws<SignatureVerificationException>(action);
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Null_Expiration_Claim()
        {
            var serializer = new JsonNetSerializer();
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { exp = (object)null }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(token, "ABC", verify: true);

            var message = Assert.Throws<SignatureVerificationException>(action).Message;
            Assert.Equal(message, "Claim 'exp' must be a number.");
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Null_Expiration_Claim_MultipleKeys()
        {
            var serializer = new JsonNetSerializer();
            var validTor = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { exp = (object)null }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(token, new []{"ABC", "DEF"}, verify: true);

            var message = Assert.Throws<SignatureVerificationException>(action).Message;
            Assert.Equal(message, "Claim 'exp' must be a number.");
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Expired_Claim()
        {
            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validTor = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            var now = dateTimeProvider.GetNow();
            var exp = UnixEpoch.GetSecondsSince(now.AddHours(-1));

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { exp }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(token, "ABC", verify: true);

            Assert.Throws<TokenExpiredException>(action);
        }

        [Fact]
        public void DecodeToObject_Should_DecodeToken_On_Exp_Claim_After_Year2038()
        {
            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validTor = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            // Why 2038? See https://en.wikipedia.org/wiki/Year_2038_problem
            var post2038 = new DateTime(2038, 1, 19, 3, 14, 8, DateTimeKind.Utc);
            var exp = (post2038 - new DateTime(1970, 1, 1)).TotalSeconds;
            var payload = new { exp };
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var validToken = encoder.Encode(payload, "ABC");

            var expected = serializer.Serialize(payload);
            var actual = decoder.Decode(validToken, "ABC", true);

            Assert.Equal(actual, expected);
        }

        [Fact]
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

            Action action = () => decoder.DecodeToObject<Customer>(token, "ABC", verify: true);

            Assert.Throws<SignatureVerificationException>(action);
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Null_NotBefore_Claim()
        {
            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validTor = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { nbf = (object)null }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(token, "ABC", verify: true);

            var message = Assert.Throws<SignatureVerificationException>(action).Message;
            Assert.Equal(message, "Claim 'nbf' must be a number.");
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_After_NotBefore_Becomes_Valid()
        {
            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validTor = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validTor, urlEncoder);

            var now = dateTimeProvider.GetNow();
            var nbf = UnixEpoch.GetSecondsSince(now);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var token = encoder.Encode(new { nbf }, "ABC");

            decoder.DecodeToObject<Customer>(token, "ABC", verify: true);
        }
    }
}