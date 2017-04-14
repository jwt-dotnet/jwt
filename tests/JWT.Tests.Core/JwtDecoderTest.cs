using System;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using Xunit;
using JWT.Tests.Common;

namespace JWT.Tests
{
    public class JwtDecoderTest
    {
        [Fact]
        public void Decode_Should_Decode_Token_To_Json_Encoded_String()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var expectedPayload = serializer.Serialize(TestData.Customer);

            var actualPayload = decoder.Decode(TestData.Token, "ABC", verify: false);

            actualPayload.Should().Be(expectedPayload);
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actualPayload = decoder.DecodeToObject(TestData.Token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(TestData.DictionaryPayload, options => options.IncludingAllRuntimeProperties());
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            var actualPayload = decoder.DecodeToObject<Customer>(TestData.Token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(TestData.Customer);
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Malformed_Token()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, null, urlEncoder);

            Action action = () => decoder.DecodeToObject<Customer>(TestData.MalformedToken, "ABC", verify: false);

            action.ShouldThrow<ArgumentException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Key()
        {
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            Action action = () => decoder.DecodeToObject<Customer>(TestData.Token, "XYZ", verify: true);

            action.ShouldThrow<SignatureVerificationException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Expiration_Claim()
        {
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var invalidtoken = encoder.Encode(new { exp = "asdsad" }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(invalidtoken, "ABC", verify: true);

            action.ShouldThrow<SignatureVerificationException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Expired_Claim()
        {
            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            var now = dateTimeProvider.GetNow();
            var exp = (int)(now.AddHours(-1) - JwtValidator.UnixEpoch).TotalSeconds;

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var expiredtoken = encoder.Encode(new { exp = exp }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(expiredtoken, "ABC", verify: true);

            action.ShouldThrow<TokenExpiredException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_Before_NotBefore_Becomes_Valid()
        {
            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var nbf = (int)(DateTime.UtcNow.AddHours(1) - JwtValidator.UnixEpoch).TotalSeconds;
            var invalidnbftoken = encoder.Encode(new { nbf = nbf }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(invalidnbftoken, "ABC", verify: true);

            action.ShouldThrow<SignatureVerificationException>();
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_After_NotBefore_Becomes_Valid()
        {
            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var validator = new JwtValidator(serializer, dateTimeProvider);
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var nbf = (int)(DateTime.UtcNow - JwtValidator.UnixEpoch).TotalSeconds;
            var validnbftoken = encoder.Encode(new { nbf = nbf }, "ABC");

            decoder.DecodeToObject<Customer>(validnbftoken, "ABC", verify: true);
        }
    }
}