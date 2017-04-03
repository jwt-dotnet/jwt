using System;
using System.Collections.Generic;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using Xunit;

namespace JWT.Tests
{
    public class JwtDecoderTest
    {
        private static readonly Customer _customer = new Customer { FirstName = "Bob", Age = 37 };

        private const string _token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";
        private const string _malformedtoken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";

        private static readonly IDictionary<string, object> _dictionaryPayload = new Dictionary<string, object>
        {
            { "FirstName", "Bob" },
            { "Age", 37 }
        };

        [Fact]
        public void Decode_Should_Decode_Token_To_Json_Encoded_String()
        {
            var serializer = new JsonNetSerializer();
            var decoder = new JwtDecoder(serializer, null);

            var expectedPayload = serializer.Serialize(_customer);

            var actualPayload = decoder.Decode(_token, "ABC", verify: false);

            actualPayload.Should().Be(expectedPayload);
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary()
        {
            var serializer = new JsonNetSerializer();
            var decoder = new JwtDecoder(serializer, null);

            var actualPayload = decoder.DecodeToObject(_token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(_dictionaryPayload, options => options.IncludingAllRuntimeProperties());
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type()
        {
            var serializer = new JsonNetSerializer();
            var decoder = new JwtDecoder(serializer, null);

            var actualPayload = decoder.DecodeToObject<Customer>(_token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(_customer);
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Malformed_Token()
        {
            var serializer = new JsonNetSerializer();
            var decoder = new JwtDecoder(serializer, null);

            Action action = () => decoder.DecodeToObject<Customer>(_malformedtoken, "ABC", verify: false);

            action.ShouldThrow<ArgumentException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Key()
        {
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var decoder = new JwtDecoder(serializer, validator);

            Action action = () => decoder.DecodeToObject<Customer>(_token, "XYZ", verify: true);

            action.ShouldThrow<SignatureVerificationException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Expiration_Claim()
        {
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var decoder = new JwtDecoder(serializer, validator);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer);
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
            var decoder = new JwtDecoder(serializer, validator);

            var now = dateTimeProvider.GetNow();
            var exp = (int)(now.AddHours(-1) - JwtValidator.UnixEpoch).TotalSeconds;

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer);
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
            var decoder = new JwtDecoder(serializer, validator);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer);
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
            var decoder = new JwtDecoder(serializer, validator);

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer);
            var nbf = (int)(DateTime.UtcNow - JwtValidator.UnixEpoch).TotalSeconds;
            var validnbftoken = encoder.Encode(new { nbf = nbf }, "ABC");

            decoder.DecodeToObject<Customer>(validnbftoken, "ABC", verify: true);
        }
    }
}