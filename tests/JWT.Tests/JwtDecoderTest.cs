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

            var actualPayload = decoder.DecodeToObject<Customer>(_token, "ABC", false);

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
            var invalidexptoken = encoder.Encode(new { exp = "asdsad" }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(invalidexptoken, "ABC", verify: true);

            action.ShouldThrow<SignatureVerificationException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Expired_Claim()
        {
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var decoder = new JwtDecoder(serializer, validator);

            var anHourAgoUtc = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0));
            var unixTimestamp = (int)anHourAgoUtc.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer);
            var invalidexptoken = encoder.Encode(new { exp = unixTimestamp }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(invalidexptoken, "ABC", verify: true);

            action.ShouldThrow<TokenExpiredException>();
        }
    }
}