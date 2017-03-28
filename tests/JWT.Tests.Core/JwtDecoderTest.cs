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
            var decoder = new JwtDecoder(serializer, null);

            var expectedPayload = serializer.Serialize(TestData.Customer);

            var actualPayload = decoder.Decode(TestData.Token, "ABC", verify: false);

            actualPayload.Should().Be(expectedPayload);
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary()
        {
            var serializer = new JsonNetSerializer();
            var decoder = new JwtDecoder(serializer, null);

            var actualPayload = decoder.DecodeToObject(TestData.Token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(TestData.DictionaryPayload, options => options.IncludingAllRuntimeProperties());
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type()
        {
            var serializer = new JsonNetSerializer();
            var decoder = new JwtDecoder(serializer, null);

            var actualPayload = decoder.DecodeToObject<Customer>(TestData.Token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(TestData.Customer);
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Malformed_Token()
        {
            var serializer = new JsonNetSerializer();
            var decoder = new JwtDecoder(serializer, null);

            Action action = () => decoder.DecodeToObject<Customer>(TestData.MalformedToken, "ABC", verify: false);

            action.ShouldThrow<ArgumentException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Key()
        {
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var decoder = new JwtDecoder(serializer, validator);

            Action action = () => decoder.DecodeToObject<Customer>(TestData.Token, "XYZ", verify: true);

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
            var hourAgo = now.Subtract(new TimeSpan(1, 0, 0));
            var unixTimestamp = (int)(hourAgo - new DateTime(1970, 1, 1)).TotalSeconds;

            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer);
            var expiredtoken = encoder.Encode(new { exp = unixTimestamp }, "ABC");

            Action action = () => decoder.DecodeToObject<Customer>(expiredtoken, "ABC", verify: true);

            action.ShouldThrow<TokenExpiredException>();
        }
    }
}