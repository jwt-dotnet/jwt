using System;
using System.Collections.Generic;

using FluentAssertions;
using JWT.Serializers;
using JWT.Tests.Serializers;
using Xunit;

namespace JWT.Tests
{
    public class DecodeTests
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
        public void Decode_Should_Decode_Token_To_Json_Encoded_String_With_JsonNet_Serializer()
        {
            var serializer = new JsonNetSerializer();
            JsonWebToken.JsonSerializer = serializer;

            var expectedPayload = serializer.Serialize(_customer);
            var actualPayload = JsonWebToken.Decode(_token, "ABC", verify: false);

            actualPayload.Should().Be(expectedPayload);
        }

        [Fact]
        public void Decode_Should_Decode_Token_To_Json_Encoded_String_With_WebScript_Serializer()
        {
            var serializer = new WebScriptJsonSerializer();
            JsonWebToken.JsonSerializer = serializer;

            var expectedPayload = serializer.Serialize(_customer);

            var actualPayload = JsonWebToken.Decode(_token, "ABC", verify: false);

            actualPayload.Should().Be(expectedPayload);
        }

        [Fact]
        public void Decode_Should_Decode_Token_To_Json_Encoded_String_With_ServiceStack_Serializer()
        {
            var serializer = new ServiceStackJsonSerializer();
            JsonWebToken.JsonSerializer = serializer;

            var expectedPayload = serializer.Serialize(_customer);

            var actualPayload = JsonWebToken.Decode(_token, "ABC", verify: false);

            actualPayload.Should().Be(expectedPayload);
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary_With_WebScript_Serializer()
        {
            JsonWebToken.JsonSerializer = new WebScriptJsonSerializer();

            var actualPayload = JsonWebToken.DecodeToObject(_token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(_dictionaryPayload, options => options.IncludingAllRuntimeProperties());
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary_With_ServiceStack_Serializer()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();

            var actualPayload = JsonWebToken.DecodeToObject(_token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(_dictionaryPayload, options => options.IncludingAllRuntimeProperties());
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary_With_JsonNet_Serializer()
        {
            JsonWebToken.JsonSerializer = new JsonNetSerializer();

            var actualPayload = JsonWebToken.DecodeToObject(_token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(_dictionaryPayload, options => options.IncludingAllRuntimeProperties());
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type_With_WebScript_Serializer()
        {
            JsonWebToken.JsonSerializer = new WebScriptJsonSerializer();

            var actualPayload = JsonWebToken.DecodeToObject<Customer>(_token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(_customer);
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type_With_ServiceStack_Serializer()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();

            var actualPayload = JsonWebToken.DecodeToObject<Customer>(_token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(_customer);
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type_With_JsonNet_Serializer()
        {
            JsonWebToken.JsonSerializer = new JsonNetSerializer();

            var actualPayload = JsonWebToken.DecodeToObject<Customer>(_token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(_customer);
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Malformed_Token()
        {
            Action action = () => JsonWebToken.DecodeToObject<Customer>(_malformedtoken, "ABC", verify: false);

            action.ShouldThrow<ArgumentException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Key()
        {
            Action action = () => JsonWebToken.DecodeToObject<Customer>(_token, "XYZ", verify: true);

            action.ShouldThrow<SignatureVerificationException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Invalid_Expiration_Claim()
        {
            var invalidexptoken = JsonWebToken.Encode(new { exp = "asdsad" }, "ABC", JwtHashAlgorithm.HS256);

            Action action = () => JsonWebToken.DecodeToObject<Customer>(invalidexptoken, "ABC", verify: true);

            action.ShouldThrow<SignatureVerificationException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_On_Expired_Claim()
        {
            var exp = (int)(DateTime.UtcNow.AddHours(-1) - JwtValidator.UnixEpoch).TotalSeconds;
            var expiredtoken = JsonWebToken.Encode(new { exp = exp }, "ABC", JwtHashAlgorithm.HS256);

            Action action = () => JsonWebToken.DecodeToObject<Customer>(expiredtoken, "ABC", verify: true);

            action.ShouldThrow<TokenExpiredException>();
        }

        [Fact]
        public void DecodeToObject_Should_Throw_Exception_Before_NotBefore_Becomes_Valid()
        {
            var nbf = (int)(DateTime.UtcNow.AddHours(1) - JwtValidator.UnixEpoch).TotalSeconds;
            var invalidnbftoken = JsonWebToken.Encode(new { nbf = nbf }, "ABC", JwtHashAlgorithm.HS256);

            Action action = () => JsonWebToken.DecodeToObject<Customer>(invalidnbftoken, "ABC", verify: true);

            action.ShouldThrow<SignatureVerificationException>();
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_After_NotBefore_Becomes_Valid()
        {
            var nbf = (int)(DateTime.UtcNow - JwtValidator.UnixEpoch).TotalSeconds;
            var validnbftoken = JsonWebToken.Encode(new { nbf = nbf }, "ABC", JwtHashAlgorithm.HS256);

            JsonWebToken.DecodeToObject<Customer>(validnbftoken, "ABC", verify: true);
        }
    }
}