using System.Collections.Generic;
using FluentAssertions;
using JWT.Serializers;
using JWT.Tests.Serializers;
using Xunit;

namespace JWT.Tests
{
    public class EncodeTests
    {
        private static readonly Customer _customer = new Customer { FirstName = "Bob", Age = 37 };

        private const string _token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";
        private const string _extraheaderstoken = "eyJmb28iOiJiYXIiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.slrbXF9VSrlX7LKsV-Umb_zEzWLxQjCfUOjNTbvyr1g";

        [Fact]
        public void Should_Encode_Type_With_WebScript_Serializer()
        {
            JsonWebToken.JsonSerializer = new WebScriptJsonSerializer();

            var actual = JsonWebToken.Encode(_customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(_token);
        }

        [Fact]
        public void Should_Encode_Type_With_WebScript_Serializer_And_Extra_Headers()
        {
            JsonWebToken.JsonSerializer = new WebScriptJsonSerializer();

            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };
            var actual = JsonWebToken.Encode(extraheaders, _customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(_extraheaderstoken);
        }

        [Fact]
        public void Should_Encode_Type_With_ServiceStack_Serializer()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();

            var actual = JsonWebToken.Encode(_customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(_token);
        }

        [Fact]
        public void Should_Encode_Type_With_ServiceStack_Serializer_And_Extra_Headers()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();

            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };
            var actual = JsonWebToken.Encode(extraheaders, _customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(_extraheaderstoken);
        }

        [Fact]
        public void Should_Encode_Type_With_JsonNet_Serializer()
        {
            JsonWebToken.JsonSerializer = new JsonNetSerializer();

            var actual = JsonWebToken.Encode(_customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(_token);
        }

        [Fact]
        public void Should_Encode_Type_With_JsonNet_Serializer_And_Extra_Headers()
        {
            JsonWebToken.JsonSerializer = new JsonNetSerializer();

            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };
            var actual = JsonWebToken.Encode(extraheaders, _customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(_extraheaderstoken);
        }
    }
}