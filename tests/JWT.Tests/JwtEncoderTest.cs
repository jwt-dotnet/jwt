using System.Collections.Generic;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using Xunit;

namespace JWT.Tests
{
    public class JwtEncoderTest
    {
        private static readonly Customer _customer = new Customer { FirstName = "Bob", Age = 37 };

        private const string _token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";
        private const string _extraheaderstoken = "eyJmb28iOiJiYXIiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.slrbXF9VSrlX7LKsV-Umb_zEzWLxQjCfUOjNTbvyr1g";

        [Fact]
        public void Encode_Should_Encode_To_Token()
        {
            var serializer = new JsonNetSerializer();
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer);

            var actual = encoder.Encode(_customer, "ABC");

            actual.Should().Be(_token);
        }

        [Fact]
        public void Encode_Should_Encode_To_Token_With_Extra_Headers()
        {
            var serializer = new JsonNetSerializer();
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer);

            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };
            var actual = encoder.Encode(extraheaders, _customer, "ABC");

            actual.Should().Be(_extraheaderstoken);
        }
    }
}