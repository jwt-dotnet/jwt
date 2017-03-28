using System.Collections.Generic;
using FluentAssertions;
using JWT.Serializers;
using Xunit;
using JWT.Tests.Common;

namespace JWT.Tests
{
    public class EncodeTests
    {
        [Fact]
        public void Should_Encode_Type_With_JsonNet_Serializer()
        {
            JsonWebToken.JsonSerializer = new JsonNetSerializer();

            var actual = JsonWebToken.Encode(TestData.Customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(TestData.Token);
        }

        [Fact]
        public void Should_Encode_Type_With_JsonNet_Serializer_And_Extra_Headers()
        {
            JsonWebToken.JsonSerializer = new JsonNetSerializer();

            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };
            var actual = JsonWebToken.Encode(extraheaders, TestData.Customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(TestData.ExtraHeadersToken);
        }
    }
}