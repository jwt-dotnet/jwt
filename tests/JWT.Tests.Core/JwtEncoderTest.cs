using System.Collections.Generic;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using Xunit;
using JWT.Tests.Common;

namespace JWT.Tests
{
    public class JwtEncoderTest
    {
        [Fact]
        public void Encode_Should_Encode_To_Token()
        {
            var serializer = new JsonNetSerializer();
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer);

            var actual = encoder.Encode(TestData.Customer, "ABC");

            actual.Should().Be(TestData.Token);
        }

        [Fact]
        public void Encode_Should_Encode_To_Token_With_Extra_Headers()
        {
            var serializer = new JsonNetSerializer();
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer);

            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };
            var actual = encoder.Encode(extraheaders, TestData.Customer, "ABC");

            actual.Should().Be(TestData.ExtraHeadersToken);
        }
    }
}