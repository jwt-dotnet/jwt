using FluentAssertions;
using JWT.Tests.Common;
using JWT.Tests.NETFramework.Serializers;
using System.Collections.Generic;
using Xunit;

namespace JWT.Tests.NETFramework
{
    public class EncodeTests
    {
        [Fact]
        public void Should_Encode_Type_With_WebScript_Serializer()
        {
            JsonWebToken.JsonSerializer = new WebScriptJsonSerializer();

            var actual = JsonWebToken.Encode(TestData.Customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(TestData.Token);
        }

        [Fact]
        public void Should_Encode_Type_With_WebScript_Serializer_And_Extra_Headers()
        {
            JsonWebToken.JsonSerializer = new WebScriptJsonSerializer();

            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };
            var actual = JsonWebToken.Encode(extraheaders, TestData.Customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(TestData.ExtraHeadersToken);
        }

        [Fact]
        public void Should_Encode_Type_With_ServiceStack_Serializer()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();

            var actual = JsonWebToken.Encode(TestData.Customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(TestData.Token);
        }

        [Fact]
        public void Should_Encode_Type_With_ServiceStack_Serializer_And_Extra_Headers()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();

            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };
            var actual = JsonWebToken.Encode(extraheaders, TestData.Customer, "ABC", JwtHashAlgorithm.HS256);

            actual.Should().Be(TestData.ExtraHeadersToken);
        }

    }
}
