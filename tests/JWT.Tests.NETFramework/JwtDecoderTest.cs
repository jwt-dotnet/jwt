using FluentAssertions;
using JWT.Serializers;
using JWT.Tests.Common;
using Xunit;

namespace JWT.Tests.NETFramework
{
    /// <summary>
    /// Sanity tests to make sure the package works from a .NET Framework project.
    /// The main tests are in JWT.Tests.Core, which should be cross-platform.
    /// </summary>
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
    }
}
