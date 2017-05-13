using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using JWT.Tests.Common;
using Xunit;

namespace JWT.Tests.NETFramework
{
    /// <summary>
    /// Sanity tests to make sure the package works from a .NET Framework project.
    /// The main tests are in JWT.Tests.Core, which should be cross-platform.
    /// </summary>
    public class JwtEncoderTest
    {
        [Fact]
        public void Encode_Should_Encode_To_Token()
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);

            var actual = encoder.Encode(TestData.Customer, "ABC");

            actual.Should().Be(TestData.Token);
        }
    }
}
