using FluentAssertions;
using JWT.Builder;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class JwtHeaderTests
    {
        [TestMethod]
        public void JwtHeader_Should_Be_Serializable()
        {
            const string token = TestData.TokenByAsymmetricAlgorithm;

            var serializer = new DefaultJsonSerializerFactory().Create();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);

            var expected = decoder.DecodeHeader<JwtHeader>(token);
            expected.Should().NotBeNull();

            var serializedHeader = serializer.Serialize(expected);
            var actual = serializer.Deserialize<JwtHeader>(serializedHeader);
            
            actual.Should().BeEquivalentTo(expected);
        }
    }
}
