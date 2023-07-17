using FluentAssertions;
using JWT.Builder;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
namespace JWT.Tests.Stubs
{
    [TestClass]
    public class JwtHeaderTests
    {
        public void JwtHeader_Should_Create()
        {
            var header = new JwtHeader();
            header.Should().NotBeNull();
        }
        [TestMethod]
        public void JwtHeader_Should_Serialize()
        {
            const string token = TestData.TokenByAsymmetricAlgorithm;

            var serializer = new DefaultJsonSerializerFactory().Create();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);

            var header = decoder.DecodeHeader<JwtHeader>(token);
            header.Should().NotBeNull();

            var serializedHeader = serializer.Serialize(header);
            header.Should().Equals(serializer.Deserialize<JwtHeader>(serializedHeader)));
        }
    }
}
