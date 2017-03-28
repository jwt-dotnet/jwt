using FluentAssertions;
using JWT.Tests.Common;
using JWT.Tests.NETFramework.Serializers;
using Xunit;

namespace JWT.Tests.NETFramework
{
    public class DecodeTests
    {
        [Fact]
        public void Decode_Should_Decode_Token_To_Json_Encoded_String_With_WebScript_Serializer()
        {
            var serializer = new WebScriptJsonSerializer();
            JsonWebToken.JsonSerializer = serializer;

            var expectedPayload = serializer.Serialize(TestData.Customer);

            var actualPayload = JsonWebToken.Decode(TestData.Token, "ABC", verify: false);

            actualPayload.Should().Be(expectedPayload);
        }

        [Fact]
        public void Decode_Should_Decode_Token_To_Json_Encoded_String_With_ServiceStack_Serializer()
        {
            var serializer = new ServiceStackJsonSerializer();
            JsonWebToken.JsonSerializer = serializer;

            var expectedPayload = serializer.Serialize(TestData.Customer);

            var actualPayload = JsonWebToken.Decode(TestData.Token, "ABC", verify: false);

            actualPayload.Should().Be(expectedPayload);
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary_With_WebScript_Serializer()
        {
            JsonWebToken.JsonSerializer = new WebScriptJsonSerializer();

            var actualPayload = JsonWebToken.DecodeToObject(TestData.Token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(TestData.DictionaryPayload, options => options.IncludingAllRuntimeProperties());
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Dictionary_With_ServiceStack_Serializer()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();

            var actualPayload = JsonWebToken.DecodeToObject(TestData.Token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(TestData.DictionaryPayload, options => options.IncludingAllRuntimeProperties());
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type_With_WebScript_Serializer()
        {
            JsonWebToken.JsonSerializer = new WebScriptJsonSerializer();

            var actualPayload = JsonWebToken.DecodeToObject<Customer>(TestData.Token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(TestData.Customer);
        }

        [Fact]
        public void DecodeToObject_Should_Decode_Token_To_Generic_Type_With_ServiceStack_Serializer()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();

            var actualPayload = JsonWebToken.DecodeToObject<Customer>(TestData.Token, "ABC", verify: false);

            actualPayload.ShouldBeEquivalentTo(TestData.Customer);
        }


    }
}
