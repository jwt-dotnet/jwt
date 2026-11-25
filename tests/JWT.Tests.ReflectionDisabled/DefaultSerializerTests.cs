using System;
using System.Collections.Generic;
using System.Text.Json;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.ReflectionDisabled
{
    [TestClass]
    public class DefaultSerializerTests
    {
        [ClassInitialize]
        public static void ClassInitialize(TestContext context) =>
            JsonSerializer.IsReflectionEnabledByDefault.Should().BeFalse("the project disables reflection-based serialization");

        [TestMethod]
        public void Serialize_Should_Use_Builtin_Metadata_For_Dictionary_Claims()
        {
            var serializer = new SystemTextSerializer();

            var json = serializer.Serialize(TestData.PayloadWithCommonClaimTypes);

            json.Should()
                .Be(TestData.PayloadWithCommonClaimTypesJson);
        }

        [TestMethod]
        public void Encode_And_Decode_Should_Round_Trip_Header_And_Claims_With_Default_Serializer()
        {
            var token = JwtBuilder.Create()
                                  .WithAlgorithm(new HMACSHA256Algorithm())
                                  .WithSecret(TestData.Secret)
                                  .AddHeader(HeaderName.KeyId, "kid-1")
                                  .AddClaim("name", "value")
                                  .ExpirationTime(DateTime.UtcNow.AddHours(1))
                                  .Encode();

            var header = JwtBuilder.Create()
                                   .DecodeHeader<JwtHeader>(token);
            var claims = JwtBuilder.Create()
                                   .WithAlgorithm(new HMACSHA256Algorithm())
                                   .WithSecret(TestData.Secret)
                                   .MustVerifySignature()
                                   .Decode<Dictionary<string, object>>(token);

            header.KeyId.Should().Be("kid-1");
            header.Algorithm.Should().Be("HS256");
            claims["name"].Should().Be("value");
        }

        [TestMethod]
        public void Serialize_Should_Throw_NotSupportedException_For_Type_Without_Metadata()
        {
            var serializer = new SystemTextSerializer();

            Action action = () => serializer.Serialize(TestData.Customer);

            action.Should()
                  .Throw<NotSupportedException>()
                  .WithMessage("*Customer*");
        }
    }
}
