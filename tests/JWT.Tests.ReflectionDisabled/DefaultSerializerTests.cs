using System;
using System.Collections.Generic;
using System.Text.Json;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Serializers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.ReflectionDisabled
{
    [TestClass]
    public class DefaultSerializerTests
    {
        private const string Secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";

        [ClassInitialize]
        public static void ClassInitialize(TestContext context) =>
            JsonSerializer.IsReflectionEnabledByDefault.Should().BeFalse("the project disables reflection-based serialization");

        [TestMethod]
        public void Serialize_Should_Use_Builtin_Metadata_For_Dictionary_Claims()
        {
            var serializer = new SystemTextSerializer();

            var json = serializer.Serialize(new Dictionary<string, object>
            {
                { "string", "value" },
                { "long", 42L },
                { "bool", true },
                { "date", new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc) },
                { "array", new[] { "a", "b" } },
                { "intList", new List<int> { 1, 2 } },
                { "nested", new Dictionary<string, object> { { "inner", 1 } } }
            });

            json.Should()
                .Be("{\"string\":\"value\",\"long\":42,\"bool\":true,\"date\":\"2020-01-02T03:04:05Z\",\"array\":[\"a\",\"b\"],\"intList\":[1,2],\"nested\":{\"inner\":1}}");
        }

        [TestMethod]
        public void Encode_And_Decode_Should_Round_Trip_Header_And_Claims_With_Default_Serializer()
        {
            var token = JwtBuilder.Create()
                                  .WithAlgorithm(new HMACSHA256Algorithm())
                                  .WithSecret(Secret)
                                  .AddHeader(HeaderName.KeyId, "kid-1")
                                  .AddClaim("name", "value")
                                  .ExpirationTime(DateTime.UtcNow.AddHours(1))
                                  .Encode();

            var header = JwtBuilder.Create()
                                   .DecodeHeader<JwtHeader>(token);
            var claims = JwtBuilder.Create()
                                   .WithAlgorithm(new HMACSHA256Algorithm())
                                   .WithSecret(Secret)
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

            Action action = () => serializer.Serialize(new PayloadWithoutMetadata());

            action.Should()
                  .Throw<NotSupportedException>()
                  .WithMessage("*PayloadWithoutMetadata*");
        }

        public sealed class PayloadWithoutMetadata
        {
        }
    }
}
