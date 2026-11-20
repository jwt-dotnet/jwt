#if NET8_0_OR_GREATER
using System;
using System.Collections.Generic;
using System.Text.Json;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Exceptions;
using JWT.Serializers;
using JWT.Tests.Models;
using JWT.Tests.Stubs;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Serializers
{
    [TestClass]
    public class SystemTextSerializerTests
    {
        private static readonly byte[] _key = System.Text.Encoding.UTF8.GetBytes(TestData.Secret);

        // Same resolver the default constructor uses when reflection-based serialization is disabled (trimmed and Native AOT apps)
        private static SystemTextSerializer CreateReflectionFreeSerializer() =>
            new SystemTextSerializer(new JsonSerializerOptions { TypeInfoResolver = JwtNetJsonSerializerContext.Default });

        [TestMethod]
        public void Ctor_Should_Throw_When_Options_Is_Null()
        {
            Action action = () => new SystemTextSerializer(null);

            action.Should()
                  .Throw<ArgumentNullException>();
        }

        [TestMethod]
        public void Ctor_Should_Not_Modify_Supplied_Options()
        {
            var options = new JsonSerializerOptions { TypeInfoResolver = CustomerJsonSerializerContext.Default };

            _ = new SystemTextSerializer(options);

            options.IsReadOnly.Should().BeFalse();
            options.Converters.Should().BeEmpty();
            options.TypeInfoResolver.Should().BeSameAs(CustomerJsonSerializerContext.Default);
        }

        [TestMethod]
        public void Encode_And_Decode_Should_Use_Supplied_Context_For_Custom_Type()
        {
            var serializer = new SystemTextSerializer(CustomerJsonSerializerContext.Default.Options);
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(new HMACSHA256Algorithm(), serializer, urlEncoder);
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var decoder = new JwtDecoder(serializer, validator, urlEncoder, new HMACSHA256Algorithm());

            var token = encoder.Encode(TestData.Customer, _key);
            var customer = decoder.DecodeToObject<Customer>(token, _key);

            customer.Should()
                    .BeEquivalentTo(TestData.Customer);
        }

        [TestMethod]
        public void Deserialize_Should_Throw_When_Metadata_For_Type_Is_Missing()
        {
            var serializer = CreateReflectionFreeSerializer();

            Action action = () => serializer.Deserialize(typeof(Customer), "{}");

            action.Should()
                  .Throw<NotSupportedException>()
                  .WithMessage("*Customer*");
        }

        [TestMethod]
        public void Serialize_Should_Apply_Root_Object_Converter_From_Supplied_Options()
        {
            var serializer = new SystemTextSerializer(new JsonSerializerOptions { Converters = { new FixedOutputObjectConverter() } });

            var json = serializer.Serialize(new Dictionary<string, object> { { "claim", "value" } });

            json.Should()
                .Be("\"fixed\"");
        }

        [TestMethod]
        public void Serialize_Without_Reflection_Should_Produce_Same_Json_As_Default()
        {
            var payload = TestData.PayloadWithCommonClaimTypes;

            var expected = new SystemTextSerializer().Serialize(payload);
            var actual = CreateReflectionFreeSerializer().Serialize(payload);

            actual.Should()
                  .Be(expected);
        }

        [TestMethod]
        public void Encode_And_Decode_Without_Reflection_Should_Support_Common_Claim_Types()
        {
            var serializer = CreateReflectionFreeSerializer();
            var builder = JwtBuilder.Create()
                                    .WithAlgorithm(new HMACSHA256Algorithm())
                                    .WithSecret(TestData.Secret)
                                    .WithJsonSerializer(serializer);

            var token = builder.AddHeader(HeaderName.KeyId, "kid-1")
                               .AddClaims(TestData.PayloadWithCommonClaimTypes)
                               .ExpirationTime(DateTime.UtcNow.AddHours(1))
                               .Encode();

            var header = JwtBuilder.Create()
                                   .WithJsonSerializer(serializer)
                                   .DecodeHeader<JwtHeader>(token);
            header.KeyId.Should().Be("kid-1");
            header.Algorithm.Should().Be("HS256");

            var claims = JwtBuilder.Create()
                                   .WithAlgorithm(new HMACSHA256Algorithm())
                                   .WithSecret(TestData.Secret)
                                   .WithJsonSerializer(serializer)
                                   .MustVerifySignature()
                                   .Decode<Dictionary<string, object>>(token);
            claims["string"].Should().Be("value");
            claims["long"].Should().Be(42m);
            claims["double"].Should().Be(1.5m);
            claims["bool"].Should().Be(true);
            claims["date"].Should().Be(new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc));
            claims["guid"].Should().Be("1f0a3f9e-4b8c-4a63-9b8e-7d4c2b1a0f11");
            claims["array"].Should().BeEquivalentTo(new List<object> { "a", "b" });
            claims["intList"].Should().BeEquivalentTo(new List<object> { 1m, 2m });
            claims["longList"].Should().BeEquivalentTo(new List<object> { 3m });
            claims["doubleList"].Should().BeEquivalentTo(new List<object> { 0.5m });
            claims["boolList"].Should().BeEquivalentTo(new List<object> { true });
            claims["boolArray"].Should().BeEquivalentTo(new List<object> { false });
            claims["nested"].Should().BeEquivalentTo(new Dictionary<string, object> { { "inner", 1m } });
        }

        [TestMethod]
        public void Decode_Without_Reflection_Should_Throw_When_Token_Expired()
        {
            var serializer = CreateReflectionFreeSerializer();

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(new HMACSHA256Algorithm())
                                  .WithSecret(TestData.Secret)
                                  .WithJsonSerializer(serializer)
                                  .ExpirationTime(DateTime.UtcNow.AddHours(-1))
                                  .Encode();

            Action action = () => JwtBuilder.Create()
                                            .WithAlgorithm(new HMACSHA256Algorithm())
                                            .WithSecret(TestData.Secret)
                                            .WithJsonSerializer(serializer)
                                            .MustVerifySignature()
                                            .Decode(token);

            action.Should()
                  .Throw<TokenExpiredException>();
        }
    }
}
#endif
