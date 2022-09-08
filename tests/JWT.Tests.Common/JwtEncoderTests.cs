using System.Collections.Generic;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class JwtEncoderTests
    {
        [TestMethod]
        public void Encode_Should_Encode_To_Token()
        {
            const string key = TestData.Secret;
            var customer = TestData.Customer;
            const string expected = TestData.Token;

            var algorithm = new HMACSHA256Algorithm();
            var urlEncoder = new JwtBase64UrlEncoder();
            var serializer = CreateSerializer();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var actual = encoder.Encode(customer, key);

            actual.Should()
                  .Be(expected, "because the same data encoded with the same key must result in the same token");
        }

        [TestMethod]
        public void Encode_Should_Encode_To_Token_With_Extra_Headers()
        {
            var extraHeaders = new Dictionary<string, object>
            {
                { "foo", "bar" }
            };
            const string key = TestData.Secret;
            var customer = TestData.Customer;
            const string expected = TestData.TokenWithExtraHeaders;

            var algorithm = new HMACSHA256Algorithm();
            var urlEncoder = new JwtBase64UrlEncoder();
            var serializer = CreateSerializer();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var actual = encoder.Encode(extraHeaders, customer, key);

            actual.Should()
                  .Be(expected, "because the same data encoded with the same key must result in the same token");
        }

        [TestMethod]
        public void Encode_Should_Encode_To_Token_With_Custom_Type_Headers()
        {
            var extraHeaders = new Dictionary<string, object>
            {
                { "typ", "foo" }
            };
            const string key = TestData.Secret;
            var customer = TestData.Customer;
            const string expected = TestData.TokenWithCustomTypeHeader;

            var algorithm = new HMACSHA256Algorithm();
            var urlEncoder = new JwtBase64UrlEncoder();
            var serializer = CreateSerializer();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var actual = encoder.Encode(extraHeaders, customer, key);

            actual.Should()
                  .Be(expected, "because the same data encoded with the same key must result in the same token");
        }

        [TestMethod]
        public void Encode_With_NoAlgorithm_Should_Encode_To_Token()
        {
            const string key = TestData.Secret;
            var customer = TestData.Customer;
            const string expected = TestData.TokenWithoutSignature;

            var algorithm = new NoneAlgorithm();
            var urlEncoder = new JwtBase64UrlEncoder();
            var serializer = CreateSerializer();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var actual = encoder.Encode(customer, key);

            actual.Should()
                  .Be(expected, "because the same data encoded with the same key must result in the same token");
        }
        
        [TestMethod]
        public void Encode_Should_Encode_To_Token_Using_Json_Net()
        {
            const string key = TestData.Secret;
            var customer = TestData.Customer;
            const string expected = TestData.Token;

            var algorithm = new HMACSHA256Algorithm();
            var urlEncoder = new JwtBase64UrlEncoder();
            var serializer = new JsonNetSerializer();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var actual = encoder.Encode(customer, key);

            actual.Should()
                  .Be(expected, "because the same data encoded with the same key must result in the same token");
        }
        
        private static IJsonSerializer CreateSerializer() => 
            new DefaultJsonSerializerFactory().Create();
        
        [TestMethod]
        public void Encode_With_NoAlgorithm_Should_Encode_To_Token_Not_Needing_Secret()
        {
            var customer = TestData.Customer;
            const string expected = TestData.TokenWithoutSignature;

            var algorithm = new NoneAlgorithm();
            var urlEncoder = new JwtBase64UrlEncoder();
            var serializer = CreateSerializer();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var actual = encoder.Encode(customer, (string)null);

            actual.Should()
                  .Be(expected, "because the same data encoded with the same key must result in the same token");
        }
    }
}
