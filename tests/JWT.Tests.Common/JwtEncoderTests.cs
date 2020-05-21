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
            var toEncode = TestData.Customer;
            const string expected = TestData.Token;

            var algorithm = new HMACSHA256Algorithm();
            var urlEncoder = new JwtBase64UrlEncoder();
            var serializer = new JsonNetSerializer();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var actual = encoder.Encode(toEncode, key);

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
            var toEncode = TestData.Customer;
            const string expected = TestData.TokenWithExtraHeaders;

            var algorithm = new HMACSHA256Algorithm();
            var urlEncoder = new JwtBase64UrlEncoder();
            var serializer = new JsonNetSerializer();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var actual = encoder.Encode(extraHeaders, toEncode, key);

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
            var toEncode = TestData.Customer;
            const string expected = TestData.TokenWithCustomTypeHeader;

            var algorithm = new HMACSHA256Algorithm();
            var urlEncoder = new JwtBase64UrlEncoder();
            var serializer = new JsonNetSerializer();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var actual = encoder.Encode(extraHeaders, toEncode, key);

            actual.Should()
                  .Be(expected, "because the same data encoded with the same key must result in the same token");
        }
    }
}
