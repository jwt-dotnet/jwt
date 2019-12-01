using System.Collections.Generic;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using JWT.Tests.Common.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Common
{
    [TestClass]
    public class JwtEncoderTests
    {
        [TestMethod]
        public void Encode_Should_Encode_To_Token()
        {
            const string key = "ABC";
            var toEncode = TestData.Customer;
            const string token = TestData.Token;

            var algorithm = new HMACSHA256Algorithm();
            var urlEncoder = new JwtBase64UrlEncoder();
            var serializer = new JsonNetSerializer();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var actual = encoder.Encode(toEncode, key);

            actual.Should()
                  .Be(token, "because the same data encoded with the same key must result in the same token");
        }

        [TestMethod]
        public void Encode_Should_Encode_To_Token_With_Extra_Headers()
        {
            var extraHeaders = new Dictionary<string, object>
            {
                { "foo", "bar" }
            };
            const string key = "ABC";
            var toEncode = TestData.Customer;
            const string token = TestData.ExtraHeadersToken;

            var algorithm = new HMACSHA256Algorithm();
            var urlEncoder = new JwtBase64UrlEncoder();
            var serializer = new JsonNetSerializer();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var actual = encoder.Encode(extraHeaders, toEncode, key);

            actual.Should()
                  .Be(token, "because the same data encoded with the same key must result in the same token");
        }
    }
}
