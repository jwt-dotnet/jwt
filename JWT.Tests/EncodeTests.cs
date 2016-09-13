using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class EncodeTests
    {
        private static readonly Customer _customer = new Customer { FirstName = "Bob", Age = 37 };

        private const string _token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";
        private const string _extraheaderstoken = "eyJmb28iOiJiYXIiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.slrbXF9VSrlX7LKsV-Umb_zEzWLxQjCfUOjNTbvyr1g";

        [TestMethod]
        public void Should_Encode_Type()
        {
            string result = JsonWebToken.Encode(_customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(_token, result);
        }

        [TestMethod]
        public void Should_Encode_Type_With_Extra_Headers()
        {
            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };

            string result = JsonWebToken.Encode(extraheaders, _customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(_extraheaderstoken, result);
        }

        [TestMethod]
        public void Should_Encode_Type_With_ServiceStack()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();
            string result = JsonWebToken.Encode(_customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(_token, result);
        }

        [TestMethod]
        public void Should_Encode_Type_With_ServiceStack_And_Extra_Headers()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();

            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };
            string result = JsonWebToken.Encode(extraheaders, _customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(_extraheaderstoken, result);
        }

        [TestMethod]
        public void Should_Encode_Type_With_Newtonsoft_Serializer()
        {
            JsonWebToken.JsonSerializer = new NewtonJsonSerializer();
            string result = JsonWebToken.Encode(_customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(_token, result);
        }

        [TestMethod]
        public void Should_Encode_Type_With_Newtonsoft_Serializer_And_Extra_Headers()
        {
            JsonWebToken.JsonSerializer = new NewtonJsonSerializer();

            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };
            string result = JsonWebToken.Encode(extraheaders, _customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(_extraheaderstoken, result);
        }
    }
}