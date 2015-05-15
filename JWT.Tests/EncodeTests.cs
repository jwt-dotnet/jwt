using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;

namespace JWT.Tests
{
    [TestClass]
    public class EncodeTests
    {
        string token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";
        string extraheaderstoken = "eyJmb28iOiJiYXIiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.slrbXF9VSrlX7LKsV-Umb_zEzWLxQjCfUOjNTbvyr1g";
        Customer customer = new Customer() { FirstName = "Bob", Age = 37 };

        [TestMethod]
        public void Should_Encode_Type()
        {
            string result = JsonWebToken.Encode(customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(token, result);
        }

        [TestMethod]
        public void Should_Encode_Type_With_Extra_Headers()
        {
            var extraheaders = new Dictionary<string, object>() { {"foo", "bar"} };
            
            string result = JsonWebToken.Encode(extraheaders, customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(extraheaderstoken, result);
        }

        [TestMethod]
        public void Should_Encode_Type_With_ServiceStack()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();
            string result = JsonWebToken.Encode(customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(token, result);
        }

        [TestMethod]
        public void Should_Encode_Type_With_ServiceStack_And_Extra_Headers() {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();
            
            var extraheaders = new Dictionary<string, object>() { { "foo", "bar" } };
            string result = JsonWebToken.Encode(extraheaders, customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(extraheaderstoken, result);
        }

        [TestMethod]
        public void Should_Encode_Type_With_Newtonsoft_Serializer() {
            JsonWebToken.JsonSerializer = new NewtonJsonSerializer();
            string result = JsonWebToken.Encode(customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(token, result);
        }

        [TestMethod]
        public void Should_Encode_Type_With_Newtonsoft_Serializer_And_Extra_Headers() {
            JsonWebToken.JsonSerializer = new NewtonJsonSerializer();

            var extraheaders = new Dictionary<string, object>() { { "foo", "bar" } };
            string result = JsonWebToken.Encode(extraheaders, customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(extraheaderstoken, result);
        }
    }
}
