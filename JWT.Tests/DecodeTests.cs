using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using FluentAssertions;

namespace JWT.Tests
{
    [TestClass]
    
    public class DecodeTests
    {
        JavaScriptSerializer jsonSerializer = new JavaScriptSerializer();
        string token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";
        Customer customer = new Customer() { FirstName = "Bob", Age = 37 };

        [TestMethod]
        public void Should_Decode_Token_To_Json_Encoded_String()
        {
            var expected_payload = jsonSerializer.Serialize(customer);

            string decoded_payload = JWT.JsonWebToken.Decode(token, "ABC", false);

            Assert.AreEqual(expected_payload, decoded_payload);
        }

        [TestMethod]
        public void Should_Decode_Token_To_Dictionary()
        {
            Dictionary<string, object> expected_payload = new Dictionary<string, object>() { 
                { "FirstName", "Bob" },
                { "Age", 37 }
            };

            object decoded_payload = JWT.JsonWebToken.DecodeToObject(token, "ABC", false);

            decoded_payload.ShouldBeEquivalentTo(expected_payload, options=>options.IncludingAllRuntimeProperties());
        }

        [TestMethod]
        public void Should_Decode_Token_To_Generic_Type()
        {
            Customer expected_payload = customer;

            Customer decoded_payload = JWT.JsonWebToken.DecodeToObject<Customer>(token, "ABC", false);

            decoded_payload.ShouldBeEquivalentTo(expected_payload);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Should_Throw_On_Malformed_Token() {
            string malformedtoken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";

            Customer decoded_payload = JWT.JsonWebToken.DecodeToObject<Customer>(malformedtoken, "ABC", false);
        }

        [TestMethod]
        [ExpectedException(typeof(SignatureVerificationException))]
        public void Should_Throw_On_Invalid_Key()
        {
            string invalidkey = "XYZ";

            Customer decoded_payload = JWT.JsonWebToken.DecodeToObject<Customer>(token, invalidkey, true);
        }

        [TestMethod]
        [ExpectedException(typeof(SignatureVerificationException))]
        public void Should_Throw_On_Invalid_Expiration_Claim()
        {
            var invalidexptoken = JWT.JsonWebToken.Encode(new { exp = "asdsad" }, "ABC", JwtHashAlgorithm.HS256);

            Customer decoded_payload = JWT.JsonWebToken.DecodeToObject<Customer>(invalidexptoken, "ABC", true);
        }

        [TestMethod]
        [ExpectedException(typeof(SignatureVerificationException))]
        public void Should_Throw_On_Expired_Token()
        {
            var anHourAgoUtc = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0));
            Int32 unixTimestamp = (Int32)(anHourAgoUtc.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

            var invalidexptoken = JWT.JsonWebToken.Encode(new { exp=unixTimestamp }, "ABC", JwtHashAlgorithm.HS256);

            Customer decoded_payload = JWT.JsonWebToken.DecodeToObject<Customer>(invalidexptoken, "ABC", true);
        }
    }

    public class Customer {
        public string FirstName {get;set;}
        public int Age {get;set;}
    }
}
