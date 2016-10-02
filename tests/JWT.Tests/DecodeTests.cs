using System;
using System.Collections.Generic;

#if !NETCOREAPP1_0
using System.Web.Script.Serialization;
#endif

using FluentAssertions;

using Xunit;

namespace JWT.Tests
{
    public class DecodeTests
    {
        private static readonly Customer _customer = new Customer { FirstName = "Bob", Age = 37 };

        private const string _token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";
        private const string _malformedtoken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";

        private static readonly IDictionary<string, object> _dictionaryPayload = new Dictionary<string, object>
        {
            { "FirstName", "Bob" },
            { "Age", 37 }
        };

#if !NETCOREAPP1_0
        [Fact]
        public void Should_Decode_Token_To_Json_Encoded_String()
        {
            var jsonSerializer = new JavaScriptSerializer();
            var expectedPayload = jsonSerializer.Serialize(_customer);

            string decodedPayload = JsonWebToken.Decode(_token, "ABC", false);

            Assert.Equal(expectedPayload, decodedPayload);
        }
#endif


#if NETCOREAPP1_0
        [Fact]
        public void Should_Decode_Token_To_Json_Encoded_String()
        {
            var jsonSerializer = new NewtonsoftJsonSerializer();
            var expectedPayload = jsonSerializer.Serialize(_customer);

            string decodedPayload = JsonWebToken.Decode(_token, "ABC", false);

            Assert.Equal(expectedPayload, decodedPayload);
        }
#endif

        [Fact]
        public void Should_Decode_Token_To_Dictionary()
        {
            object decodedPayload = JsonWebToken.DecodeToObject(_token, "ABC", false);

            decodedPayload.ShouldBeEquivalentTo(_dictionaryPayload, options => options.IncludingAllRuntimeProperties());
        }

#if !NETCOREAPP1_0
        [Fact]
        public void Should_Decode_Token_To_Dictionary_With_ServiceStack()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();

            object decodedPayload = JsonWebToken.DecodeToObject(_token, "ABC", false);

            decodedPayload.ShouldBeEquivalentTo(_dictionaryPayload, options => options.IncludingAllRuntimeProperties());
        }
#endif

        [Fact]
        public void Should_Decode_Token_To_Dictionary_With_Newtonsoft()
        {
            JsonWebToken.JsonSerializer = new NewtonJsonSerializer();

            object decodedPayload = JsonWebToken.DecodeToObject(_token, "ABC", false);

            decodedPayload.ShouldBeEquivalentTo(_dictionaryPayload, options => options.IncludingAllRuntimeProperties());
        }

        [Fact]
        public void Should_Decode_Token_To_Generic_Type()
        {
            Customer decodedPayload = JsonWebToken.DecodeToObject<Customer>(_token, "ABC", false);

            decodedPayload.ShouldBeEquivalentTo(_customer);
        }

#if !NETCOREAPP1_0
        [Fact]
        public void Should_Decode_Token_To_Generic_Type_With_ServiceStack()
        {
            JsonWebToken.JsonSerializer = new ServiceStackJsonSerializer();

            Customer decodedPayload = JsonWebToken.DecodeToObject<Customer>(_token, "ABC", false);

            decodedPayload.ShouldBeEquivalentTo(_customer);
        }
#endif

        [Fact]
        public void Should_Decode_Token_To_Generic_Type_With_Newtonsoft()
        {
            JsonWebToken.JsonSerializer = new NewtonJsonSerializer();

            Customer decodedPayload = JsonWebToken.DecodeToObject<Customer>(_token, "ABC", false);

            decodedPayload.ShouldBeEquivalentTo(_customer);
        }

        [Fact]
        public void Should_Throw_On_Malformed_Token()
        {
            Assert.Throws<ArgumentException>(() => JsonWebToken.DecodeToObject<Customer>(_malformedtoken, "ABC", false));
        }

        [Fact]
        public void Should_Throw_On_Invalid_Key()
        {
            string invalidkey = "XYZ";

            Assert.Throws<SignatureVerificationException>(() => JsonWebToken.DecodeToObject<Customer>(_token, invalidkey, true));
        }

        [Fact]
        public void Should_Throw_On_Invalid_Expiration_Claim()
        {
            var invalidexptoken = JsonWebToken.Encode(new { exp = "asdsad" }, "ABC", JwtHashAlgorithm.HS256);

            Assert.Throws<SignatureVerificationException>(() => JsonWebToken.DecodeToObject<Customer>(invalidexptoken, "ABC", true));
        }

        [Fact]
        public void Should_Throw_On_Expired_Claim()
        {
            var anHourAgoUtc = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0));
            Int32 unixTimestamp = (Int32)(anHourAgoUtc.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

            var invalidexptoken = JsonWebToken.Encode(new { exp = unixTimestamp }, "ABC", JwtHashAlgorithm.HS256);

            Assert.Throws<TokenExpiredException>(() => JsonWebToken.DecodeToObject<Customer>(invalidexptoken, "ABC", true));
        }
    }

    public class Customer
    {
        public string FirstName { get; set; }

        public int Age { get; set; }
    }
}
