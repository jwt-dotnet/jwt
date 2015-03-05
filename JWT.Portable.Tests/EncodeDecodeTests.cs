using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class EncodeDecodeTests
    {
        [TestMethod]
        public void CanEncode()
        {
            var payload = new Payload() { Name = "John", Age = 25, Active = true, CreatedAt = DateTime.Parse("1/1/2010") };
            var expectedresult = Simple.SimpleJson.SerializeObject(payload);

            var token = JsonWebToken.Encode(payload, "AC1234567890", JwtHashAlgorithm.HS256);

            string actualresult = JsonWebToken.Decode(token, "AC1234567890");

            Assert.AreEqual(expectedresult, actualresult);
        }

        [TestMethod]
        public void CanDecodeWithoutVerification()
        {
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiSm9obiIsIkFnZSI6MjUsIkFjdGl2ZSI6dHJ1ZSwiQ3JlYXRlZEF0IjoiXC9EYXRlKDEyNjIzMjIwMDAwMDApXC8ifQ.3_9-wSSeqqtY-_VYMD_KaPbM8Z9909a4M7xbWjX7RSg";
            var expectedresult = "{\"Name\":\"John\",\"Age\":25,\"Active\":true,\"CreatedAt\":\"\\/Date(1262322000000)\\/\"}";

            string actualresult = JsonWebToken.Decode(token, "AC1234567890", false);

            Assert.AreEqual(expectedresult, actualresult);
        }

        [TestMethod]
        public void CanDecodeWithVerification()
        {
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiSm9obiIsIkFnZSI6MjUsIkFjdGl2ZSI6dHJ1ZSwiQ3JlYXRlZEF0IjoiXC9EYXRlKDEyNjIzMjIwMDAwMDApXC8ifQ.3_9-wSSeqqtY-_VYMD_KaPbM8Z9909a4M7xbWjX7RSg";
            var expectedresult = "{\"Name\":\"John\",\"Age\":25,\"Active\":true,\"CreatedAt\":\"\\/Date(1262322000000)\\/\"}";

            string actualresult = JsonWebToken.Decode(token, "AC1234567890", true);

            Assert.AreEqual(expectedresult, actualresult);
        }
    }

    public class Payload
    {
        public string Name { get; set; }
        public int Age { get; set; }
        public bool Active { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}



