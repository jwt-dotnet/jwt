using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class JWTFixture
    {
        private static string SECRET = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";

        [TestMethod]
        public void ShouldValidateToken()
        {
            var jwt = JWT.JsonWebToken.Encode(new { foo = "bar" }, Convert.FromBase64String(SECRET), JWT.JwtHashAlgorithm.HS256);
            var payload = JWT.JsonWebToken.DecodeToObject(jwt, Convert.FromBase64String(SECRET)) as Dictionary<string, object>;

            Assert.AreEqual("foo", payload.Keys.First());
            Assert.AreEqual("bar", payload.Values.First());
        }

        [TestMethod]
        public void ShouldThrowIfSignatureFails()
        {
            // validJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgBOo";
            string invalidJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgB1a";
            try
            {
                var payload = JWT.JsonWebToken.DecodeToObject(invalidJwt, Convert.FromBase64String(SECRET)) as Dictionary<string, object>;
            }
            catch (SignatureVerificationException ex)
            {
                Assert.AreEqual("Invalid signature. Expected 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgB1Y= got 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgBOo=", ex.Message);
                return;
            }

            Assert.Fail("Should have thrown exception");
        }

        [TestMethod]
        public void ShouldThrowIfAudienceIsWrong()
        {
            var jwt = JWT.JsonWebToken.Encode(new { foo = "bar", aud = "my:audience" }, Convert.FromBase64String(SECRET), JWT.JwtHashAlgorithm.HS256);

            try
            {
                var payload = JWT.JsonWebToken.DecodeToObject(jwt, Convert.FromBase64String(SECRET), audience: "wrong:audience") as Dictionary<string, object>;
            }
            catch (TokenValidationException ex)
            {
                Assert.AreEqual("Audience mismatch. Expected: 'wrong:audience' and got: 'my:audience'", ex.Message);
                return;
            }

            Assert.Fail("Should have thrown exception");
        }

        [TestMethod]
        public void ShouldThrowIfExpired()
        {
            var jwt = JWT.JsonWebToken.Encode(new { foo = "bar", exp = (DateTime.UtcNow.AddHours(-1).Ticks - 621355968000000000) / 10000000 }, Convert.FromBase64String(SECRET), JWT.JwtHashAlgorithm.HS256);

            try
            {
                var payload = JWT.JsonWebToken.DecodeToObject(jwt, Convert.FromBase64String(SECRET), checkExpiration: true) as Dictionary<string, object>;
            }
            catch (TokenValidationException ex)
            {
                Assert.IsTrue(ex.Message.StartsWith("Token is expired"));
                return;
            }

            Assert.Fail("Should have thrown exception");
        }

        [TestMethod]
        public void ShouldNotCheckExpirationByDefault()
        {
            var jwt = JWT.JsonWebToken.Encode(new { foo = "bar", exp = (DateTime.UtcNow.AddHours(-1).Ticks - 621355968000000000) / 10000000 }, Convert.FromBase64String(SECRET), JWT.JwtHashAlgorithm.HS256);

            var payload = JWT.JsonWebToken.DecodeToObject(jwt, Convert.FromBase64String(SECRET)) as Dictionary<string, object>;

            Assert.AreEqual("bar", payload["foo"]);
        }

        [TestMethod]
        public void ShouldThrowIfIssuerIsWrong()
        {
            var jwt = JWT.JsonWebToken.Encode(new { foo = "bar", iss = "some:issuer" }, Convert.FromBase64String(SECRET), JWT.JwtHashAlgorithm.HS256);

            try
            {
                var payload = JWT.JsonWebToken.DecodeToObject(jwt, Convert.FromBase64String(SECRET), issuer: "wrong:issuer") as Dictionary<string, object>;
            }
            catch (TokenValidationException ex)
            {
                Assert.AreEqual("Token issuer mismatch. Expected: 'wrong:issuer' and got: 'some:issuer'", ex.Message);
                return;
            }

            Assert.Fail("Should have thrown exception");
        }
    }
}
