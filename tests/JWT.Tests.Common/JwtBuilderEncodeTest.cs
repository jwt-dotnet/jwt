using System;
using JWT.Algorithms;
using JWT.JwtBuilder;
using JWT.JwtBuilder.Enums;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtBuilderEncodeTest
    {
        [Fact]
        public void CreateToken()
        {
            var token = new Builder()
                .SetAlgorithm(new HMACSHA256Algorithm())
                .SetSecret("gsdhjfkhdfjklhjklgfsdhgfbsdgfvsdvfghjdjfgb")
                .Build();
            Assert.True(token.Length > 0 && token.Split('.').Length == 3);
        }

        [Fact]
        public void CreateTokenWithPayload()
        {
            var testtime = DateTime.UtcNow.AddHours(5).ToString();
            var token = new Builder()
                .SetAlgorithm(new HMACSHA256Algorithm())
                .SetSecret("gsdhjfkhdfjklhjklgfsdhgfbsdgfvsdvfghjdjfgb")
                .AddClaim(PublicClaimsNames.ExpirationTime, testtime)
                .Build();
            Assert.True(token.Length > 0 && token.Split('.').Length == 3);
            var decodedToken = System.Text.Encoding.UTF8.GetString(new JwtBase64UrlEncoder().Decode(token.Split('.')[1]));
            Assert.True(decodedToken.Contains("exp") && decodedToken.Contains(testtime));
        }

        [Fact]
        public void TryToCreateTokenWithoutInformaiton()
        {
            string token = null;
            Assert.Throws<Exception>(() =>
            {
                token = new Builder().Build();
            });
            Assert.True(token == null);
        }

        [Fact]
        public void TryToCreateTokenOnlyWithAlgorithm()
        {
            Assert.Throws<Exception>(() => new Builder().SetAlgorithm(new HMACSHA256Algorithm()).Build());
        }

        [Fact]
        public void TryToCreateATokenOnlyWithSecret()
        {
            Assert.Throws<Exception>(() => new Builder().SetSecret("fjhsdghflghlk").Build());
        }
    }
}