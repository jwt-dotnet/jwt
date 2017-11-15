using System.Collections.Generic;
using JWT.JwtBuilder.Models;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtDataTest
    {
        [Fact]
        public void CanCreate_With_New_JwtData_With_Params()
        {
            var headers = new Dictionary<string, string>();
            headers.Add("test", "test");

            var payload = new Dictionary<string, object>();
            payload.Add("test", "payload");

            var jwtData = new JwtData();

            Assert.True(jwtData.Header["test"] == "test");
            Assert.True(jwtData.Payload["test"].ToString() == "payload");

            jwtData.Payload.Add("payload01", "payload02");
            Assert.True(jwtData.Payload["payload01"].ToString() == "payload02");
        }
    }
}