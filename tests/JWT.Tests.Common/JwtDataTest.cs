using System.Collections.Generic;
using JWT.Builder;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtDataTest
    {
        [Fact]
        public void JwtData_With_Ctor_Params()
        {
            var headers = new Dictionary<string, object>
            {
                { "test", "header" }
            };

            var payload = new Dictionary<string, object>
            {
                { "test", "payload" }
            };

            var jwtData = new JwtData(headers, payload);

            Assert.Equal(jwtData.Header["test"], "header");
            Assert.Equal(jwtData.Payload["test"], "payload");

            jwtData.Payload.Add("payload01", "payload02");
            Assert.Equal(jwtData.Payload["payload01"], "payload02");
        }
    }
}