using System;
using System.Collections.Generic;
using System.Text;
using JWT.Algorithms;
using JWT.Builder.Models;
using JWT.Serializers;
using JWT.Tests.Common;
using Xunit;


namespace JWT.Tests
{
    public class JWDataTests
    {
        [Fact]
        public void CanCreateANewJWTDataWithParams()
        {
            var headers = new Dictionary<string, string>();
            headers.Add("test", "test");
            var payload = new Dictionary<string, object>();
            payload.Add("test", "payload");
            var jwtData = new JWTData(headers, payload);
            Assert.True(jwtData.Header["test"] == "test");
            Assert.True(jwtData.PayLoad["test"].ToString() == "payload");
            jwtData.PayLoad.Add("payload01", "payload02");
            Assert.True(jwtData.PayLoad["payload01"].ToString() == "payload02");
        }
    }
}
