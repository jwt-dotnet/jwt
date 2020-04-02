using System.Collections.Generic;
using AutoFixture;
using FluentAssertions;
using JWT.Builder;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class JwtDataTests
    {
        private static readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public void JwtData_With_Ctor_Params()
        {
            var headers = _fixture.Create<Dictionary<string, object>>();
            var payload = _fixture.Create<Dictionary<string, object>>();

            var jwtData = new JwtData(headers, payload);

            jwtData.Header
                   .Should()
                   .Contain(headers, "because header must match the one provided");

            jwtData.Payload
                   .Should()
                   .Contain(payload, "because payload must match the one provided");
        }
    }
}