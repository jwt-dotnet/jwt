using System.Collections.Generic;
using AutoFixture;
using FluentAssertions;
using JWT.Builder;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtDataTest
    {
        private readonly Fixture _fixture = new Fixture();

        [Fact]
        public void JwtData_With_Ctor_Params()
        {
            var headers = _fixture.Create<Dictionary<string, object>>();
            var payload = _fixture.Create<Dictionary<string, object>>();

            var jwtData = new JwtData(headers, payload);

            jwtData.Header.Should()
                .Contain(headers, "because the DTO's header must match the one provided");

            jwtData.Payload.Should()
                .Contain(payload, "because the DTO's payload must match the one provided");
        }
    }
}