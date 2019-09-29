using System;
using System.Security.Cryptography;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using Xunit;

namespace JWT.Tests.Common
{
    public class RS256AlgorithmTest
    {
        private readonly Fixture _fixture = new Fixture();

        [Fact]
        public void Sign_Should_Throw_Exception_When_PrivateKey_Is_Null()
        {
            var publicKey = _fixture.Create<RSA>();
            var alg = new RS256Algorithm(publicKey, null);

            var bytesToSign = Array.Empty<byte>();

            Action signWithoutPrivateKey =
                () => alg.Sign(null, bytesToSign);

            signWithoutPrivateKey.Should()
                                 .Throw<InvalidOperationException>("because asymmetric algorithm cannot sign data without a private key");
        }
    }
}
