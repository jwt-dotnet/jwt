using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class RS256AlgorithmTests
    {
        private static readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_PublicKey_Is_Null()
        {
            var privateKey = _fixture.Create<RSACryptoServiceProvider>();

            Action action =
                () => new RS256Algorithm(null, privateKey);

            action.Should()
                  .Throw<ArgumentNullException>("because asymmetric algorithm cannot be constructed without public key");
        }

        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_PrivateKey_Is_Null()
        {
            var publicKey = _fixture.Create<RSACryptoServiceProvider>();

            Action action =
                () => new RS256Algorithm(publicKey, null);

            action.Should()
                  .Throw<ArgumentNullException>("because asymmetric algorithm cannot be constructed without private key");
        }

        [TestMethod]
        public void Sign_Should_Throw_Exception_When_PrivateKey_Is_Null()
        {
            var publicKey = _fixture.Create<RSACryptoServiceProvider>();
            var alg = new RS256Algorithm(publicKey);

            var bytesToSign = Array.Empty<byte>();

            Action action =
                () => alg.Sign(null, bytesToSign);

            action.Should()
                  .Throw<InvalidOperationException>("because asymmetric algorithm cannot sign data without private key");
        }

        [DataTestMethod]
        [DataRow(TestData.ServerRsaPublicKey1)]
        public void Ctor_Should_Not_Throw_Exception_When_Certificate_Has_No_PrivateKey(string publicKey)
        {
            var bytes = Encoding.ASCII.GetBytes(publicKey);
            var certificate = new X509Certificate2(bytes);

            var algorithm = new RS256Algorithm(certificate);

            algorithm.Should()
                     .NotBeNull();
        }
    }
}