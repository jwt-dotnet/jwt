#if !(NET35 || NET40 || NET46)
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class ES256AlgorithmTests
    {
        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_PublicKey_Is_Null()
        {
            var privateKey = ECDsa.Create();

            Action action =
                () => new ES256Algorithm(null, privateKey);

            action.Should()
                  .Throw<ArgumentNullException>("because asymmetric algorithm cannot be constructed without public key");
        }

        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_PrivateKey_Is_Null()
        {
            var publicKey = ECDsa.Create();

            Action action =
                () => new ES256Algorithm(publicKey, null);

            action.Should()
                  .Throw<ArgumentNullException>("because asymmetric algorithm cannot be constructed without private key");
        }

        [TestMethod]
        public void Sign_Should_Throw_Exception_When_PrivateKey_Is_Null()
        {
            var publicKey = ECDsa.Create();
            var alg = new ES256Algorithm(publicKey);

            var bytesToSign = Array.Empty<byte>();

            Action action =
                () => alg.Sign(null, bytesToSign);

            action.Should()
                  .Throw<InvalidOperationException>("because asymmetric algorithm cannot sign data without private key");
        }

        [DataTestMethod]
        [DataRow(TestData.ServerEcdsaPublicKey)]
        public void Ctor_Should_Not_Throw_Exception_When_Certificate_Has_No_PrivateKey(string publicKey)
        {
            var bytes = Encoding.ASCII.GetBytes(publicKey);
            var certificate = new X509Certificate2(bytes);

            var algorithm = new ES256Algorithm(certificate);

            algorithm.Should()
                .NotBeNull();
        }

        [TestMethod]
        public void Name_Should_Be_ES256()
        {
            var publicKey = ECDsa.Create();
            var alg = new ES256Algorithm(publicKey);

            alg.Name.Should()
                    .Be(JwtAlgorithmName.ES256.ToString());
        }

        [TestMethod]
        public void HashAlgorithm_Should_Be_SHA256()
        {
            var publicKey = ECDsa.Create();
            var alg = new ES256Algorithm(publicKey);

            alg.HashAlgorithm.Should()
                             .Be("SHA256");
        }
    }
}

#endif