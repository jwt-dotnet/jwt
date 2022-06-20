using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class RSAlgorithmTests
    {
        [DynamicData(nameof(GetFactoryWithPublicPrivateKey), DynamicDataSourceType.Method)]
        [DataTestMethod]
        public void Ctor_Should_Throw_Exception_When_PublicKey_Is_Null(Func<RSA, RSA, RSAlgorithm> algFactory)
        {
            var privateKey = new RSACryptoServiceProvider();

            Action action = () => algFactory(null, privateKey);

            action.Should()
                  .Throw<ArgumentNullException>("because asymmetric algorithm cannot be constructed without public key");
        }

        [DynamicData(nameof(GetFactoryWithPublicPrivateKey), DynamicDataSourceType.Method)]
        [DataTestMethod]
        public void Ctor_Should_Throw_Exception_When_PrivateKey_Is_Null(Func<RSA, RSA, RSAlgorithm> algFactory)
        {
            var publicKey = new RSACryptoServiceProvider();

            Action action = () => algFactory(publicKey, null);

            action.Should()
                  .Throw<ArgumentNullException>("because asymmetric algorithm cannot be constructed without private key");
        }

        [DynamicData(nameof(GetFactoryWithPublicKey), DynamicDataSourceType.Method)]
        [DataTestMethod]
        public void Sign_Should_Throw_Exception_When_PrivateKey_Is_Null(Func<RSA, RSAlgorithm> algFactory)
        {
            var publicKey = new RSACryptoServiceProvider();
            var alg = algFactory(publicKey);

            var bytesToSign = Array.Empty<byte>();

            Action action = () => alg.Sign(null, bytesToSign);

            action.Should()
                  .Throw<InvalidOperationException>("because asymmetric algorithm cannot sign data without private key");
        }

        [DynamicData(nameof(GetFactoryWithCert), DynamicDataSourceType.Method)]
        [DataTestMethod]
        public void Ctor_Should_Not_Throw_Exception_When_Certificate_Has_No_PrivateKey(Func<X509Certificate2, RSAlgorithm> algFactory)
        {
            var cert = TestData.CertificateWithPublicKey;

            var alg = algFactory(cert);

            alg.Should()
               .NotBeNull();
        }

        private static IEnumerable<object[]> GetFactoryWithPublicKey()
        {
            yield return new object[] { new Func<RSA, RSAlgorithm>(publicKey => new RS256Algorithm(publicKey)) };
            yield return new object[] { new Func<RSA, RSAlgorithm>(publicKey => new RS384Algorithm(publicKey)) };
            yield return new object[] { new Func<RSA, RSAlgorithm>(publicKey => new RS512Algorithm(publicKey)) };
            yield return new object[] { new Func<RSA, RSAlgorithm>(publicKey => new RS1024Algorithm(publicKey)) };
        }

        private static IEnumerable<object[]> GetFactoryWithPublicPrivateKey()
        {
            yield return new object[] { new Func<RSA, RSA, RSAlgorithm>((publicKey, privateKey) => new RS256Algorithm(publicKey, privateKey)) };
            yield return new object[] { new Func<RSA, RSA, RSAlgorithm>((publicKey, privateKey) => new RS384Algorithm(publicKey, privateKey)) };
            yield return new object[] { new Func<RSA, RSA, RSAlgorithm>((publicKey, privateKey) => new RS512Algorithm(publicKey, privateKey)) };
            yield return new object[] { new Func<RSA, RSA, RSAlgorithm>((publicKey, privateKey) => new RS1024Algorithm(publicKey, privateKey)) };
        }

        private static IEnumerable<object[]> GetFactoryWithCert()
        {
            yield return new object[] { new Func<X509Certificate2, RSAlgorithm>(cert => new RS256Algorithm(cert)) };
            yield return new object[] { new Func<X509Certificate2, RSAlgorithm>(cert => new RS384Algorithm(cert)) };
            yield return new object[] { new Func<X509Certificate2, RSAlgorithm>(cert => new RS512Algorithm(cert)) };
            yield return new object[] { new Func<X509Certificate2, RSAlgorithm>(cert => new RS1024Algorithm(cert)) };
        }
    }
}
