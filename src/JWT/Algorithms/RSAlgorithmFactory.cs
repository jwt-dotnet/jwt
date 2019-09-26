using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <inheritdoc />
    public sealed class RSAlgorithmFactory : HMACSHAAlgorithmFactory
    {
        private readonly Func<X509Certificate2> _certFactory;
        private readonly Func<RS256Algorithm> _createAlgorithmMethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="RSAlgorithmFactory"/> class
        /// </summary>
        /// <param name="certFactory">Func that returns <see cref="X509Certificate2" /> which will be used to instantiate <see cref="RS256Algorithm" /></param>
        public RSAlgorithmFactory(Func<X509Certificate2> certFactory)
        {
            _certFactory = certFactory;
            _createAlgorithmMethod = CreateWithCertificate;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RSAlgorithmFactory"/> class
        /// </summary>
        /// <param name="publicKey">The RSA service provider which will be used to instantiate <see cref="RS256Algorithm" /></param>
        public RSAlgorithmFactory(RSACryptoServiceProvider publicKey) =>
            _createAlgorithmMethod = () => new RS256Algorithm(publicKey);
            

        /// <inheritdoc />
        public override IJwtAlgorithm Create(JwtHashAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case JwtHashAlgorithm.RS256:
                    {
                        return _createAlgorithmMethod();
                    }
                default:
                    throw new NotSupportedException($"For algorithm {Enum.GetName(typeof(JwtHashAlgorithm), algorithm)} please use the appropriate factory by implementing {nameof(IAlgorithmFactory)}");
            }
        }

        private RS256Algorithm CreateWithCertificate()
        {
            var certificate = _certFactory();
#if NETSTANDARD1_3
            return new RS256Algorithm((RSACryptoServiceProvider)certificate.GetRSAPublicKey(), certificate.GetRSAPrivateKey());
#else
            return new RS256Algorithm((RSACryptoServiceProvider)certificate.PublicKey.Key, (RSA)certificate.PrivateKey);
#endif
        }
    }
}