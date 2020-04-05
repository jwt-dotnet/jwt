using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <inheritdoc />
    public sealed class RSAlgorithmFactory : HMACSHAAlgorithmFactory
    {
        private readonly Func<RS256Algorithm> _algFactory;

        /// <summary>
        /// Creates an instance of the <see cref="RSAlgorithmFactory" /> class using the provided <see cref="X509Certificate2" />.
        /// </summary>
        /// <param name="certFactory">Func that returns <see cref="X509Certificate2" /> which will be used to instantiate <see cref="RS256Algorithm" /></param>
        public RSAlgorithmFactory(Func<X509Certificate2> certFactory) =>
            _algFactory = () => new RS256Algorithm(certFactory());

        /// <summary>
        /// Creates an instance of <see cref="RSAlgorithmFactory"/> using the provided public key only.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        public RSAlgorithmFactory(RSA publicKey) =>
            _algFactory = () => new RS256Algorithm(publicKey);

        /// <summary>
        /// Creates an instance of <see cref="RSAlgorithmFactory"/> using the provided pair of public and private keys.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <param name="privateKey">The private key for signing the data.</param>
        public RSAlgorithmFactory(RSA publicKey, RSA privateKey) =>
            _algFactory = () => new RS256Algorithm(publicKey, privateKey);

        protected override IJwtAlgorithm Create(JwtAlgorithmName algorithm)
        {
            switch (algorithm)
            {
                case JwtAlgorithmName.RS256:
                    return _algFactory();
                default:
                    throw new NotSupportedException($"For algorithm {Enum.GetName(typeof(JwtAlgorithmName), algorithm)} please use the appropriate factory by implementing {nameof(IAlgorithmFactory)}");
            }
        }
    }
}