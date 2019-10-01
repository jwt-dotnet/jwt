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
            _algFactory = CreateWithCertificate;

        /// <summary>
        /// Creates an instance of <see cref="RSAlgorithmFactory"/> using the provided public key only.
        /// </summary>
        /// <remarks>
        /// An instance of <see cref="RSAlgorithmFactory" /> created using this constructor can only be used for verifying the data, not for signing it.
        /// </remarks>
        /// <param name="publicKey">The public key for verifying the data.</param>
        public RSAlgorithmFactory(RSA publicKey) =>
            _algFactory = () => new RS256Algorithm(publicKey);

        /// <summary>
        /// Creates an instance of <see cref="RSAlgorithmFactory"/> using the provided pair of public and private keys.
        /// </summary>
        /// <remarks>
        /// An instance of <see cref="RSAlgorithmFactory" /> created using this constructor can only be used for verifying the data, not for signing it.
        /// </remarks>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <param name="privateKey">The private key for signing the data.</param>
        public RSAlgorithmFactory(RSA publicKey, RSA privateKey) =>
            _algFactory = () => new RS256Algorithm(publicKey, privateKey);

        /// <inheritdoc />
        public override IJwtAlgorithm Create(JwtHashAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case JwtHashAlgorithm.RS256:
                    return _createAlgorithmMethod();
                default:
                    throw new NotSupportedException($"For algorithm {Enum.GetName(typeof(JwtHashAlgorithm), algorithm)} please use the appropriate factory by implementing {nameof(IAlgorithmFactory)}");
            }
        }

        private RS256Algorithm CreateWithCertificate()
        {
            var certificate = _certFactory();
            return new RS256Algorithm(certificate);
        }
    }
}
