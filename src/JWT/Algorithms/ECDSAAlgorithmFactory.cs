using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <inheritdoc />
    public sealed class ECDSAAlgorithmFactory : HMACSHAAlgorithmFactory
    {
#if NETSTANDARD2_0 || NET5_0
        private readonly Func<X509Certificate2> _certFactory;

        private readonly ECDsa _publicKey;
        private readonly ECDsa _privateKey;

        /// <summary>
        /// Creates an instance of the <see cref="ECDSAAlgorithmFactory" /> class using the provided <see cref="X509Certificate2" />.
        /// </summary>
        /// <param name="certFactory">Func that returns <see cref="X509Certificate2" /> which will be used to instantiate <see cref="RS256Algorithm" /></param>
        public ECDSAAlgorithmFactory(Func<X509Certificate2> certFactory)
        {
            _certFactory = certFactory ?? throw new ArgumentNullException(nameof(certFactory));
        }

        /// <summary>
        /// Creates an instance of <see cref="ECDSAAlgorithmFactory"/> using the provided public key only.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        public ECDSAAlgorithmFactory(ECDsa publicKey)
        {
            _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        }

        /// <summary>
        /// Creates an instance of <see cref="ECDSAAlgorithmFactory"/> using the provided pair of public and private keys.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <param name="privateKey">The private key for signing the data.</param>
        public ECDSAAlgorithmFactory(ECDsa publicKey, ECDsa privateKey)
            : this(publicKey)
        {
            _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        }
#endif

        protected override IJwtAlgorithm Create(JwtAlgorithmName algorithm)
        {
#if NETSTANDARD2_0 || NET5_0
            switch (algorithm)
            {
                case JwtAlgorithmName.ES256:
                    return CreateES256Algorithm();
                case JwtAlgorithmName.ES384:
                    return CreateES384Algorithm();
                case JwtAlgorithmName.ES512:
                    return CreateES512Algorithm();
                case JwtAlgorithmName.HS256:
                case JwtAlgorithmName.HS384:
                case JwtAlgorithmName.HS512:
                    throw new NotSupportedException($"For algorithm {algorithm} please use an instance of {nameof(HMACSHAAlgorithmFactory)}");
                case JwtAlgorithmName.RS256:
                case JwtAlgorithmName.RS384:
                case JwtAlgorithmName.RS512:
                    throw new NotSupportedException($"For algorithm {algorithm} please use an instance of {nameof(RSAlgorithmFactory)}");
                default:
                    throw new NotSupportedException($"For algorithm {Enum.GetName(typeof(JwtAlgorithmName), algorithm)} please use the appropriate factory by implementing {nameof(IAlgorithmFactory)}");
            }
#else
            throw new NotImplementedException("ECDSA algorithms are only supported when targeting .NET Standard 2.0");
#endif
        }

#if NETSTANDARD2_0 || NET5_0
        private IJwtAlgorithm CreateES256Algorithm()
        {
            if (_certFactory is object)
            {
                return new ES256Algorithm(_certFactory());
            }
            if (_publicKey is object && _privateKey is object)
            {
                return new ES256Algorithm(_publicKey, _privateKey);
            }
            if (_publicKey is object)
            {
                return new ES256Algorithm(_publicKey);
            }

            throw new InvalidOperationException("Can't create a new algorithm without a certificate factory, private key or public key");
        }

        private IJwtAlgorithm CreateES384Algorithm()
        {
            if (_certFactory is object)
            {
                return new ES384Algorithm(_certFactory());
            }
            if (_publicKey is object && _privateKey is object)
            {
                return new ES384Algorithm(_publicKey, _privateKey);
            }
            if (_publicKey is object)
            {
                return new ES384Algorithm(_publicKey);
            }

            throw new InvalidOperationException("Can't create a new algorithm without a certificate factory, private key or public key");
        }

        private IJwtAlgorithm CreateES512Algorithm()
        {
            if (_certFactory is object)
            {
                return new ES512Algorithm(_certFactory());
            }
            if (_publicKey is object && _privateKey is object)
            {
                return new ES512Algorithm(_publicKey, _privateKey);
            }
            if (_publicKey is object)
            {
                return new ES512Algorithm(_publicKey);
            }

            throw new InvalidOperationException("Can't create a new algorithm without a certificate factory, private key or public key");
        }
#endif
    }
}
