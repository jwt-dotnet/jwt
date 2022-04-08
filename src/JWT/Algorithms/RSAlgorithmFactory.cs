using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <inheritdoc />
    public sealed class RSAlgorithmFactory : JwtAlgorithmFactory
    {
        private readonly Func<X509Certificate2> _certFactory;
        private readonly RSA _publicKey;
        private readonly RSA _privateKey;

        /// <summary>
        /// Creates an instance of the <see cref="RSAlgorithmFactory" /> class using the provided <see cref="X509Certificate2" />.
        /// </summary>
        /// <param name="certFactory">Func that returns <see cref="X509Certificate2" /> which will be used to instantiate <see cref="RS256Algorithm" /></param>
        public RSAlgorithmFactory(Func<X509Certificate2> certFactory) =>
            _certFactory = certFactory ?? throw new ArgumentNullException(nameof(certFactory));

        /// <summary>
        /// Creates an instance of <see cref="RSAlgorithmFactory"/> using the provided public key only.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        public RSAlgorithmFactory(RSA publicKey) =>
            _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));

        /// <summary>
        /// Creates an instance of <see cref="RSAlgorithmFactory"/> using the provided pair of public and private keys.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <param name="privateKey">The private key for signing the data.</param>
        public RSAlgorithmFactory(RSA publicKey, RSA privateKey)
            : this(publicKey) =>
            _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));

        protected override IJwtAlgorithm Create(JwtAlgorithmName algorithm)
        {
            switch (algorithm)
            {
                case JwtAlgorithmName.RS256:
                    return CreateRS256Algorithm();
                case JwtAlgorithmName.RS384:
                    return CreateRS384Algorithm();
                case JwtAlgorithmName.RS512:
                    return CreateRS512Algorithm();
                case JwtAlgorithmName.RS1024:
                    return CreateRS1024Algorithm();
                case JwtAlgorithmName.RS2048:
                    return CreateRS2048Algorithm();
                case JwtAlgorithmName.RS4096:
                    return CreateRS4096Algorithm();
                case JwtAlgorithmName.HS256:
                case JwtAlgorithmName.HS384:
                case JwtAlgorithmName.HS512:
                    throw new NotSupportedException($"For algorithm {algorithm} please use an instance of {nameof(HMACSHAAlgorithmFactory)}");
                case JwtAlgorithmName.ES256:
                case JwtAlgorithmName.ES384:
                case JwtAlgorithmName.ES512:
                    throw new NotSupportedException($"For algorithm {algorithm} please use an instance of {nameof(ECDSAAlgorithmFactory)}");
                default:
                    throw new NotSupportedException($"For algorithm {Enum.GetName(typeof(JwtAlgorithmName), algorithm)} please use the appropriate factory by implementing {nameof(IAlgorithmFactory)}");
            }
        }

        private RS256Algorithm CreateRS256Algorithm()
        {
            if (_certFactory is object)
            {
                return new RS256Algorithm(_certFactory());
            }
            if (_publicKey is object && _privateKey is object)
            {
                return new RS256Algorithm(_publicKey, _privateKey);
            }
            if (_publicKey is object)
            {
                return new RS256Algorithm(_publicKey);
            }

            throw new InvalidOperationException("Can't create a new algorithm without a certificate factory, private key or public key");
        }

        private RS384Algorithm CreateRS384Algorithm()
        {
            if (_certFactory is object)
            {
                return new RS384Algorithm(_certFactory());
            }
            if (_publicKey is object && _privateKey is object)
            {
                return new RS384Algorithm(_publicKey, _privateKey);
            }
            if (_publicKey is object)
            {
                return new RS384Algorithm(_publicKey);
            }

            throw new InvalidOperationException("Can't create a new algorithm without a certificate factory, private key or public key");
        }

        private RS512Algorithm CreateRS512Algorithm()
        {
            if (_certFactory is object)
            {
                return new RS512Algorithm(_certFactory());
            }
            if (_publicKey is object && _privateKey is object)
            {
                return new RS512Algorithm(_publicKey, _privateKey);
            }
            if (_publicKey is object)
            {
                return new RS512Algorithm(_publicKey);
            }

            throw new InvalidOperationException("Can't create a new algorithm without a certificate factory, private key or public key");
        }

        private RS1024Algorithm CreateRS1024Algorithm()
        {
            if (_certFactory is object)
            {
                return new RS1024Algorithm(_certFactory());
            }
            if (_publicKey is object && _privateKey is object)
            {
                return new RS1024Algorithm(_publicKey, _privateKey);
            }
            if (_publicKey is object)
            {
                return new RS1024Algorithm(_publicKey);
            }

            throw new InvalidOperationException("Can't create a new algorithm without a certificate factory, private key or public key");
        }

        private RS2048Algorithm CreateRS2048Algorithm()
        {
            if (_certFactory is object)
            {
                return new RS2048Algorithm(_certFactory());
            }
            if (_publicKey is object && _privateKey is object)
            {
                return new RS2048Algorithm(_publicKey, _privateKey);
            }
            if (_publicKey is object)
            {
                return new RS2048Algorithm(_publicKey);
            }

            throw new InvalidOperationException("Can't create a new algorithm without a certificate factory, private key or public key");
        }

        private RS4096Algorithm CreateRS4096Algorithm()
        {
            if (_certFactory is object)
            {
                return new RS4096Algorithm(_certFactory());
            }
            if (_publicKey is object && _privateKey is object)
            {
                return new RS4096Algorithm(_publicKey, _privateKey);
            }
            if (_publicKey is object)
            {
                return new RS4096Algorithm(_publicKey);
            }

            throw new InvalidOperationException("Can't create a new algorithm without a certificate factory, private key or public key");
        }
    }
}