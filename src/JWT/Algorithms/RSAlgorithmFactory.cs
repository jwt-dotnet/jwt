using System;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <inheritdoc />
    public sealed class RSAlgorithmFactory : HMACSHAAlgorithmFactory
    {
        private readonly Func<X509Certificate2> _certFactory;

        /// <summary>
        /// Initializes a new instance of the <see cref="RSAlgorithmFactory"/> class
        /// </summary>
        /// <param name="certFactory">Func that returns <see cref="X509Certificate2" /> which will be used to instantiate <see cref="RS256Algorithm" /></param>
        public RSAlgorithmFactory(Func<X509Certificate2> certFactory)
        {
            _certFactory = certFactory;
        }

        /// <inheritdoc />
        public override IJwtAlgorithm Create(JwtHashAlgorithm algorithm)
        {
            return algorithm == JwtHashAlgorithm.RS256 ?
                       new RS256Algorithm(_certFactory()) :
                       base.Create(algorithm);
        }
    }
}