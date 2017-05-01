using System;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    public sealed class RSAlgorithmFactory : HMACSHAAlgorithmFactory
    {
        private readonly Func<X509Certificate2> _certFactory;

        public RSAlgorithmFactory(Func<X509Certificate2> certFactory)
        {
            _certFactory = certFactory;
        }

        public override IJwtAlgorithm Create(JwtHashAlgorithm algorithm)
        {
            return algorithm == JwtHashAlgorithm.RS256 ?
                       new RS256Algorithm(_certFactory()) :
                       base.Create(algorithm);
        }
    }
}