using System;
using JWT.Algorithms;

namespace JWT
{
    public sealed class AlgorithmFactory : IAlgorithmFactory
    {
        public IJwtAlgorithm Create(string algorithmName)
        {
            return Create((JwtHashAlgorithm)Enum.Parse(typeof(JwtHashAlgorithm), algorithmName));
        }

        public IJwtAlgorithm Create(JwtHashAlgorithm algorithm)
        {
            return Create(algorithm, null);
        }

        public IJwtAlgorithm Create(JwtHashAlgorithm algorithm, object param)
        {
            switch (algorithm)
            {
                case JwtHashAlgorithm.HS256:
                    return new HMACSHA256Algorithm();
                case JwtHashAlgorithm.HS384:
                    return new HMACSHA384Algorithm();
                case JwtHashAlgorithm.HS512:
                    return new HMACSHA512Algorithm();
                case JwtHashAlgorithm.RS256:
                    throw new NotSupportedException($"For {nameof(JwtHashAlgorithm.RS256)} please implement custom factory by implementing {nameof(IAlgorithmFactory)}");
                default:
                    throw new InvalidOperationException($"Algorithm {algorithm} is not supported.");
            }
        }
    }
}