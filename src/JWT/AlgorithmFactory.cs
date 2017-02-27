using System;
using JWT.Algorithms;

namespace JWT
{
    public sealed class AlgorithmFactory
    {
        public IJwtAlgorithm Create(string algorithmName)
        {
            return Create((JwtHashAlgorithm)Enum.Parse(typeof(JwtHashAlgorithm), algorithmName));
        }

        public IJwtAlgorithm Create(JwtHashAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case JwtHashAlgorithm.HS256:
                    return new HMACSHA256Algorithm();
                case JwtHashAlgorithm.HS384:
                    return new HMACSHA384Algorithm();
                case JwtHashAlgorithm.HS512:
                    return new HMACSHA512Algorithm();
                default:
                    throw new InvalidOperationException($"Algorithm {algorithm} is not supported.");
            }
        }
    }
}