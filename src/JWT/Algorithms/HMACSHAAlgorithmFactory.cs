using System;
using JWT.Algorithms;

namespace JWT.Algorithms
{
    /// <summary>
    /// Provides IJwtAlgorithms.
    /// </summary>
    public class HMACSHAAlgorithmFactory : IAlgorithmFactory
    {
        /// <summary>
        /// Creates an AlgorithmFactory using the provided
        /// algorithm name.
        /// </summary>
        /// <param name="algorithmName">The name of the algorithm.</param>
        /// <returns></returns>
        public IJwtAlgorithm Create(string algorithmName)
        {
            return Create((JwtHashAlgorithm)Enum.Parse(typeof(JwtHashAlgorithm), algorithmName));
        }

        /// <summary>
        /// Creates an AlgorithmFactory using the provided
        /// algorithm name.
        /// </summary>
        /// <param name="algorithm">The name of the algorithm.</param>
        public virtual IJwtAlgorithm Create(JwtHashAlgorithm algorithm)
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
                    throw new NotSupportedException($"For algorithm {nameof(JwtHashAlgorithm.RS256)} please create custom factory by implementing {nameof(IAlgorithmFactory)}");
                default:
                    throw new InvalidOperationException($"Algorithm {algorithm} is not supported.");
            }
        }
    }
}