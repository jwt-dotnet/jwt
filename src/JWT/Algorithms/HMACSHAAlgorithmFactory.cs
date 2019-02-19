using System;

namespace JWT.Algorithms
{
    /// <inheritdoc />
    public class HMACSHAAlgorithmFactory : IAlgorithmFactory
    {
        /// <inheritdoc />
        public IJwtAlgorithm Create(string algorithmName) =>
            Create((JwtHashAlgorithm)Enum.Parse(typeof(JwtHashAlgorithm), algorithmName));

        /// <inheritdoc />
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
                    throw new NotSupportedException($"Algorithm {algorithm} is not supported.");
            }
        }
    }
}