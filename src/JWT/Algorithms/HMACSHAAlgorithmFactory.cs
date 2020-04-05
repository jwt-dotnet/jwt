using System;

namespace JWT.Algorithms
{
    /// <inheritdoc />
    public class HMACSHAAlgorithmFactory : IAlgorithmFactory
    {
        /// <inheritdoc />
        public virtual IJwtAlgorithm Create(JwtDecoderContext context)
        {
            var algorithmName = (JwtAlgorithmName)Enum.Parse(typeof(JwtAlgorithmName), context.Header.Algorithm);
            return Create(algorithmName);
        }

        protected virtual IJwtAlgorithm Create(JwtAlgorithmName algorithm)
        {
            switch (algorithm)
            {
                case JwtAlgorithmName.HS256:
                    return new HMACSHA256Algorithm();
                case JwtAlgorithmName.HS384:
                    return new HMACSHA384Algorithm();
                case JwtAlgorithmName.HS512:
                    return new HMACSHA512Algorithm();
                case JwtAlgorithmName.RS256:
                    throw new NotSupportedException($"For algorithm {nameof(JwtAlgorithmName.RS256)} please create custom factory by implementing {nameof(IAlgorithmFactory)}");
                default:
                    throw new NotSupportedException($"Algorithm {algorithm} is not supported.");
            }
        }
    }
}