using System;

namespace JWT.Algorithms
{
    /// <inheritdoc />
    public class HMACSHAAlgorithmFactory : JwtAlgorithmFactory
    {
        protected override IJwtAlgorithm Create(JwtAlgorithmName algorithm)
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
                case JwtAlgorithmName.RS384:
                case JwtAlgorithmName.RS512:
                    throw new NotSupportedException($"For algorithm {algorithm} please use an instance of {nameof(RSAlgorithmFactory)}");
                case JwtAlgorithmName.ES256:
                case JwtAlgorithmName.ES384:
                case JwtAlgorithmName.ES512:
                    throw new NotSupportedException($"For algorithm {algorithm} please use an instance of {nameof(ECDSAAlgorithmFactory)}");
                default:
                    throw new NotSupportedException($"For algorithm {Enum.GetName(typeof(JwtAlgorithmName), algorithm)} please use the appropriate factory by implementing {nameof(IAlgorithmFactory)}");
            }
        }
    }
}