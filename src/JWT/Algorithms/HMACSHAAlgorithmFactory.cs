using System;

namespace JWT.Algorithms
{
    /// <inheritdoc />
    public class HMACSHAAlgorithmFactory : JwtAlgorithmFactory
    {
        private readonly byte[] _key;

        public HMACSHAAlgorithmFactory()
        {
            
        }

        public HMACSHAAlgorithmFactory(byte[] key)
        {
            _key = key;
        }

        protected override IJwtAlgorithm Create(JwtAlgorithmName algorithm)
        {
            switch (algorithm)
            {
                case JwtAlgorithmName.HS256:
                    return new HMACSHA256Algorithm(_key);
                case JwtAlgorithmName.HS384:
                    return new HMACSHA384Algorithm(_key);
                case JwtAlgorithmName.HS512:
                    return new HMACSHA512Algorithm(_key);
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