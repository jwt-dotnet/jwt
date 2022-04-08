using System;

namespace JWT.Algorithms
{
    /// <inheritdoc />
    public abstract class JwtAlgorithmFactory : IAlgorithmFactory
    {
        /// <inheritdoc />
        public virtual IJwtAlgorithm Create(JwtDecoderContext context)
        {
            var algorithm = context?.Header?.Algorithm ?? throw new ArgumentNullException(nameof(context));
            var algorithmName = (JwtAlgorithmName)Enum.Parse(typeof(JwtAlgorithmName), algorithm);
            return Create(algorithmName);
        }

        protected abstract IJwtAlgorithm Create(JwtAlgorithmName algorithm);
    }
}