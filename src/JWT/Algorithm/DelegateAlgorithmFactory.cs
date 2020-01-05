

namespace JWT.Algorithms
{
    /// <inheritdoc />
    public sealed class RSAlgorithmFactory : HMACSHAAlgorithmFactory
    {
        private readonly Func<RS256Algorithm> _algFactory;


        /// <inheritdoc />
        public override IJwtAlgorithm Create(JwtHashAlgorithm algorithm)
        {
       
    }
}
