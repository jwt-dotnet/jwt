namespace JWT.Algorithms
{
    public sealed class GenericAlgorithmFactory<TAlgo> : IAlgorithmFactory
        where TAlgo : IJwtAlgorithm, new()
    {
        /// <inheritdoc />
        public IJwtAlgorithm Create(JwtDecoderContext context) =>
            new TAlgo();
    }
}