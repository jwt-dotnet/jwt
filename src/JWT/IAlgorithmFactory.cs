namespace JWT
{
    public interface IAlgorithmFactory
    {
        IJwtAlgorithm Create(string algorithmName);

        IJwtAlgorithm Create(JwtHashAlgorithm algorithm);

        IJwtAlgorithm Create(JwtHashAlgorithm algorithm, object param);
    }
}