namespace JWT.Jwk
{
    public interface IJwtWebKeysCollectionFactory
    {
        JwtWebKeysCollection CreateKeys();
    }
}