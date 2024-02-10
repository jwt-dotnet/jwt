namespace JWT.Jwk
{
    public interface IJwtWebKeysCollection
    {
        JwtWebKey Find(string keyId);
    }
}