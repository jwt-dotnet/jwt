namespace JWT
{
    public interface IJwtAlgorithm
    {
        byte[] Sign(byte[] key, byte[] bytesToSign);

        string Name { get; }
    }
}