namespace JWT
{
    public interface IAlgorithm
    {
        byte[] Sign(byte[] key, byte[] bytesToSign);

        string Name { get; }
    }
}