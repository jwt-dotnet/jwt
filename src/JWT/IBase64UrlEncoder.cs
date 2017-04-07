namespace JWT
{
    public interface IBase64UrlEncoder
    {
        string Encode(byte[] input);

        byte[] Decode(string input);
    }
}
