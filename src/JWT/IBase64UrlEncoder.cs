namespace JWT
{
    public interface IBase64UrlEncoder
    {
        string UrlEncode(byte[] input);

        byte[] UrlDecode(string input);
    }
}