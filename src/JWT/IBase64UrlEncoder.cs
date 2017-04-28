namespace JWT
{
    /// <summary>
    /// Base64UrlEncoder interface.
    /// </summary>
    public interface IBase64UrlEncoder
    {
        /// <summary>
        /// Encode the byte array to a Base64 string.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        string Encode(byte[] input);

        /// <summary>
        /// Decode the Base64 string to a byte array.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        byte[] Decode(string input);
    }
}
