namespace JWT
{
    /// <summary>
    /// Represents a base64 encoder/decoder.
    /// </summary>
    public interface IBase64UrlEncoder
    {
        /// <summary>
        /// Encodes the byte array to a Base64 string.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        string Encode(byte[] input);

        /// <summary>
        /// Decodes the Base64 string to a byte array.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        byte[] Decode(string input);
    }
}
