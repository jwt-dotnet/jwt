using System.Security.Cryptography;

namespace JWT.Algorithms
{
    public sealed class HMACSHA256Algorithm : IAlgorithm
    {
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            using (var sha = new HMACSHA256(key))
            {
                return sha.ComputeHash(bytesToSign);
            }
        }

        public string Name => JwtHashAlgorithm.HS256.ToString();
    }
}