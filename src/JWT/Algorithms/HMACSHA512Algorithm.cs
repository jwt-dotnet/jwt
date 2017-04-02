using System.Security.Cryptography;

namespace JWT.Algorithms
{
    public sealed class HMACSHA512Algorithm : IJwtAlgorithm
    {
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            using (var sha = new HMACSHA512(key))
            {
                return sha.ComputeHash(bytesToSign);
            }
        }

        public string Name => JwtHashAlgorithm.HS512.ToString();
    }
}