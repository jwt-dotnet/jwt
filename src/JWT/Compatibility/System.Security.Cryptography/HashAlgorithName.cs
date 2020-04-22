#if NET35 || NET40
namespace System.Security.Cryptography
{
    internal static class HashAlgorithmName
    {
        public static readonly string MD5 = nameof(MD5);
        public static readonly string SHA1 = nameof(SHA1);
        public static readonly string SHA256 = nameof(SHA256);
        public static readonly string SHA384 = nameof(SHA384);
        public static readonly string SHA512 = nameof(SHA512);
    }
}
#endif