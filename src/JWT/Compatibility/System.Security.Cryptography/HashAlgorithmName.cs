#if NET35 || NET40
namespace System.Security.Cryptography
{
    public readonly struct HashAlgorithmName
    {
        public HashAlgorithmName(string name) =>
            this.Name = name;

        public string Name { get; }

        public static readonly HashAlgorithmName MD5 = new HashAlgorithmName(nameof(MD5));
        public static readonly HashAlgorithmName SHA1 = new HashAlgorithmName(nameof(SHA1));
        public static readonly HashAlgorithmName SHA256 = new HashAlgorithmName(nameof(SHA256));
        public static readonly HashAlgorithmName SHA384 = new HashAlgorithmName(nameof(SHA384));
        public static readonly HashAlgorithmName SHA512 = new HashAlgorithmName(nameof(SHA512));
    }
}
#endif
