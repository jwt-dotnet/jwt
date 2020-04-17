#if NET35 || NET40
namespace System.Security.Cryptography
{
    internal struct HashAlgorithmName : IEquatable<HashAlgorithmName>
    {
        public static HashAlgorithmName MD5 => new HashAlgorithmName("MD5");
        public static HashAlgorithmName SHA1 => new HashAlgorithmName("SHA1");
        public static HashAlgorithmName SHA256 => new HashAlgorithmName("SHA256");
        public static HashAlgorithmName SHA384 => new HashAlgorithmName("SHA384");
        public static HashAlgorithmName SHA512 => new HashAlgorithmName("SHA512");

        public string Name { get; }

        public HashAlgorithmName(string name)
        {
            this.Name = name;
        }

        public static bool operator ==(HashAlgorithmName left, HashAlgorithmName right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(HashAlgorithmName left, HashAlgorithmName right)
        {
            return !(left == right);
        }

        public bool Equals(HashAlgorithmName other)
        {
            return this.Name == other.Name;
        }

        public override bool Equals(object obj)
        {
            return obj is HashAlgorithmName other && Equals(other);
        }

        public override int GetHashCode()
        {
            return this.Name?.GetHashCode() ?? 0;
        }

        public override string ToString()
        {
            return this.Name ?? string.Empty;
        }
    }
}
#endif