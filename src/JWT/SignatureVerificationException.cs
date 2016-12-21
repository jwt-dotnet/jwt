using System;

namespace JWT
{
    public class SignatureVerificationException : Exception
    {
        private const string ExpectedKey = "Expected";
        private const string ReceivedKey = "Received";

        public SignatureVerificationException(string message)
            : base(message)
        {
        }

        public string Expected
        {
            get { return GetOrDefault<string>(ExpectedKey); }
            internal set { Data.Add(ExpectedKey, value); }
        }

        public string Received
        {
            get { return GetOrDefault<string>(ReceivedKey); }
            internal set { Data.Add(ReceivedKey, value); }
        }

        protected T GetOrDefault<T>(string key)
        {
            if (Data.Contains(key))
                return (T)Data[key];
            return default(T);
        }
    }
}