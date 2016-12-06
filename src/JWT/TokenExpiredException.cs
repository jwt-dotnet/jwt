using System;
using System.Collections.Generic;

namespace JWT
{
    public class TokenExpiredException : Exception
    {
        private const string PayloadDataKey = "PayloadData";
        private const string ExpirationKey = "Expiration";

        public TokenExpiredException(string message)
             : base(message)
        {
        }

        public Dictionary<string, object> PayloadData
        {
            get { return GetOrDefault<Dictionary<string, object>>(PayloadDataKey); }
            internal set { Data.Add(PayloadDataKey, value); }
        }

        public DateTime? Expiration
        {
            get { return GetOrDefault<DateTime?>(ExpirationKey); }
            internal set { Data.Add(ExpirationKey, value); }
        }

        private T GetOrDefault<T>(string key)
        {
            if (Data.Contains(key))
                return (T)Data[key];
            return default(T);
        }
    }
}