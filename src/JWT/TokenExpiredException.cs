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
            get
            {
               if (Data.Contains(PayloadDataKey))
                  return (Dictionary<string, object>) Data[PayloadDataKey];
               return null;
            }
            internal set { Data.Add(PayloadDataKey, value); }
        }
 
        public DateTime? Expiration
        {
            get
            {
               if (Data.Contains(ExpirationKey))
                  return (DateTime) Data[ExpirationKey];
               return null;
            }
            internal set { Data.Add(ExpirationKey, value); }
        }
    }
}