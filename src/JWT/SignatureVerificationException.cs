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
            get
            {
               if (Data.Contains(ExpectedKey))
                  return (string) Data[ExpectedKey];
               return null;
            }
            internal set { Data.Add(ExpectedKey, value); }
        }
 
        public string Received
        {
            get
            {
               if (Data.Contains(ReceivedKey))
                  return (string) Data[ReceivedKey];
               return null;
            }
            internal set { Data.Add(ReceivedKey, value); }
        }
    }
}