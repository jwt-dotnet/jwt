﻿using System;

namespace JWT
{
    /// <summary>
    /// Represents an exception thrown when a signature validation fails.
    /// </summary>
    public class SignatureVerificationException : Exception
    {
        private const string ExpectedKey = "Expected";
        private const string ReceivedKey = "Received";

        /// <summary>
        /// Create the SignatureVerificationException.
        /// </summary>
        /// <param name="message">The error message.</param>
        public SignatureVerificationException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Expected key.
        /// </summary>
        public string Expected
        {
            get => GetOrDefault<string>(ExpectedKey);
            internal set => this.Data.Add(ExpectedKey, value);
        }

        /// <summary>
        /// Received key.
        /// </summary>
        public string Received
        {
            get => GetOrDefault<string>(ReceivedKey);
            internal set => this.Data.Add(ReceivedKey, value);
        }

        /// <summary>
        /// Retrieves the value for the provided key, or default.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        protected T GetOrDefault<T>(string key)
        {
            if (this.Data.Contains(key))
                return (T)this.Data[key];
            return default(T);
        }
    }
}