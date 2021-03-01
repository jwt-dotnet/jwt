using System;
using JWT.Exceptions;

#if NET35 || NET40
using IReadOnlyPayloadDictionary = System.Collections.Generic.IDictionary<string, object>;
using IReadOnlyList = System.Collections.Generic.IList<string>;
#else
using IReadOnlyPayloadDictionary = System.Collections.Generic.IReadOnlyDictionary<string, object>;
using IReadOnlyList = System.Collections.Generic.IReadOnlyList<string>;
#endif

namespace JWT
{
    /// <summary>
    /// A context for validating JWT claims
    /// </summary>
    public class JwtClaimValidationContext
    {
        /// <summary>
        /// Get token claims
        /// </summary>
        public IReadOnlyPayloadDictionary Claims { get; internal set; }

        /// <summary>
        /// Get current time in seconds since unix epoch
        /// </summary>
        public double NowInSecondsSinceEpoch { get; internal set; }

        /// <summary>
        /// Get expire claim value if exists
        /// </summary>
        public double? Expire { get; internal set; }

        /// <summary>
        /// Get issued at claim value if exists
        /// </summary>
        public double? IssuedAt { get; internal set; }

        /// <summary>
        /// Get not before claim value if exists
        /// </summary>
        public double? NotBefore { get; internal set; }

        /// <summary>
        /// Get issuer claim value if exists
        /// </summary>
        public string Issuer { get; internal set; }

        /// <summary>
        /// Get subject claim value if exists
        /// </summary>
        public string Subject { get; internal set; }

        /// <summary>
        /// Get audience claim value if exists
        /// </summary>
        public IReadOnlyList Audiences { get; internal set; }
    }

    /// <summary>
    /// Requirements for validating JWT claims
    /// </summary>
    public class JwtClaimValidation
    {
        /// <summary>
        /// get/set time margin in seconds for time-based claim validation
        /// </summary>
        public int TimeMarginInSeconds { get; set; }

        /// <summary>
        /// a function to validate JWT claims
        /// </summary>
        public Func<JwtClaimValidationContext, int, Exception> Validator { get; set; }
    }

    /// <summary>
    /// Extension methods to support claim validation
    /// </summary>
    public static class JwtClaimValidationExtensions
    {
        /// <summary>
        /// validate expire claim
        /// </summary>
        /// <param name="context">the jwt validation context</param>
        /// <param name="timeMargin">time margin in seconds</param>
        /// <returns>null if claim is valid; an exception otherwise</returns>
        /// <exception cref="TokenExpiredException">if claim is expired</exception>
        public static Exception ValidateExpireClaim(this JwtClaimValidationContext context, int timeMargin)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            if (context.Expire == null) return null;

            if (context.NowInSecondsSinceEpoch - timeMargin < context.Expire) return null;

            return new TokenExpiredException("Token has expired.")
            {
                Expiration = UnixEpoch.Value.AddSeconds(context.Expire.Value),
                PayloadData = context.Claims
            };
        }

        /// <summary>
        /// validate issued at claim
        /// </summary>
        /// <param name="context">the jwt validation context</param>
        /// <param name="timeMargin">time margin in seconds</param>
        /// <returns>null if claim is valid; an exception otherwise</returns>
        /// <exception cref="SignatureVerificationException">if claim is not valid</exception>
        public static Exception ValidateIssuedAtClaim(this JwtClaimValidationContext context, int timeMargin)
        {
            if (context.IssuedAt + timeMargin < context.NowInSecondsSinceEpoch)
                return new SignatureVerificationException("Token is not valid.");

            return null;
        }

        /// <summary>
        /// validate not before claim
        /// </summary>
        /// <param name="context">the jwt validation context</param>
        /// <param name="timeMargin">time margin in seconds</param>
        /// <returns>null if claim is valid; an exception otherwise</returns>
        /// <exception cref="SignatureVerificationException">if claim is not yet valid</exception>
        public static Exception ValidateNotBeforeClaim(this JwtClaimValidationContext context, int timeMargin)
        {
            if (context.NowInSecondsSinceEpoch + timeMargin < context.NotBefore)
                return new SignatureVerificationException("Token is not yet valid.");

            return null;
        }
    }
}
