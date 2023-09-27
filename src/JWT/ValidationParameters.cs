using System;

namespace JWT
{
    /// <summary>
    /// Contains a set of parameters that are used by a <see cref="JwtValidator" /> when validating a token.
    /// </summary>
    public class ValidationParameters
    {
        /// <remarks>
        /// By default, all peroperties are set to <c>true</c> to ensure validation is enabled.
        /// Use <see cref="Default"/> if you'd like to set all properties set to <see langword="true" />
        /// or use <see cref="None"/> if you'd like to set all properties set to <see langword="false" />.
        /// </remarks>>
        public ValidationParameters()
        {
        }

        /// <summary>
        /// Gets or sets whether to validate the validity of the token's signature.
        /// </summary>
        public bool ValidateSignature { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to validate the validity of the token's expiration time.
        /// </summary>
        public bool ValidateExpirationTime { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to validate the validity of the token's issued time.
        /// </summary>
        public bool ValidateIssuedTime { get; set; } = true;

        /// <summary>
        /// Gets or sets the time margin in seconds for exp and nbf during token validation.
        /// </summary>
        public int TimeMargin { get; set; }

        /// <summary>
        /// Returns a <see cref="ValidationParameters" /> with all properties set to <see langword="true" />.
        /// </summary>
        public static ValidationParameters Default => new ValidationParameters();

        /// <summary>
        /// Returns a <see cref="ValidationParameters" /> with all properties set to <see langword="false" />.
        /// </summary>
        public static ValidationParameters None => new ValidationParameters
        {
            ValidateSignature = false,
            ValidateExpirationTime = false,
            ValidateIssuedTime = false,
            TimeMargin = 0
        };
    }

    public static class ValidationParametersExtensions
    {
        public static ValidationParameters With(this ValidationParameters @this, Action<ValidationParameters> action)
        {
            if (action is null)
                throw new ArgumentNullException(nameof(action));

            action(@this);

            return @this;
        }
    }
}
