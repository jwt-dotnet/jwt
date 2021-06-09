using System;

namespace JWT
{
    /// <summary>
    /// Contains a set of parameters that are used by a <see cref="JwtValidator" /> when validating a token.
    /// </summary>
    public class ValidationParameters
    {
        /// <summary>
        /// <para>
        /// The constructor is kept private to prevent creating a new <see cref="ValidationParameters"/> object which
        /// will not validate any of the parameters of a token.
        /// </para>
        /// <para>
        /// Use <see cref="Default"/> if you wish to create a <see cref="ValidationParameters"/> object with all
        /// properties set to <see langword="true"/> or use <see cref="None"/> if you wish to create a create a
        /// <see cref="ValidationParameters"/> object with all validation turned off.
        /// </para>
        /// </summary>
        private ValidationParameters()
        {
        }

        /// <summary>
        /// Gets or sets a boolean that controls if validation of the signature that signed the token is called.
        /// </summary>
        public bool ValidateIssuerSigningKey { get; set; }

        /// <summary>
        /// Gets or sets a boolean to control if the lifetime will be validated during token validation.
        /// </summary>
        public bool ValidateLifetime { get; set; }

        /// <summary>
        /// Gets or sets a boolean to control if the issued time will be validated during token validation.
        /// </summary>
        public bool ValidateIssuedTime { get; set; }

        /// <summary>
        /// Gets or sets an integer to control the time margin in seconds for exp and nbf during token validation.
        /// </summary>
        public int TimeMargin { get; set; }

        /// <summary>
        /// A boolean that indicates if any of the <see cref="ValidationParameters" /> properties have been set to <see langword="true" />.
        /// </summary>
        public bool RequiresValidation => this.ValidateIssuerSigningKey || this.ValidateLifetime || this.ValidateIssuedTime;

        /// <summary>
        /// Returns a <see cref="ValidationParameters" /> with all the validation parameters set to <see langword="false" />.
        /// </summary>
        public static ValidationParameters None => new ValidationParameters
        {
            ValidateIssuerSigningKey = false,
            ValidateLifetime = false,
            ValidateIssuedTime = false,
            TimeMargin = 0
        };

        /// <summary>
        /// Returns a <see cref="ValidationParameters" /> with all the validation parameters set to <see langword="true" />.
        /// </summary>
        public static ValidationParameters Default => new ValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidateIssuedTime = true,
            TimeMargin = 0
        };
    }

    public static class ValidationParametersExtensions
    {
        public static ValidationParameters With(this ValidationParameters @this, Action<ValidationParameters> action)
        {
            action(@this);
            return @this;
        }
    }
}
