namespace JWT
{
    /// <summary>
    /// Contains a set of parameters that are used by a <see cref="JwtValidator" /> when validating a token.
    /// </summary>
    public class ValidationParameters
    {
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
            ValidateIssuedTime = false
        };

        /// <summary>
        /// Returns a <see cref="ValidationParameters" /> with all the validation parameters set to <see langword="true" />.
        /// </summary>
        public static ValidationParameters Default => new ValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidateIssuedTime = true
        };
    }
}
