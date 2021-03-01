using System;
using JWT.Exceptions;

#if NET35 || NET40
using IReadOnlyPayloadDictionary = System.Collections.Generic.IDictionary<string, object>;
using IReadOnlyStringList = System.Collections.Generic.IList<string>;
#else
using IReadOnlyPayloadDictionary = System.Collections.Generic.IReadOnlyDictionary<string, object>;
using IReadOnlyStringList = System.Collections.Generic.IReadOnlyList<string>;
#endif


namespace JWT
{
    /// <summary>
    /// Requirements for validating JWT claims
    /// </summary>
    public class JwtClaimValidation
    {
        /// <summary>
        /// initialize new instance
        /// </summary>
        public JwtClaimValidation()
        {
            TimeMargin = 0;
            ResetValidators();
        }

        /// <summary>
        /// get/set time margin in seconds for time-based claim validation
        /// </summary>
        public int TimeMargin { get; set; }

        /// <summary>
        /// get/set whether the expire claim must exist jwt payload, 
        /// when the claim exists it will trigger the <see cref="ExpireValidator"/>
        /// </summary>
        public bool ExpireMustExist { get; set; } = false;

        /// <summary>
        /// get/set whether the issued at claim must exist jwt payload, 
        /// when the claim exists it will trigger the <see cref="IssuedAtValidator"/>
        /// </summary>
        public bool IssuedAtMustExist { get; set; } = false;

        /// <summary>
        /// get/set whether the not before claim must exist jwt payload, 
        /// when the claim exists it will trigger the <see cref="NotBeforeValidator"/>
        /// </summary>
        public bool NotBeforeMustExist { get; set; } = false;

        /// <summary>
        /// get/set whether the issuer claim must exist jwt payload, 
        /// when the claim exists it will trigger the <see cref="IssuerValidator"/>
        /// </summary>
        public bool IssuerMustExist { get; set; } = false;

        /// <summary>
        /// get/set whether the subject claim must exist jwt payload, 
        /// when the claim exists it will trigger the <see cref="SubjectValidator"/>
        /// </summary>
        public bool SubjectMustExist { get; set; } = false;

        /*
        /// <summary>
        /// get/set whether the audience claim must exist jwt payload, 
        /// when the claim exists it will trigger the <see cref="AudienceValidator"/>
        /// </summary>
        public bool AudienceMustExist { get; set; } = false;
        */

        /// <summary>
        /// get/set the method to invoke in order to validate the expire claim,
        /// the method takes the following parameters in order: jwt payload, expire claim value, current time in seconds since epoch,
        /// the method should return an exception if claim is not valid
        /// </summary>
        public Func<IReadOnlyPayloadDictionary, double, double, Exception> ExpireValidator { get; set; }

        /// <summary>
        /// get/set the method to invoke in order to validate the issued at claim,
        /// the method takes the following parameters in order: jwt payload, issued at claim value, current time in seconds since epoch,
        /// the method should return an exception if claim is not valid
        /// </summary>
        public Func<IReadOnlyPayloadDictionary, double, double, Exception> IssuedAtValidator { get; set; }

        /// <summary>
        /// get/set the method to invoke in order to validate the not before claim,
        /// the method takes the following parameters in order: jwt payload, not before claim value, current time in seconds since epoch,
        /// the method should return an exception if claim is not valid
        /// </summary>
        public Func<IReadOnlyPayloadDictionary, double, double, Exception> NotBeforeValidator { get; set; }

        /// <summary>
        /// get/set the method to invoke in order to validate the issuer claim,
        /// the method takes the following parameters in order: jwt payload, issuer claim value, 
        /// the method should return an exception if claim is not valid
        /// </summary>
        public Func<IReadOnlyPayloadDictionary, string, Exception> IssuerValidator { get; set; }

        /// <summary>
        /// get/set the method to invoke in order to validate the subject claim,
        /// the method takes the following parameters in order: jwt payload, subject claim value, 
        /// the method should return an exception if claim is not valid
        /// </summary>
        public Func<IReadOnlyPayloadDictionary, string, Exception> SubjectValidator { get; set; }

        /*
        /// <summary>
        /// get/set the method to invoke in order to validate the expire claim,
        /// the method takes the following parameters in order: jwt payload, audience claim value, 
        /// the method should return an exception if claim is not valid
        /// </summary>
        public Func<IReadOnlyPayloadDictionary, IReadOnlyStringList, Exception> AudienceValidator { get; set; }
        */

        /// <summary>
        /// the default validator for expire claim
        /// </summary>
        /// <param name="jwtPayload">the jwt payload</param>
        /// <param name="expireValue">the claim value</param>
        /// <param name="nowSecondsSinceEpoch">current time in seconds since unix epoch</param>
        /// <returns>null if claim is valid; an exception otherwise</returns>
        /// <exception cref="TokenExpiredException">if claim is expired</exception>
        public Exception DefaultExpireValidator(IReadOnlyPayloadDictionary jwtPayload,
            double expireValue, double nowSecondsSinceEpoch)
        {
            if (nowSecondsSinceEpoch - TimeMargin >= expireValue)
            {
                return new TokenExpiredException("Token has expired.")
                {
                    Expiration = UnixEpoch.Value.AddSeconds(expireValue),
                    PayloadData = jwtPayload
                };
            }

            return null;
        }

        /// <summary>
        /// the default validator for issued at claim
        /// </summary>
        /// <param name="jwtPayload">the jwt payload</param>
        /// <param name="iatValue">the claim value</param>
        /// <param name="nowSecondsSinceEpoch">current time in seconds since unix epoch</param>
        /// <returns>null if claim is valid; an exception otherwise</returns>
        /// <exception cref="SignatureVerificationException">if claim is not valid</exception>
        public Exception DefaultIssuedAtValidator(IReadOnlyPayloadDictionary jwtPayload,
            double iatValue, double nowSecondsSinceEpoch)
        {
            if (iatValue + TimeMargin < nowSecondsSinceEpoch)
                return new SignatureVerificationException("Token is not valid.");

            return null;
        }

        /// <summary>
        /// the default validator for not before claim
        /// </summary>
        /// <param name="jwtPayload">the jwt payload</param>
        /// <param name="nbfValue">the claim value</param>
        /// <param name="nowSecondsSinceEpoch">current time in seconds since unix epoch</param>
        /// <returns>null if claim is valid; an exception otherwise</returns>
        /// <exception cref="SignatureVerificationException">if claim is not yet valid</exception>
        public Exception DefaultNotBeforeValidator(IReadOnlyPayloadDictionary jwtPayload,
            double nbfValue, double nowSecondsSinceEpoch)
        {
            if (nowSecondsSinceEpoch + TimeMargin < nbfValue)
                return new SignatureVerificationException("Token is not yet valid.");

            return null;
        }

        /// <summary>
        /// set default validators
        /// </summary>
        public void ResetValidators()
        {
            ExpireValidator = DefaultExpireValidator;
            IssuedAtValidator = DefaultIssuedAtValidator;
            NotBeforeValidator = DefaultNotBeforeValidator;
            IssuerValidator = SubjectValidator = (a, b) => null;
            //AudienceValidator = (_, _) => null;
        }
    }
}
