using System;
using System.Collections.Generic;
namespace JWT.Builder.Models
{

    /// <summary>
    /// Represents the Data that will store in a JWT.
    /// </summary>
    public class JWTData
    {
        /// <summary>
        /// Create a new instance of JWTData and initalize Header and Payload.
        /// </summary>
        /// <returns>A Instance of <see cref"JWTData"/></returns>
        public JWTData() : this(header: new Dictionary<string, string>(), payLoad: new Dictionary<string, object>())
        {
        }

        /// <summary>
        /// Create a new instance of JWTData
        /// </summary>
        /// <param name="header">A Instance of a dictionary that contains the headers</param>
        /// <param name="payLoad">A instance of a dictionary that contans the payload</param>
        public JWTData(Dictionary<string, string> header, Dictionary<string, object> payLoad)
        {
            this.Header = header;
            this.PayLoad = payLoad;
        }

        public JWTData(string token)
        {
            var partsOfToken = token.Split('.');
            if(partsOfToken.Length != 3)
            {
                throw new ArgumentOutOfRangeException(nameof(partsOfToken), "Token must consist of 3 delimited by dot parts.");
            }

        }

        /// <summary>
        /// The header information as a key, value store of the JWT
        /// </summary>
        /// <returns>The headers of the JWT</returns>
        public Dictionary<string, string> Header { get; set; }
        /// <summary>
        /// The payload of the JWT as a key,value store
        /// </summary>
        /// <returns>The payload of the JWT</returns>
        public Dictionary<string, object> PayLoad { get; set; }

        private Dictionary<string, string> ConvertStringHeader(string header)
        {

            return null;
        }

    }
}