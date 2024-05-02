using System;

namespace JWT.Jwk
{
    /// <summary>
    /// Based on Microsoft.AspNetCore.WebUtilities.WebEncoders
    /// </summary>
    internal static class JwtWebKeyPropertyValuesEncoder
    {
        public static byte[] Base64UrlDecode(string input)
        {
            if (input is null)
                return null;
    
            var paddingCharsCount = GetNumBase64PaddingCharsToAddForDecode(input.Length);
            var buffer = new char[input.Length + paddingCharsCount];
    
            for (var i = 0; i < input.Length; ++i)
            {
                char ch = DecodeCharacter(input[i]);
                buffer[i] = ch;
            }
    
            for (var i = input.Length; i < buffer.Length; ++i) 
            {
                buffer[i] = '=';
            }
    
            return Convert.FromBase64CharArray(buffer, 0, buffer.Length);
        }
    
        private static int GetNumBase64PaddingCharsToAddForDecode(int length)
        {
            switch (length % 4)
            {
                case 0:
                    return 0;
                case 2:
                    return 2;
                case 3:
                    return 1;
                default:
                    throw new ArgumentOutOfRangeException (nameof(length), $"Malformed input: {length} is an invalid input length.");
            }
        }
    
        private static char DecodeCharacter(char ch)
        {
            switch (ch)
            {
                case '-':
                    return '+';
                case '_':
                    return '/';
                default:
                    return ch;
            }
        }
    }
}
