using System;

namespace JWT.Jwk;

/// <summary>
/// Based on Microsoft.AspNetCore.WebUtilities.WebEncoders
/// </summary>
internal static class JwtWebKeyPropertyValuesEncoder
{
    public static byte[] Base64UrlDecode(string input)
    {
        if (input == null)
            return null;

        var inputLength = input.Length;

        var paddingCharsCount = GetNumBase64PaddingCharsToAddForDecode(inputLength);

        var buffer = new char[inputLength + paddingCharsCount];

        for (var i = 0; i < inputLength; ++i)
        {
            var symbol = input[i];

            switch (symbol)
            {
                case '-':
                    buffer[i] = '+';
                    break;
                case '_':
                    buffer[i] = '/';
                    break;
                default:
                    buffer[i] = symbol;
                    break;
            }
        }

        for (var i = input.Length; i < buffer.Length; ++i) 
            buffer[i] = '=';

        return Convert.FromBase64CharArray(buffer, 0, buffer.Length);
    }

    private static int GetNumBase64PaddingCharsToAddForDecode(int inputLength)
    {
        switch (inputLength % 4)
        {
            case 0:
                return 0;
            case 2:
                return 2;
            case 3:
                return 1;
            default:
                throw new FormatException($"Malformed input: {inputLength} is an invalid input length.");
        }
    }
}