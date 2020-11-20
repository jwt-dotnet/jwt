using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using JWT.Algorithms;

namespace JWT.Tests.Models
{
    public static class TestData
    {
        public static readonly Customer Customer = new Customer
        {
            FirstName = "Jesus",
            Age = 33
        };

        public const string Secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
        public const string Secret2 = "QWORIJkmQWEDIHbjhOIHAUSDFOYnUGWEYT";

        public static string[] Secrets = { Secret, Secret2 };

        public const string Token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJKZXN1cyIsIkFnZSI6MzN9.jBdQNPhChZpZSMZX6Z5okc7YJ3dc5esWp4YCtasYXFU";
        public const string TokenWithExtraHeaders = "eyJmb28iOiJiYXIiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJKZXN1cyIsIkFnZSI6MzN9.QQJaPxDE6E7l-zC-LKTbEgPfId5FDvowRKww1o6jdwU";
        public const string TokenWithCustomTypeHeader = "eyJ0eXAiOiJmb28iLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJKZXN1cyIsIkFnZSI6MzN9.vubwuLxx_7AWGvo-Y8XF_l7XP1WOv5obJulIk3RlVdk";
        public const string TokenWithExp = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJKZXN1cyIsIkFnZSI6MzMsImV4cCI6MTYwNTgzNDI1NX0.dOkG1StO33Ae0qFQbHLslvSsCV6ThLofjc885egDnuY";
        public const string TokenWithNbf = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJKZXN1cyIsIkFnZSI6MzMsIm5iZiI6MTYwNTgzNDI1NX0.iuxTYx6CMcNaxgvPn8pfnPFDhIZceKB0PrIZgkmHFbg";
        public const long TokenTimestamp = 1605834255;

        public const string TokenWithIncorrectSignature = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        public const string TokenWithoutHeader = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.oj1ROhq6SyGDG3C0WIPe8wDuMJjA47uKwXCHkxl6Zy0";
        public const string TokenWithoutAlgorithm = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.ANY";

        public const string TokenByAsymmetricAlgorithm = "eyJraWQiOiJDRkFFQUUyRDY1MEE2Q0E5ODYyNTc1REU1NDM3MUVBOTgwNjQzODQ5IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoyMTQ3NDgzNjQ4LCJGaXJzdE5hbWUiOiJKZXN1cyIsIkFnZSI6MzN9.ZeGfWN3kBHZLiSh4jzzn6kx7F6lNu5OsowZW0Sv-_wpSgQO2_QXFUPLx23wm4J9rjMGQlSksEtCLd_X3iiBOBLbxAUWzdj59iJIAh485unZj12sBJ7KHDVsOMc6DcSJdwRo9S9yiJ_RJ57R-dn4uRdZTBXBZHrrmb35UjaAG6hFfu5d1Ap4ZjLxqDJGl0Wo4j5l6vR8HFpmiFHvqPQ4apjqkBGnitJ7oghbeRX0SIVNSkXbBDp3i9pC-hxzs2oHZC9ys0rJlfpxLls3MV4oQbQ7m6W9MrwwsdObJHI7PiTNfObLKdgySi6WkQS7rwXVz0DqRa8TXv8_USkvhsyGLMQ";

        public static readonly IDictionary<string, object> DictionaryPayload = new Dictionary<string, object>
        {
            { nameof(Customer.FirstName), Customer.FirstName },
            { nameof(Customer.Age), Customer.Age },
        };

        public const string ServerRsaPublicKey1 = "-----BEGIN CERTIFICATE-----MIICPDCCAaWgAwIBAgIBADANBgkqhkiG9w0BAQ0FADA7MQswCQYDVQQGEwJ1czELMAkGA1UECAwCVVMxETAPBgNVBAoMCENlcnR0ZXN0MQwwCgYDVQQDDANqd3QwHhcNMTcwNjI3MTgzNjM3WhcNMjAwMzIzMTgzNjM3WjA7MQswCQYDVQQGEwJ1czELMAkGA1UECAwCVVMxETAPBgNVBAoMCENlcnR0ZXN0MQwwCgYDVQQDDANqd3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALsspKjcF/mB0nheaT+9KizOeBM6Qpi69LzOLBw8rxohSFJw/BFB/ch+8jXbtq23IwtavJTwSeY6a7pbZgrwCwUK/27gy04m/tum5FJBfCVGTTI4vqUYeTKimQzxj2pupQ+wx//1tKrXMIDGdllmQ/tffQHXxYGBR5Ol543YRN+dAgMBAAGjUDBOMB0GA1UdDgQWBBQMfi0akrZdtPpiYSbE4h2/9vlaozAfBgNVHSMEGDAWgBQMfi0akrZdtPpiYSbE4h2/9vlaozAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAF9pg6H7C7O5/oHeRtKSOPb9WnrHZ/mxAl30wCh2pCtJLkgMKKhquYmKqTA+QWpSF/Qeaq17DAf7Wq8VQ2QES9WCQm+PlBlTeZAf3UTLkxIUDchuS8mR7QAgG67QNLl2OKMC4NWzq0d6ZYNzVqHHPe2AKgsRro6SEAv0Sf2QhE3j-----END CERTIFICATE-----";

        public const string ServerRsaPublicThumbprint1 = "CFAEAE2D650A6CA9862575DE54371EA980643849";

        public const string ServerRsaPublicKey2 = "MIIDfDCCAmSgAwIBAgIQQDCxkdjCQqmQsnSLtcHj3TANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJ1czELMAkGA1UECBMCVVMxETAPBgNVBAoTCENlcnR0ZXN0MQwwCgYDVQQDEwNqd3QwHhcNMjAwMzIzMDI1NDAzWhcNMjMwMzIzMDMwNDAzWjA7MQswCQYDVQQGEwJ1czELMAkGA1UECBMCVVMxETAPBgNVBAoTCENlcnR0ZXN0MQwwCgYDVQQDEwNqd3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5hM+0cIjO0oLcxQPGdnSS0ZVJDSNVsPmtiXimSLhEIPczbZ35OSWa9PI+PRIztr/yjtwjTlCES4EjyEoJ8LYIQmGVLdYV5ULS/CyXVpgWpDdiSv6QOwB2qMv3mKiPcmaKxy+oo4zfihBqGkCC6QnspyvUFPZiWTx86Apw3u3WqBRE3HQ+PjMnjDSnWdPaAsb75ti61RU+9qYj3BwxDJR6xnAaYz1RSkxHOw4+Ty+/tNtObrZmTH7msVRpV7kMU1QgyD3Y2/JTTf3YUU0LCm1J+WJ0cMbVrILAvVlOQnRn3IlcI1LOL/e6XEyET5tVymv8S5EoJjGf2o8VnTsF3vttAgMBAAGjfDB6MA4GA1UdDwEB/wQEAwIFoDAJBgNVHRMEAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAfBgNVHSMEGDAWgBTTMvXgytSFWwQk58CpxCpZAr5G1jAdBgNVHQ4EFgQU0zL14MrUhVsEJOfAqcQqWQK+RtYwDQYJKoZIhvcNAQELBQADggEBAK5vSwzh0x0pJm6njJX29rsd53ktyph+L90Enh0xzLFN0Ku9p+tM8E9TmKR+9ppdPqIEe4G/AuR1fHvmWenEw44M85Y/pBIPZDM2QVQngjg6iRQ42yD5hb/P4+UnvP9a5uI4Xc3f4NlJi3n54qBmdD5Hg52tNYgr8FKRoNzAoUCHelLk5PW0llF8Nc6cjJf0JfrSA1lVua488Dd34sPt798xM3IoISof1dqKslTypHP4BCyZ55SSfQJ+GrY7T9J3ct23BTrPnhhq0sPDogN4j258RmDriBGZmRcnrlmuBD5v+lvjYk0fISYNMfkrCQg5zae4d6BJIZVLY3gITGbaNoA=";

        public const string ServerRsaPrivateKey = "<RSAKeyValue><Modulus>uYTPtHCIztKC3MUDxnZ0ktGVSQ0jVbD5rYl4pki4RCD3M22d+TklmvTyPj0SM7a/8o7cI05QhEuBI8hKCfC2CEJhlS3WFeVC0vwsl1aYFqQ3Ykr+kDsAdqjL95ioj3JmiscvqKOM34oQahpAgukJ7Kcr1BT2Ylk8fOgKcN7t1qgURNx0Pj4zJ4w0p1nT2gLG++bYutUVPvamI9wcMQyUesZwGmM9UUpMRzsOPk8vv7TbTm62Zkx+5rFUaVe5DFNUIMg92NvyU0392FFNCwptSflidHDG1ayCwL1ZTkJ0Z9yJXCNSzi/3ulxMhE+bVcpr/EuRKCYxn9qPFZ07Bd77bQ==</Modulus><Exponent>AQAB</Exponent><P>2Mrzzbb8Gh7aoW0YXdtdO7WEZ7+pOvbxdp4Qw8sp8dF5cF5vss3I2FoJ9kssy/DsUsreBUhD0HKrADBus7BHKXp7Q/9hhu1nAJxpng255cUfngVD9k1xQdfWEHCeWrr7XJHcplTkh4ysH4nWK+8S+RoCpiuphkJJqVxPzDaY1+M=</P><Q>2xHwflmaMbNs9dXi3wx10SyG5KQJeRIXlKkhlUYlAU+7598AdmTiUPHfhj4WDRCmcJGHjSWqdiuQuwmRYsBXRhtk7XjGAjcefloSpXSR9G+tpVFuIthBU337g2pK1o8z/29LKiWZvcytgxQLEWwGIyduj2I9BoDw1jgFmVd/IG8=</Q><DP>b9n+ghO37G4g1QqpeLtWVhkoEDNFyANiv5V8BtjKclZmdoBy1ujviBikbSuKGErcUzcR593KB0EyUu2qIBGCFbd447NeiTPxYdJRd9eTIyZaUrhawThhh9wpOOAyA5PXXoJvOm4wXnNI1xjRpGc7/cPavAto8rk+sh/LmAxPPYs=</DP><DQ>b2l2N6v2IWSw+22lje5WVOUiTVGnh61N1MsXS0V7OGmGlOvy3kN8XdJE7Y7RxB89pm480+neAW8ykgzRpblQKVVxRNxxR1sk5PmGFiNsvzW0yCjbrFjzEDU4HqOGIAyAU14UigDJaZ+YdttQrbGUhXheYAmEI7SbxzaCknPPMX0=</DQ><InverseQ>SpRpqI+Z4g3jMbb0iE0oD+FAUaBXGp00DjKVbeYH8WQl2rVGFkspFYeN69u3ZFUL3JJd4rCF6zbuLq6iyDJq/F+Jo4zSzXChepr/dSEH1TszaA6imdqFyj3pjOT/ZXNK4YPCRijRM3fy8GdNybZDQljL1djY8D1YK3CWEtKuogs=</InverseQ><D>ADJKztC1SseTfRmPgnZ+DLXAgbflpK6WS3+/9/UcKAsc5LOmA8bytwvkjpPqYNGkH5g7iKU8yP16rbrSXgy6NJ7VYAVENJIhYWKdxxJzAMfvVkeCc4A/sa1GFThwXUG5KBND7EExrsu3oe67LyhOBJXv7vHCvQhSwkZNbiDEtOh7y6bKOOb0aluzPir3eY3HyN7TP2uS5mEeokMvwk9yGOUvCeKoz8t9WJf8HoP2OsDqFsbs5qA66qC6DWaU9OZ0VrO3zgmceIDP2ZXFkWmz2cVJ/Yvfi5zCvc0+g670twnuG8P00Syr/3xNCVuhwwuZbDcILjNvc9uOu9iDbY5xZQ==</D></RSAKeyValue>";

        public static readonly IJwtAlgorithm HMACSHA256Algorithm = new HMACSHA256Algorithm();

        public static readonly IJwtAlgorithm RS256Algorithm = new RS256Algorithm(
            new X509Certificate2(
                Encoding.ASCII.GetBytes(ServerRsaPublicKey2)));
    }
}