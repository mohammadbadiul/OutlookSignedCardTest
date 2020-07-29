using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace OutlookSignedCardTest
{
    public static class Signer
    {
        public static JwtSecurityToken Sign(X509Certificate2 cert, IEnumerable<Claim> claims)
        {
            var subject = new ClaimsIdentity(claims);

            var x509Key = new X509SecurityKey(cert);
            SigningCredentials signingCredentials = new SigningCredentials(x509Key, SecurityAlgorithms.RsaSha256Signature);

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            handler.SetDefaultTimesOnTokenCreation = false;
            JwtSecurityToken token = handler.CreateJwtSecurityToken(
                subject: subject,
                issuedAt: DateTime.UtcNow,
                signingCredentials: signingCredentials);

            return token;
        }
        public static JwtSecurityToken Sign(RsaSecurityKey rsaKey, IEnumerable<Claim> claims)
        {
            var subject = new ClaimsIdentity(claims);

            SigningCredentials signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256Signature);

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            handler.SetDefaultTimesOnTokenCreation = false;
            JwtSecurityToken token = handler.CreateJwtSecurityToken(
                subject: subject,
                issuedAt: DateTime.UtcNow,
                signingCredentials: signingCredentials);

            return token;
        }
    }
}