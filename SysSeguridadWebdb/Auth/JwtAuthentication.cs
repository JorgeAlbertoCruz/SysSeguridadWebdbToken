﻿// Agregar las siguientes librerias
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SysSeguridadWebdb.Models;

namespace SysSeguridadWebdb.Auth
{
    public class JwtAuthentication
    {
        private readonly string _key;

        public JwtAuthentication(string key)
        {
            _key = key;
        }

        /// <summary>
        /// Método para encriptar strings con MD5
        /// </summary>
        /// <param name="pUsuario"></param>
        /// <returns></returns>
        public string EncriptarMD5(string pUsuario)
        {

            
            using (var md5 = MD5.Create())
            {
                var result = md5.ComputeHash(Encoding.ASCII.GetBytes(pUsuario));
                var strEncriptar = "";
                for (int i = 0; i < result.Length; i++)
                    strEncriptar += result[i].ToString("x2").ToLower();
                pUsuario = strEncriptar;
            }
            return pUsuario;
        }

        public string Authenticate(Usuario pUsuario)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(_key); // clave de al menos 256 bits

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
            new Claim(ClaimTypes.Name, pUsuario.Login)
                }),
                Expires = DateTime.UtcNow.AddHours(8),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(tokenKey),
                    SecurityAlgorithms.HmacSha256Signature
                )
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}