using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Configuration;
using System.IO;
using System.Text;
using System.Net.Http;
using System.Linq;
using System.Net;

namespace AZURE.API.OWTSERVICE.Utilities
{
    /// <summary>
    /// This Helper object is create to hold any common utility functions that can refactored from
    /// the original implementation to simplify the process for code maintenability.
    /// </summary>
    public static class Helper
    {
        /// <summary>
        /// Help to dereference hostname to IP Address.
        /// </summary>
        /// <param name="hostName"></param>
        /// <returns></returns>
        public static string ServerIP(string hostName)
        {
            string _serverIp = (string.IsNullOrEmpty(hostName) ? Dns.GetHostName() : hostName);
            _serverIp = Dns.GetHostAddresses(hostName)[0].ToString();
                
            return _serverIp;
        }

        /// <summary>
        /// This method will take in the encrypted json web token and the security key that was used
        /// to encrypted the encrypted Json Web Token. It will validates the Json Web Token and return
        /// the decrypted Security Token to the caller. 
        /// Note To Developer, After the decrypted Security Token is created successfully you can extact
        /// the Payload using the JwtSecurityToken.
        /// </summary>
        /// <param name="encryptedJsonWebToken"></param>
        /// <param name="securityKey"></param>
        /// <returns>SecurityToken</returns>
        public static SecurityToken GetValidatedToken(string encryptedJsonWebToken, string securityKey)
        {
            SecurityToken validatedToken = null;

            try
            {
                // Hash of our security key
                var publicSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));

                string[] audiences = ConfigurationManager.AppSettings["AudienceList"].Split('|');
                string[] issuers = ConfigurationManager.AppSettings["IssuerList"].Split('|');

                // Clean the list of Audiences from the configurable Values.
                for(int i = 0; i < audiences.Length; i++)
                {
                    audiences[i] = audiences[i].Trim();
                }

                // Clean the list of Issuers from the configurable Values.
                for (int i = 0; i < issuers.Length; i++)
                {
                    issuers[i] = issuers[i].Trim();
                }

                // Define and Specified the Validation Parameters
                var tokenValidationParameters = new TokenValidationParameters()
                {
                    ValidAudiences = audiences,
                    ValidIssuers = issuers,
                    IssuerSigningKey = publicSigningKey,
                    RequireExpirationTime = true,
                };

                // Decrypt the JSON Web Token into the SecurityToken.
                var tokenHandler = new JwtSecurityTokenHandler();
                // This validatToken mehtod call will throw an ArgumentNullException if the method parameter
                // cannot be evaluated succesffully. Hence, we are wrapping this entire security process
                // in the try-catch block to handle this exception gracefully.
                // This ValidateToken method will first validate the token itself using the signing key to verify
                // if this token are tempered with in anyway before actually going through another process of validation
                // against the tokenValidationParameters that are defined.
                tokenHandler.ValidateToken(encryptedJsonWebToken, tokenValidationParameters, out validatedToken);
            }
            catch (Exception ex)
            {
                // Note: We need to set the validatedTOken to NULL if an Excpetion is thrown and it mostly mean something
                // is wrong with the Json Web Token, could be corruption or if it's been tampered with. We don't know all
                // the exact Exception that might occurs so we will have handle the base Exception for all that might occur.
                // We should probably do something loggging inthe future to document and track this unknow exception and just 
                // let it gracefully fall-through.
                validatedToken = null;
                     
                LogData(ConfigurationManager.AppSettings["ExceptionLog"], $"[{Helper.ServerIP(Dns.GetHostName())}] [GetValidatedToken: {ex.Message}]");
            }

            return validatedToken;
        }

        /// <summary>
        /// This method will take in the HttpRequestMessage object from a web request and look at the 
        /// header of the Request to for a Json Web Token if it's available it will extract and return 
        /// the token otherwise it will return an empty string value.
        /// </summary>
        /// <param name="req"></param>
        /// <returns>string representing the Json Web Token (JWT)</returns>
        public static string GetJsonWebTokenFromRequestHeader(HttpRequestMessage req)
        {
            var jsonWebToken = string.Empty;

            if (req.Headers.Contains("Authorization"))
            {
                var authHeader = req.Headers.GetValues("Authorization").First();
                var authArray = authHeader.Split(' ');
                if (authArray.Length == 2)
                {
                    if (authArray[0].ToLowerInvariant().Equals("bearer"))
                    {
                        // Our JWT is in index = 1 because the Request contain --> Authorization: bearer <JSON_WEB_TOKEN>
                        jsonWebToken = authArray[1];
                    }
                }
            }

            return jsonWebToken;
        }

        /// <summary>
        /// Takes in the File Path and create a log file correspond to today date and keep appending to it.
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="data"></param>
        public static void LogData(string filePath, string data)
        {
            string fileName = $"{DateTime.UtcNow.ToLocalTime().ToString("MMMM")}-{DateTime.UtcNow.ToLocalTime().Day}-{DateTime.UtcNow.ToLocalTime().Year}.txt";
            string fullPath = $"{filePath}\\{DateTime.UtcNow.ToLocalTime().Year}{DateTime.UtcNow.ToLocalTime().ToString("MMMM")}";
            
            try
            {
                // Ensures we have the directory path created if it doesn't exist.
                // If the fullPath exist this method will do nothing.
                System.IO.Directory.CreateDirectory(fullPath);
                fullPath = $"{fullPath}\\{fileName}";

                if (!File.Exists($"{fullPath}"))
                {
                    File.AppendAllText(fullPath, $"[{DateTime.UtcNow.ToLocalTime()}]: {data}\n");
                }
                else
                {
                    File.AppendAllText(fullPath, $"[{DateTime.UtcNow.ToLocalTime()}]: {data}\n");
                }
            }
            catch (Exception ex)
            {
                File.AppendAllText($"~/App_Data/{fileName}", $"[{DateTime.UtcNow.ToLocalTime()}]: Unable to log to original designated log location.\n{ex.Message}");
            }
        }
    }
}