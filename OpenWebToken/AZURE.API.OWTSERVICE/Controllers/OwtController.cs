using AZURE.API.OWTSERVICE.Filter;
using AZURE.API.OWTSERVICE.Models;
using AZURE.API.OWTSERVICE.Utilities;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Web.Http;

namespace AZURE.API.OWTSERVICE.Controllers
{
    /// <summary>
    /// The Open Web Token Controller that handle all incoming web request to be service.
    /// </summary>
    [RoutePrefix("api/v1/owt")]
    public class OwtController : ApiController
    {         
        /// <summary>
        /// This web method allow the client user or client application to request a web token after they have been successfully Authenticated.
        /// Note: The Client are responsible for making this request to retrieve a web token and retain it in memory or somewhere on the
        /// client side. Thus, the client will be responsible for retaining this token and pass this token in through the 
        /// HTTP Request Header to get validated against when trying to access or consume specific web service method created.
        /// </summary>
        [HttpPost]
        [OwtAuthorization]
        [Authorize(Roles = "InAllowableCallList")]
        [Route("GenerateOwtToken")]
        public HttpResponseMessage GenerateOwtToken([FromBody] OwtPayloadContract owtPayloadContract)
        {
            HttpResponseMessage resMsg = null;

            // Log the Request Contract Payload
            Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"[{Helper.ServerIP(Request.Headers.Host)}] [GenerateWebToken:{owtPayloadContract}]");

            try
            {
                // Need to Create the Signing Credentials With the Encrypted Public Key.
                var securityKey = File.ReadAllText(ConfigurationManager.AppSettings["EncryptedPublicKey"])
                                                                        .Replace("-----BEGIN PUBLIC KEY-----\n", "")
                                                                        .Replace("\n-----END PUBLIC KEY-----\n", "");

                var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));
                var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256Signature);
                var header = new JwtHeader(signingCredentials);
                
                var payload = new JwtPayload(   // Issuer - String
                                                owtPayloadContract.Issuer,
                                                // Audience - String
                                                owtPayloadContract.Audience,
                                                // Claims - IEnumerable<Claims>       
                                                new List<Claim>()
                                                {
                                                    new Claim(ClaimTypes.Uri, owtPayloadContract.URI),
                                                    new Claim(ClaimTypes.Actor, owtPayloadContract.Actor),
                                                    new Claim(ClaimTypes.Role, owtPayloadContract.Role),
                                                    new Claim(ClaimTypes.Sid, owtPayloadContract.SID),
                                                    new Claim(ClaimTypes.Name, owtPayloadContract.Name),
                                                    new Claim(ClaimTypes.NameIdentifier, owtPayloadContract.EmployeeId),
                                                    new Claim(ClaimTypes.Dns, owtPayloadContract.DNS),
                                                    new Claim(ClaimTypes.Email, owtPayloadContract.Email),
                                                    new Claim(ClaimTypes.Hash, owtPayloadContract.MacAddress),
                                                    new Claim(ClaimTypes.Locality, owtPayloadContract.IpAddress)
                                                },
                                                // Not Before - DateTime?
                                                owtPayloadContract.NotBefore,
                                                // Expires - DateTime?       
                                                owtPayloadContract.Expires,
                                                // Issued At - DateTime?
                                                owtPayloadContract.IssuedAt
                                            ); // End of JwtPayLoad Paramaters 

                var secToken = new JwtSecurityToken(header, payload);
                var handler = new JwtSecurityTokenHandler();
                var tokenString = handler.WriteToken(secToken);

                // Log the token that was generated.
                Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"[{Helper.ServerIP(Request.Headers.Host)}] [JSON_WEB_TOKEN:{(!string.IsNullOrEmpty(tokenString) ? "CREATED" : "NULL|EMPTY")}]");

                resMsg = Request.CreateResponse(HttpStatusCode.Accepted, tokenString);
            }
            catch (Exception ex)
            {
                Helper.LogData(ConfigurationManager.AppSettings["ExceptionLog"], $"[{Helper.ServerIP(Request.Headers.Host)}] [GenerateJwtToken: {ex.Message}]");
                resMsg = Request.CreateResponse(HttpStatusCode.NotAcceptable, ex);
            }

            return resMsg;
        }

        /// <summary>
        /// Only allowable Host Request with a valid Token can proceed with executing this validation method.
        /// This will allow the client to validate the JSON Web Token by Get-Method which requires the client to provide the
        /// JSON Web Token via the Request Header. 
        /// Example in the Header -- Authorization: Bearer [ENCRYPTED_JSON_WEB_TOKEN]
        /// </summary>
        /// <returns>HttpResponseMessage - a "True" or "False" message if the token failed the validation.</returns>
        [HttpPost]
        [OwtAuthorization]
        [Authorize(Roles = "InAllowableCallList")]
        [Route("InValidateToken")]
        public HttpResponseMessage InValidateToken()
        {
            HttpResponseMessage resMsg = null;
            JwtPayload payload = null;

            try
            {
                bool isValid = false;

                var securityKey = File.ReadAllText(ConfigurationManager.AppSettings["EncryptedPublicKey"])
                                                                          .Replace("-----BEGIN PUBLIC KEY-----\n", "")
                                                                          .Replace("\n-----END PUBLIC KEY-----\n", "");

                var jsonWebToken = Helper.GetJsonWebTokenFromRequestHeader(Request);
                if (!string.IsNullOrEmpty(jsonWebToken))
                {
                    SecurityToken validatedToken = Helper.GetValidatedToken(jsonWebToken, securityKey);
                    if (validatedToken != null)
                    {
                        isValid = true;
                        payload = (validatedToken as JwtSecurityToken).Payload;

                        resMsg = Request.CreateResponse(HttpStatusCode.Accepted, isValid.ToString());
                    }
                    else
                    {
                        isValid = false;
                        resMsg = Request.CreateResponse(HttpStatusCode.Accepted, isValid.ToString());
                    }
                }
                else
                {
                    resMsg = Request.CreateResponse(HttpStatusCode.Accepted, isValid.ToString());
                }

                // Log the Token that are being Invalidate Against and the result Status.
                Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"[{Helper.ServerIP(Request.Headers.Host)}] [INVALIDATE_TOKEN: {isValid.ToString()} | JSON_WEB_TOKEN:{(!string.IsNullOrEmpty(jsonWebToken) ? "EXIST" : "NOT EXIST")}]");
            }
            catch (Exception ex)
            {
                Helper.LogData(ConfigurationManager.AppSettings["ExceptionLog"], $"[{Helper.ServerIP(Request.Headers.Host)}] [INVALIDATE_TOKEN: {ex.Message}]");
                resMsg = Request.CreateResponse(HttpStatusCode.NotAcceptable, ex);
            }

            return resMsg;
        }

        /// <summary>
        /// Only allowable Host Request with a valid Token can proceed with getting or extracting the Payload.
        /// </summary>
        /// <returns>HttpResponseMessage - contain the JwtPayload.</returns>
        [HttpPost]
        [OwtAuthorization]
        [Authorize(Roles = "InAllowableCallList")]
        [Route("GetPayloadFromToken")]
        public HttpResponseMessage GetPayloadFromToken()
        {
            HttpResponseMessage resMsg = null;
            JwtPayload payload = null;

            try
            {

                var securityKey = File.ReadAllText(ConfigurationManager.AppSettings["EncryptedPublicKey"])
                                                                          .Replace("-----BEGIN PUBLIC KEY-----\n", "")
                                                                          .Replace("\n-----END PUBLIC KEY-----\n", "");

                var jsonWebToken = Helper.GetJsonWebTokenFromRequestHeader(Request);
                if (!string.IsNullOrEmpty(jsonWebToken))
                {
                    SecurityToken validatedToken = Helper.GetValidatedToken(jsonWebToken, securityKey);
                    if (validatedToken != null)
                    {
                        payload = (validatedToken as JwtSecurityToken).Payload;

                        resMsg = Request.CreateResponse(HttpStatusCode.Accepted, payload);                        
                    }
                    else
                    {
                        resMsg = Request.CreateResponse(HttpStatusCode.Accepted, payload);
                    }
                }
                else
                {
                    resMsg = Request.CreateResponse(HttpStatusCode.BadRequest, @"Token does not exist.");

                    // Log message for non-existing token.
                    Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"[{Helper.ServerIP(Request.Headers.Host)}] [GetPayloadFromToken: Token does not exist.]");
                }

                // Log the Token that are being Invalidate Against and the result payload.
                Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"[{Helper.ServerIP(Request.Headers.Host)}] [GetPayloadFromToken: CALLED | JSON_WEB_TOKEN: {(!string.IsNullOrEmpty(jsonWebToken) ? "EXIST" : "NOT EXIST")}]");
            }
            catch (Exception ex)
            {
                Helper.LogData(ConfigurationManager.AppSettings["ExceptionLog"], $"[{Helper.ServerIP(Request.Headers.Host)}] [GetPayloadFromToken: {ex.Message}]");
                resMsg = Request.CreateResponse(HttpStatusCode.NotAcceptable, ex);
            }

            return resMsg;
        }

    }
}
