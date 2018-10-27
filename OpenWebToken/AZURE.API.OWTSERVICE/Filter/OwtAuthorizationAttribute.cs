using AZURE.API.OWTSERVICE.Utilities;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Threading;
using System.Web;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace AZURE.API.OWTSERVICE.Filter
{
     /// <summary> 
     /// This is a wrapper that inherits from AuthorizationFilterAttribute that control authorization
     /// to call the Web API actions.
     /// </summary>
    public class OwtAuthorizationAttribute : AuthorizationFilterAttribute
    {     
        /// <summary>
        /// OnAuthorization - determine if the requestor should be grant permission to call Web API
        /// and assign the appropriate role to the current requestor.
        /// </summary>
        /// <param name="actionContext"></param>
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            try
            {
                var roles = new List<string>();
                string[] hosts = ConfigurationManager.AppSettings["AcceptsRequestFrom"].Split('|');
                List<string> incomingHosts = hosts.ToList<string>();

                var ctx = actionContext.Request.Properties["MS_HttpContext"] as HttpContextWrapper;
                //Took out the condition "&& !incomingHosts.Contains(ctx.Request.UserAgent) "
                string clientName = (!string.IsNullOrEmpty(ctx.Request.UserAgent) ? ctx.Request.UserAgent : string.Empty);
                IPHostEntry iphe = Dns.GetHostEntry(actionContext.Request.Headers.Host);

                Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"Request ctx.Request.UserAgent: {ctx.Request.UserAgent}");
                Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"Request ctx.Request.UserHostAddress: {ctx.Request.UserHostAddress}");
                Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"Request ctx.Request.UserHostName: {ctx.Request.UserHostName}");
                Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"Request Reverse DSN Lookup: {iphe.HostName}");

                if (ctx.Request.UserAgent == ConfigurationManager.AppSettings["DefaultUserAgent"])
                {
                    clientName = string.Empty;
                }
                if (string.IsNullOrEmpty(clientName))
                {
                    string[] dshsDomain = iphe.HostName.Split('.');
                    if(dshsDomain.Length == 4)
                    {
                        clientName = $"{dshsDomain[1]}.{dshsDomain[2]}.{dshsDomain[3]}";
                    }
                    else
                    {
                        clientName = string.Empty;
                    }                  
                }
                
                //Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"[{ctx.Request.UserHostAddress}] [{iphe.HostName}] [{ctx.Request.UserAgent}]");
                
                if (incomingHosts.Contains(clientName))
                {
                    roles.Add("InAllowableCallList");

                    Thread.CurrentPrincipal =
                        HttpContext.Current.User = new GenericPrincipal(
                                                        new GenericIdentity(ConfigurationManager.AppSettings["APPId"]), roles.ToArray());

                    Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"[{ctx.Request.UserHostAddress}] [ACCEPTED_REQUEST: {clientName}]");
                }
                else
                {
                    Helper.LogData(ConfigurationManager.AppSettings["ServiceLog"], $"[{ctx.Request.UserHostAddress}] [REJECTED_REQUEST: {clientName}]");
                }
            }
            catch (Exception ex)
            {
                // Note: We don't know all the exact Exception that might occurs so we will have handle the base Exception for all that might occur.
                // We should probably do some more loggging in the future to document and track this unknow exception and just let it gracefully fall-through.
                Helper.LogData(ConfigurationManager.AppSettings["ExceptionLog"], $"[{Helper.ServerIP(actionContext.Request.Headers.Host)}]  [JwtAuthorizationAttribute: {ex.Message}]");
            }

            base.OnAuthorization(actionContext);
        }        
    }
}