using System.Net.Http.Headers;
using System.Web.Http;

namespace AZURE.API.OWTSERVICE
{
    /// <summary>
    /// This class object control the configuration of the Web API such as routing and data format.
    /// </summary>
    public static class WebApiConfig
    {
        /// <summary>
        /// This method contains the registration of the configuration for the Web API.
        /// </summary>
        /// <param name="config"></param>
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services
            config.Formatters.Remove(config.Formatters.XmlFormatter);
            config.Formatters.JsonFormatter.SupportedMediaTypes.Add(new MediaTypeHeaderValue("application/json"));

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "VersionApi",
                routeTemplate: "api/v1/{controller}",
                defaults: new { id = RouteParameter.Optional }
            );
            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}
