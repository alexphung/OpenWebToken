using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Routing;

namespace AZURE.API.OWTSERVICE
{
    /// <summary>
    /// This is part of the Web Api Initial Registration process.
    /// </summary>
    public class WebApiApplication : System.Web.HttpApplication
    {
        /// <summary>
        /// This method are auto triggered to run on application startup.
        /// We utilize this initial method to register all external application that
        /// may get imported externally in the "Areas" section of the current application
        /// after it been published.
        /// </summary>
        protected void Application_Start()
        {
            GlobalConfiguration.Configure(WebApiConfig.Register);

            // Required code to allow the current application to recognize any external
            // application codes that mayb reside in the "Areas" section of the current
            // application.
            AreaRegistration.RegisterAllAreas();
        }
    }
}
