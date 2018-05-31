#region Related components
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.Users
{
    public class HomeController : Controller
    {
        public ViewResult Index()
        {
            return View();
        }
    }
}