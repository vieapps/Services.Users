#region Related components
using System;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Linq;
using System.Web;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.Core.Listener;
using WampSharp.V2;
using WampSharp.V2.Realm;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.Users
{
	internal static class Finalizer
	{
		internal static async Task ProcessRequestAsync(HttpContext context)
		{
			if (!context.Request.HttpMethod.Equals("GET"))
				context.ShowError(new MethodNotAllowedException(context.Request.HttpMethod));

			else if (context.Request.QueryString["x-passport-token"] == null)
				context.ShowError(new InvalidRequestException());

			else
				try
				{
					// sign out
					Global.SignOut(context);

					// response
					context.Response.Cache.SetNoStore();
					if (context.Request.QueryString["h"] != null)
					{
						context.Response.ContentType = "text/html";
						await context.Response.Output.WriteAsync("<!-- " + Global.GetSessionID(context) + "@" + Global.GetDeviceID(context) + " -->");
					}
					else
					{
						context.Response.ContentType = "application/javascript";
						await context.Response.Output.WriteAsync("/* " + Global.GetSessionID(context) + "@" + Global.GetDeviceID(context) + " */");
					}
				}
				catch (Exception ex)
				{
					context.ShowError(ex);
				}
		}
	}
}