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
	public static class Initializer
	{
		public static async Task ProcessRequestAsync(HttpContext context)
		{
			if (!context.Request.HttpMethod.Equals("GET") || context.Request.QueryString["x-passport-token"] == null)
				Global.ShowError(context, new InvalidRequestException());

			else
				try
				{
					// parse
					var token = User.ParseJSONWebToken(context.Request.QueryString["x-passport-token"], Global.AESKey, Global.GenerateJWTKey());
					var ticket = User.ParseAuthenticateTicket(token.Item3, Global.RSA, Global.AESKey);
					var user = ticket.Item1;
					var sessionID = ticket.Item2;
					var deviceID = ticket.Item3;

					// validate
					var session = Global.GetSession(context);
					session.User = user;
					session.SessionID = sessionID;
					session.DeviceID = deviceID;
					if (!await session.ExistsAsync())
						throw new SessionNotFoundException();

					// assign user credential
					context.User = new UserPrincipal(user);

					var persistent = "persistent".Encrypt().Url64Encode().Equals(context.Request.QueryString["persistent"]);
					var authCookie = new HttpCookie(System.Web.Security.FormsAuthentication.FormsCookieName)
					{
						Value = User.GetAuthenticateTicket(user.ID, sessionID, deviceID, token.Item3, System.Web.Security.FormsAuthentication.Timeout.Minutes, persistent),
						HttpOnly = true
					};
					if (persistent)
						authCookie.Expires = DateTime.Now.AddDays(14);
					context.Response.SetCookie(authCookie);

					// assign session/device identity
					Global.SetSessionID(context, sessionID);
					Global.SetDeviceID(context, deviceID);

					// response
					context.Response.Cache.SetNoStore();
					context.Response.ContentType = "application/javascript";
					await context.Response.Output.WriteAsync("/* " + sessionID + "@" + deviceID + " */");
				}
				catch (Exception ex)
				{
					Global.ShowError(context, ex);
				}
		}
	}
}