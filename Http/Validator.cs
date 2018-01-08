#region Related components
using System;
using System.Threading.Tasks;
using System.Web;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.Users
{
	internal static class Validator
	{
		internal static async Task ProcessRequestAsync(HttpContext context)
		{
			try
			{
				// check
				if (!context.Request.HttpMethod.Equals("GET"))
					throw new MethodNotAllowedException(context.Request.HttpMethod);
					
				// prepare
				var remoteIsAuthenticated = false;
				try
				{
					remoteIsAuthenticated = context.Request.QueryString["aut"] != null 
						? context.Request.QueryString["aut"].ToBase64(false, true).Decrypt(Base.AspNet.Global.EncryptionKey).IsEndsWith("-ON")
						: false;
				}
				catch { }

				var remoteUserID = "";
				try
				{
					remoteUserID = context.Request.QueryString["uid"] != null
						? context.Request.QueryString["uid"].ToBase64(false, true).Decrypt(Base.AspNet.Global.EncryptionKey)
						: "";
				}
				catch { }

				var remoteUri = context.Request.UrlReferrer != null
					? context.Request.UrlReferrer.AbsoluteUri
					: "";
				try
				{
					remoteUri = context.Request.QueryString["uri"] != null
						? context.Request.QueryString["uri"].ToBase64(false, true).Decrypt(Base.AspNet.Global.EncryptionKey)
						: context.Request.UrlReferrer != null
							? context.Request.UrlReferrer.AbsoluteUri
							: "";
				}
				catch { }

				if (string.IsNullOrWhiteSpace(remoteUri))
					throw new InvalidRequestException();

				remoteUri += (remoteUri.IndexOf("?") > 0 ? "&" : "?") + "x-passport-token=";
				if ((!remoteIsAuthenticated && context.Request.IsAuthenticated) || (remoteIsAuthenticated && !context.Request.IsAuthenticated))
					User.GetPassportToken((context.User as User).ID, context.Request.IsAuthenticated ? Global.GetAuthenticateTicket(context) : "", Global.GetSessionID(context), Global.GetDeviceID(context), Base.AspNet.Global.EncryptionKey, Base.AspNet.Global.JWTKey);

				// register session if already authenticated
				if (context.Request.IsAuthenticated)
				{
					var session = Global.GetSession(context);
					if (!await session.ExistsAsync())
						await Global.CallServiceAsync(session, "users", "session", "GET");
				}

				// response
				if (context.Request.QueryString["rdr"] != null)
					context.Response.Redirect(remoteUri);
				else
				{
					var func = "__" + Global.GetSessionID(context);
					if (context.Request.QueryString["fnc"] != null)
						try
						{
							func = context.Request.QueryString["fnc"].ToBase64(false, true).Decrypt(Base.AspNet.Global.EncryptionKey);
						}
						catch { }
					context.Response.ContentType = "application/javascript";
					await context.Response.Output.WriteAsync("(function(d,t){var p=d.createElement(t);p.async='1';p.src='" + remoteUri + "';var s=d.getElementsByTagName(t)[0];s.parentNode.insertBefore(p,s);})(document,'script');window.setTimeout(function(){try{" + func + "()}catch(e){}},1234);");
				}
			}
			catch (Exception ex)
			{
				context.ShowError(ex);
			}
		}
	}
}