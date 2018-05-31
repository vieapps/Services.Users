#region Related components
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

using Microsoft.AspNetCore.Http;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.Users
{
	public static class Utils
	{
		public static string CurrentLanguage
		{
			get
			{
				var language = Global.CurrentHttpContext.Session.Get<string>("Language");
				if (string.IsNullOrWhiteSpace(language))
				{
					language = "vi-VN";
					Global.CurrentHttpContext.Session.Add("Language", language);
				}
				return language;
			}
		}

		public static string CurrentUrl
		{
			get
			{
				var url = Global.CurrentHttpContext.GetRequestUrl(true, true);
				if (url.EndsWith("/"))
					url += "home";
				var query = $"?s={Global.CurrentHttpContext.Session.Id.Encrypt(Global.EncryptionKey).ToBase64Url(true)}";
				Global.CurrentHttpContext.GetRequestUri()
					.ParseQuery(q =>
					{
						q.Remove("s");
						q.Remove("language");
					})
					.ForEach(kvp => query += $"&{kvp.Key}={kvp.Value.UrlEncode()}");
				return url + query;
			}
		}

		public static string GetUrl(string view, string language = null)
		{
			return $"/{view ?? "home"}?s={Global.CurrentHttpContext.Session.Id.Encrypt(Global.EncryptionKey).ToBase64Url(true)}&language={language ?? Utils.CurrentLanguage}";
		}
	}
}