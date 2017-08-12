#region Related components
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	public static class Utility
	{

		#region Get setting/parameter of the app
		public static string GetAppSetting(string name, string defaultValue = null)
		{
			var value = string.IsNullOrEmpty(name)
				? null
				: ConfigurationManager.AppSettings["vieapps:" + name.Trim()];
			return string.IsNullOrEmpty(value)
				? defaultValue
				: value;
		}

		public static string GetAppParameter(string name, NameValueCollection header, NameValueCollection query, string defaultValue = null)
		{
			var value = string.IsNullOrWhiteSpace(name)
				? null
				: header?[name];
			if (value == null)
				value = string.IsNullOrWhiteSpace(name)
				? null
				: query?[name];
			return string.IsNullOrEmpty(value)
				? defaultValue
				: value;
		}
		#endregion

		#region Caching mechanism
		static int _CacheTime = 0;

		/// <summary>
		/// Gets the default time for caching data
		/// </summary>
		internal static int CacheTime
		{
			get
			{
				if (Utility._CacheTime < 1)
					try
					{
						Utility._CacheTime = Utility.GetAppSetting("CacheTime", "30").CastAs<int>();
					}
					catch
					{
						Utility._CacheTime = 30;
					}
				return Utility._CacheTime;
			}
		}

		static CacheManager _Cache = new CacheManager("VIEApps-Services-Users", "Sliding", Utility.CacheTime);

		/// <summary>
		/// Gets the default cache storage
		/// </summary>
		public static CacheManager Cache { get { return Utility._Cache; } }
		#endregion

	}

	//  --------------------------------------------------------------------------------------------

	[Serializable]
	[Repository]
	public abstract class Repository<T> : RepositoryBase<T> where T : class { }
}