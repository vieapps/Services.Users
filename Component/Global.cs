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
	public static class Global
	{

		#region Caching mechanism
		static int _CacheTime = 0;

		/// <summary>
		/// Gets the default time for caching data
		/// </summary>
		internal static int CacheTime
		{
			get
			{
				if (Global._CacheTime < 1)
					try
					{
						Global._CacheTime = ConfigurationManager.AppSettings["CacheTime"].CastAs<int>();
					}
					catch
					{
						Global._CacheTime = 30;
					}
				return Global._CacheTime;
			}
		}

		static CacheManager _Cache = new CacheManager("VIEApps-Services-Users", "Sliding", Global.CacheTime);

		/// <summary>
		/// Gets the default cache storage
		/// </summary>
		public static CacheManager Cache { get { return Global._Cache; } }
		#endregion

	}

	//  --------------------------------------------------------------------------------------------

	[Serializable]
	[Repository]
	public abstract class DataAccessor<T> : RepositoryBase<T> where T : class { }
}