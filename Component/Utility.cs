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

		static int _CacheTime = 0;

		public static int CacheTime
		{
			get
			{
				if (Utility._CacheTime < 1)
					try
					{
						Utility._CacheTime = UtilityService.GetAppSetting("CacheTime", "30").CastAs<int>();
					}
					catch
					{
						Utility._CacheTime = 30;
					}
				return Utility._CacheTime;
			}
		}

		static CacheManager _Cache = new CacheManager("VIEApps-Services-Books", "Sliding", Utility.CacheTime);

		public static CacheManager Cache { get { return Utility._Cache; } }

	}

	//  --------------------------------------------------------------------------------------------

	[Serializable]
	[Repository]
	public abstract class Repository<T> : RepositoryBase<T> where T : class { }
}