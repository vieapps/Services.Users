﻿#region Related components
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

		static Cache _Cache = new Cache("VIEApps-Services-Users", "Sliding", Utility.CacheTime);

		public static Cache Cache { get { return Utility._Cache; } }

		static string _HttpFilesUri = null;

		internal static string HttpFilesUri
		{
			get
			{
				if (string.IsNullOrWhiteSpace(Utility._HttpFilesUri))
					Utility._HttpFilesUri = UtilityService.GetAppSetting("HttpFilesUri", "https://afs.vieapps.net");
				while (Utility._HttpFilesUri.EndsWith("/"))
					Utility._HttpFilesUri = Utility._HttpFilesUri.Left(Utility._HttpFilesUri.Length - 1);
				return Utility._HttpFilesUri;
			}
		}

	}

	//  --------------------------------------------------------------------------------------------

	[Serializable]
	[Repository]
	public abstract class Repository<T> : RepositoryBase<T> where T : class { }
}