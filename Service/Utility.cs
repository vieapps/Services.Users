#region Related components
using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Threading;
using System.Threading.Tasks;
using System.Configuration;
using System.Xml.Serialization;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using MongoDB.Bson.Serialization.Attributes;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	public static class Utility
	{

		#region Caching mechanism
		static Utility()
		{
			Task.Run(async () =>
			{
				await Task.Delay(123).ConfigureAwait(false);
				Utility.GetCache();
			}).ConfigureAwait(false);
		}

		internal static Cache GetCache()
		{
			return Utility.Cache ?? (Utility.Cache = new Cache("VIEApps-Services-Users", UtilityService.GetAppSetting("Cache:ExpirationTime", "30").CastAs<int>(), false, UtilityService.GetAppSetting("Cache:Provider"), Logger.GetLoggerFactory()));
		}

		internal static Cache Cache { get; private set; }
		#endregion

		#region Files URI
		static string _FilesHttpUri = null;

		internal static string FilesHttpUri
		{
			get
			{
				if (string.IsNullOrWhiteSpace(Utility._FilesHttpUri))
					Utility._FilesHttpUri = UtilityService.GetAppSetting("HttpUri:Files", "https://afs.vieapps.net");
				while (Utility._FilesHttpUri.EndsWith("/"))
					Utility._FilesHttpUri = Utility._FilesHttpUri.Left(Utility._FilesHttpUri.Length - 1);
				return Utility._FilesHttpUri;
			}
		}
		#endregion

		#region Extensions for working with profile
		internal static JObject GetProfileJson(this Profile profile, JObject relatedData = null, bool doNormalize = true, bool addRelated = true, bool useBriefInfo = false)
		{
			var json = useBriefInfo
				? new JObject
				{
					{ "ID", profile.ID },
					{ "Name", profile.Name },
					{ "Avatar", profile.Avatar },
					{ "Gravatar", profile.GetGravatarURI() },
				}
				: profile.ToJson(false, obj =>
				{
					if (addRelated)
					{
						var account = Account.Get<Account>(profile.ID);
						obj["LastAccess"] = account.LastAccess;
						obj["Joined"] = account.Joined;

						if (relatedData != null)
							foreach (var kvp in relatedData)
								try
								{
									if (!kvp.Key.IsEquals("ID"))
										obj[kvp.Key] = kvp.Value;
								}
								catch { }
					}
				});

			if (doNormalize)
			{
				json["Email"] = !string.IsNullOrWhiteSpace(profile.Email)
					? profile.Email.Left(profile.Email.IndexOf("@")) + "@..."
					: "";
				json["Mobile"] = !string.IsNullOrWhiteSpace(profile.Mobile)
					? profile.Mobile.Trim().Replace(" ", "").Right(4).PadLeft(10, 'x')
					: "";
			}

			return json;
		}

		internal static string GetGravatarURI(this Profile profile)
			=> string.IsNullOrWhiteSpace(profile.Email)
				? Utility.FilesHttpUri + "/avatars/default.png"
				: "https://secure.gravatar.com/avatar/" + profile.Email.ToLower().Trim().GetMD5() + "?s=300&d=" + (Utility.FilesHttpUri + "/avatars/default.png").UrlEncode();
		#endregion

	}

	//  --------------------------------------------------------------------------------------------

	[Serializable]
	[Repository]
	public abstract class Repository<T> : RepositoryBase<T> where T : class
	{
		[JsonIgnore, XmlIgnore, BsonIgnore, Ignore]
		public override string ServiceName => ServiceBase.ServiceComponent.ServiceName;
	}
}