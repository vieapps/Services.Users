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
		public static Cache Cache { get; internal set; }

		public static int CacheTimeOfSessions { get; internal set; } = 180;

		public static string FilesHttpURI { get; internal set; }

		public static string ActivateHttpURI { get; internal set; }

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
				? Utility.FilesHttpURI + "/avatars/default.png"
				: "https://secure.gravatar.com/avatar/" + profile.Email.ToLower().Trim().GetMD5() + "?s=300&d=" + (Utility.FilesHttpURI + "/avatars/default.png").UrlEncode();
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