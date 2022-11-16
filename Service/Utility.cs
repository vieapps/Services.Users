#region Related components
using System.Collections.Generic;
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
		public static Cache Cache { get; internal set; }

		public static List<string> OAuths { get; internal set; } = new List<string>();

		public static bool AllowRegister { get; internal set; } = true;

		public static string FilesHttpURI { get; internal set; }

		public static string CaptchaHttpURI { get; internal set; } = $"{Utility.FilesHttpURI}/captchas/";

		public static string AvatarHttpURI { get; internal set; } = $"{Utility.FilesHttpURI}/avatars/";

		public static string ActivateHttpURI { get; internal set; }

		#region Extensions for working with profile
		internal static JObject GetProfileJson(this Profile profile, JObject relatedData = null, bool addRelated = true, bool useBriefInfo = false)
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
						var account = Account.Get<Account>(profile?.ID);
						obj["LastAccess"] = account?.LastAccess;
						obj["Joined"] = account?.Joined;

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

			return json;
		}

		internal static string GetGravatarURI(this Profile profile)
			=> string.IsNullOrWhiteSpace(profile.Email)
				? Utility.FilesHttpURI + "/avatars/default.png"
				: "https://secure.gravatar.com/avatar/" + profile.Email.ToLower().Trim().GetMD5() + "?s=300&d=" + (Utility.FilesHttpURI + "/avatars/default.png").UrlEncode();
		#endregion

	}

	//  --------------------------------------------------------------------------------------------

	[Repository]
	public abstract class Repository<T> : RepositoryBase<T> where T : class { }
}