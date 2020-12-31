#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Xml.Serialization;
using MsgPack.Serialization;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Converters;
using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	[BsonIgnoreExtraElements, DebuggerDisplay("ID = {ID}, Identity = {AccessIdentity}, Type = {Type}")]
	[Entity(CollectionName = "Accounts", TableName = "T_Users_Accounts", CacheClass = typeof(Utility), CacheName = "Cache", CreateNewVersionWhenUpdated = false)]
	public class Account : Repository<Account>
	{
		public Account() : base() { }

		/// <summary>
		/// Gets or sets the status
		/// </summary>
		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String)]
		[Property(NotNull = true)]
		[Sortable]
		public AccountStatus Status { get; set; } = AccountStatus.Activated;

		/// <summary>
		/// Gets or sets the type
		/// </summary>
		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String)]
		[Property(NotNull = true)]
		[Sortable]
		public AccountType Type { get; set; } = AccountType.BuiltIn;

		/// <summary>
		/// Gets or sets the state that require two-factors authentication
		/// </summary>
		[AsJson]
		public TwoFactorsAuthentication TwoFactorsAuthentication { get; set; } = new TwoFactorsAuthentication();

		/// <summary>
		/// Gets or sets the joined time of the user account
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime Joined { get; set; } = DateTime.Now;

		/// <summary>
		/// Gets or sets the last activity time of the user account
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime LastAccess { get; set; } = DateTime.Now;

		/// <summary>
		/// Gets or sets the type of the OAuth user account, must be string of <see cref="OAuthType">OAuthType</see> when the type of user account is OAuth
		/// </summary>
		[Property(MaxLength = 20, NotNull = true)]
		[Sortable(UniqueIndexName = "Account")]
		public string OAuthType { get; set; } = "";

		/// <summary>
		/// Gets or sets the identity of the mapped user account (when the user account is OAuth and mapped to a built-in user account)
		/// </summary>
		[Property(MaxLength = 32)]
		[Sortable(UniqueIndexName = "Account")]
		public string AccessMapIdentity { get; set; }

		/// <summary>
		/// Gets or sets the identiy of the user account (email address when the user is built-in account, OAuth ID if the user is OAuth account, account with full domain if the user is Windows account)
		/// </summary>
		[Property(MaxLength = 250, NotNull = true)]
		[Sortable(UniqueIndexName = "Account")]
		public string AccessIdentity { get; set; }

		/// <summary>
		/// Gets or sets the key of the user account in (hashed password when the user is built-in account or access token when the user is OAuth account)
		/// </summary>
		[JsonIgnore, XmlIgnore]
		[Property(MaxLength = 250)]
		public string AccessKey { get; set; } = "";

		/// <summary>
		/// Gets or sets the working roles (means working roles of business services) of the user account
		/// </summary>
		[AsJson]
		public Dictionary<string, List<string>> AccessRoles { get; set; } = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

		/// <summary>
		/// Gets or sets the working privileges (means scopes/working privileges of services or services' objects) of the user account
		/// </summary>
		[AsJson]
		public List<Privilege> AccessPrivileges { get; set; } = new List<Privilege>();

		/// <summary>
		/// Gets or sets the collection of sessions of the user account
		/// </summary>
		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public List<Session> Sessions { get; set; }

		[MessagePackIgnore]
		Profile _profile = null;

		[MessagePackIgnore]
		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public Profile Profile => this._profile ?? (this._profile = Profile.Get<Profile>(this.ID));

		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public override string Title { get; set; }

		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public override string SystemID { get; set; }

		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public override string RepositoryID { get; set; }

		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public override string RepositoryEntityID { get; set; }

		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public override Privileges OriginalPrivileges { get; set; }

		public JObject GetAccountJson(bool addStatus = false, string authenticationKey = null)
		{
			var roles = $"{SystemRole.All},{SystemRole.Authenticated}".ToList();
			if (UserIdentity.SystemAdministrators.Contains(this.ID))
				roles.Add(SystemRole.SystemAdministrator.ToString());
			this.AccessRoles?.ForEach(accessRoles => roles = roles.Concat(accessRoles).ToList());

			var json = new JObject
			{
				{ "ID", this.ID },
				{ "Roles", roles.Distinct(StringComparer.OrdinalIgnoreCase).ToJArray() },
				{ "Privileges", (this.AccessPrivileges ?? new List<Privilege>()).ToJArray(privilege => privilege.ToJson()) }
			};

			if (addStatus)
			{
				json["Status"] = this.Status.ToString();
				json["TwoFactorsAuthentication"] = this.TwoFactorsAuthentication.ToJson(authenticationKey ?? UtilityService.GetAppSetting("Keys:Authentication"));
			}

			return json;
		}

		/// <summary>
		/// Gets an user account by identity
		/// </summary>
		/// <param name="identity"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task<Account> GetByIdentityAsync(string identity, AccountType type = AccountType.BuiltIn, CancellationToken cancellationToken = default)
			=> Account.GetAsync<Account>(Filters<Account>.And(Filters<Account>.Equals("AccessIdentity", identity), Filters<Account>.Equals("Type", $"{type}")), null, null, cancellationToken);

		public async Task<List<Session>> GetSessionsAsync(CancellationToken cancellationToken = default)
			=> this.Sessions = await Session.FindAsync(Filters<Session>.Equals("UserID", this.ID), Sorts<Session>.Descending("ExpiredAt"), 0, 1, null, cancellationToken).ConfigureAwait(false);

		#region Generate password
		/// <summary>
		/// Generates a password for storing
		/// </summary>
		/// <param name="id">The string that presents the identity of an account</param>
		/// <param name="password">The string that presents the password of an account</param>
		/// <returns></returns>
		public static string GeneratePassword(string id, string password)
			=> string.IsNullOrWhiteSpace(id) || !id.IsValidUUID() || string.IsNullOrWhiteSpace(password)
				? throw new InformationInvalidException()
				: password.GenerateHashPassword(id.Trim(), password.Trim()).HexToBytes().ToBase64Url();

		/// <summary>
		/// Generates a random password
		/// </summary>
		/// <param name="email">The email address</param>
		/// <returns></returns>
		public static string GeneratePassword(string email = null)
		{
			var pos = (email ?? "").IndexOf("-");
			if (pos < 0)
				pos = (email ?? "").IndexOf("_");
			if (pos < 0)
				pos = (email ?? "").IndexOf(".");
			return CaptchaService.GenerateRandomCode(true, true).GetCapitalizedFirstLetter()
				+ (pos > 0 ? email.Substring(pos, 1) : "#") + OTPService.GeneratePassword(UtilityService.NewUUID + (email ?? ""))
				+ CaptchaService.GenerateRandomCode().GetCapitalizedFirstLetter();
		}
		#endregion

	}

	#region Two-Factors Authentication
	public class TwoFactorsAuthentication
	{
		public TwoFactorsAuthentication()
		{
			this.Required = false;
			this.Settings = new List<TwoFactorsAuthenticationSetting>();
		}

		public JArray GetProvidersJson(string authenticationKey) => this.Settings?.ToJArray(s => s.ToJson(authenticationKey)) ?? new JArray();

		public JObject ToJson(string authenticationKey, Action<JObject> onPreCompleted = null)
		{
			var json = new JObject
			{
				{ "Required",  this.Required },
				{ "Providers", this.GetProvidersJson(authenticationKey) }
			};
			onPreCompleted?.Invoke(json);
			return json;
		}

		public bool Required { get; set; }

		public List<TwoFactorsAuthenticationSetting> Settings { get; set; }
	}

	public class TwoFactorsAuthenticationSetting
	{
		public TwoFactorsAuthenticationSetting()
		{
			this.Type = TwoFactorsAuthenticationType.App;
			this.Stamp = "";
			this.Time = DateTime.Now.ToUnixTimestamp();
		}

		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String)]
		public TwoFactorsAuthenticationType Type { get; set; }

		public string Stamp { get; set; }

		public long Time { get; set; }

		public JObject ToJson(string authenticationKey, Action<JObject> onPreCompleted = null)
		{
			var json = new JObject
			{
				{ "Label", this.Type.Equals(TwoFactorsAuthenticationType.App) ? "Authenticator" : $"SMS (******{this.Stamp.Right(4)})" },
				{ "Type", this.Type.ToString() },
				{ "Time", this.Time.FromUnixTimestamp() },
				{ "Info", $"{this.Type}|{this.Stamp}|{this.Time}".Encrypt(authenticationKey, true) }
			};
			onPreCompleted?.Invoke(json);
			return json;
		}
	}
	#endregion

}