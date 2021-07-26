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
		[Property(NotNull = true), Sortable(IndexName = "Statistics")]
		public AccountStatus Status { get; set; } = AccountStatus.Activated;

		/// <summary>
		/// Gets or sets the type
		/// </summary>
		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String)]
		[Property(NotNull = true), Sortable(UniqueIndexName = "Account")]
		public AccountType Type { get; set; } = AccountType.BuiltIn;

		/// <summary>
		/// Gets or sets the state that require two-factors authentication
		/// </summary>
		[AsJson]
		public TwoFactorsAuthentication TwoFactorsAuthentication { get; set; } = new TwoFactorsAuthentication();

		/// <summary>
		/// Gets or sets the joined time of the account
		/// </summary>
		[Sortable(IndexName = "Statistics")]
		public DateTime Joined { get; set; } = DateTime.Now;

		/// <summary>
		/// Gets or sets the last activity time of the account
		/// </summary>
		[Sortable(IndexName = "Statistics")]
		public DateTime LastAccess { get; set; } = DateTime.Now;

		/// <summary>
		/// Gets or sets the type of the OAuth account, must be string of <see cref="OAuthType">OAuthType</see> when the type of account is OAuth
		/// </summary>
		[Property(MaxLength = 20)]
		[Sortable(UniqueIndexName = "Account")]
		public string OAuthType { get; set; }

		/// <summary>
		/// Gets or sets the identity of the mapped account
		/// </summary>
		[Property(MaxLength = 32)]
		[Sortable(UniqueIndexName = "Account")]
		public string AccessMapIdentity { get; set; }

		/// <summary>
		/// Gets or sets the identiy of the account (Built-In: email/phone number, OAuth: ID if the account, Windows: account with full domain)
		/// </summary>
		[Property(MaxLength = 250, NotNull = true)]
		[Sortable(UniqueIndexName = "Account")]
		public string AccessIdentity { get; set; }

		/// <summary>
		/// Gets or sets the key of the account in (hashed password when the acccout is built-in account or access token when the acccount is OAuth account)
		/// </summary>
		[JsonIgnore, XmlIgnore]
		[Property(MaxLength = 250)]
		public string AccessKey { get; set; }

		/// <summary>
		/// Gets or sets the working roles (means working roles of business services) of the account
		/// </summary>
		[AsJson]
		public Dictionary<string, List<string>> AccessRoles { get; set; } = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

		/// <summary>
		/// Gets or sets the working privileges (means scopes/working privileges of services or services' objects) of the account
		/// </summary>
		[AsJson]
		public List<Privilege> AccessPrivileges { get; set; } = new List<Privilege>();

		/// <summary>
		/// Gets or sets the collection of sessions of the account
		/// </summary>
		[MessagePackIgnore]
		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public List<Session> Sessions { get; set; }

		[MessagePackIgnore]
		Profile _profile = null;

		/// <summary>
		/// Gets the account profile that belong to this account
		/// </summary>
		[MessagePackIgnore]
		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public Profile Profile => this._profile ?? (this._profile = Profile.Get<Profile>(this.ID));

		[MessagePackIgnore]
		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public override string Title { get; set; }

		[MessagePackIgnore]
		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public override string SystemID { get; set; }

		[MessagePackIgnore]
		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public override string RepositoryID { get; set; }

		[MessagePackIgnore]
		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public override string RepositoryEntityID { get; set; }

		[MessagePackIgnore]
		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public override Privileges OriginalPrivileges { get; set; }

		/// <summary>
		/// Gets the orginal account that this account was mapped to
		/// </summary>
		[MessagePackIgnore]
		[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
		public Account Original => this.GetOriginal();

		/// <summary>
		/// Gets the orginal account that this account was mapped to
		/// </summary>
		/// <returns></returns>
		public Account GetOriginal()
			 => string.IsNullOrWhiteSpace(this.AccessMapIdentity) || !this.AccessMapIdentity.IsValidUUID() 
				? null
				: Account.Get<Account>(this.AccessMapIdentity);

		/// <summary>
		/// Gets the orginal account that this account was mapped to
		/// </summary>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public Task<Account> GetOriginalAsync(CancellationToken cancellationToken = default)
			 => string.IsNullOrWhiteSpace(this.AccessMapIdentity) || !this.AccessMapIdentity.IsValidUUID()
				? Task.FromResult<Account>(null)
				: Account.GetAsync<Account>(this.AccessMapIdentity, cancellationToken);

		public JObject GetAccountJson(bool addStatus = false, string authenticationKey = null)
		{
			var roles = new[] { $"{SystemRole.All}", $"{SystemRole.Authenticated}" }.ToList();
			if (UserIdentity.SystemAdministrators.Contains(this.ID))
				roles.Add($"{SystemRole.SystemAdministrator}");
			this.AccessRoles?.ForEach(accessRoles => roles = roles.Concat(accessRoles).ToList());

			var json = new JObject
			{
				{ "ID", this.ID },
				{ "Roles", roles.Distinct(StringComparer.OrdinalIgnoreCase).ToJArray() },
				{ "Privileges", (this.AccessPrivileges ?? new List<Privilege>()).ToJArray(privilege => privilege.ToJson()) }
			};

			if (addStatus)
			{
				json["Status"] = $"{this.Status}";
				json["TwoFactorsAuthentication"] = this.TwoFactorsAuthentication.ToJson(authenticationKey ?? UtilityService.GetAppSetting("Keys:Authentication"));
			}

			return json;
		}

		/// <summary>
		/// Gets the sessions of this account
		/// </summary>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public async Task<List<Session>> GetSessionsAsync(CancellationToken cancellationToken = default)
			=> this.Sessions = await Session.FindAsync(Filters<Session>.Equals("UserID", this.ID), Sorts<Session>.Descending("ExpiredAt"), 0, 1, null, cancellationToken).ConfigureAwait(false);

		/// <summary>
		/// Gets an account by access identity (Built-In: email/phone number, OAuth: ID if the account, Windows: account with full domain)
		/// </summary>
		/// <param name="accessIdentity"></param>
		/// <param name="type"></param>
		/// <param name="cancellationToken"></param>
		/// <param name="getOriginal"></param>
		/// <returns></returns>
		public static async Task<Account> GetByAccessIdentityAsync(string accessIdentity, AccountType type = AccountType.BuiltIn, CancellationToken cancellationToken = default, bool getOriginal = true)
		{
			if (string.IsNullOrWhiteSpace(accessIdentity))
				return null;
			var account = await Account.GetAsync(Filters<Account>.And(Filters<Account>.Equals("AccessIdentity", accessIdentity), Filters<Account>.Equals("Type", $"{type}")), null, null, cancellationToken).ConfigureAwait(false);
			return account != null
				? (getOriginal ? await account.GetOriginalAsync(cancellationToken).ConfigureAwait(false) : null) ?? account
				: null;
		}

		/// <summary>
		/// Gets an account by identity
		/// </summary>
		/// <param name="id"></param>
		/// <param name="cancellationToken"></param>
		/// <param name="getOriginal"></param>
		/// <returns></returns>
		public static async Task<Account> GetByIDAsync(string id, CancellationToken cancellationToken = default, bool getOriginal = true)
		{
			if (string.IsNullOrWhiteSpace(id) || !id.IsValidUUID())
				return null;
			var account = await Account.GetAsync<Account>(id, cancellationToken).ConfigureAwait(false);
			return account != null
				? (getOriginal ? await account.GetOriginalAsync(cancellationToken).ConfigureAwait(false) : null) ?? account
				: null;
		}

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
		/// <param name="account">The account (email address, phone number, user name)</param>
		/// <returns></returns>
		public static string GeneratePassword(string account = null)
		{
			var pos = (account ?? "").IndexOf("-");
			if (pos < 0)
				pos = (account ?? "").IndexOf("_");
			if (pos < 0)
				pos = (account ?? "").IndexOf(".");
			return CaptchaService.GenerateRandomCode(true, true).GetCapitalizedFirstLetter()
				+ (pos > 0 ? account.Substring(pos, 1) : "#") + OTPService.GeneratePassword(UtilityService.NewUUID + (account ?? ""))
				+ CaptchaService.GenerateRandomCode().GetCapitalizedFirstLetter();
		}
		#endregion

	}

	#region Two-Factors Authentication
	public class TwoFactorsAuthentication
	{
		public TwoFactorsAuthentication() { }

		public bool Required { get; set; } = false;

		public List<TwoFactorsAuthenticationSetting> Settings { get; set; } = new List<TwoFactorsAuthenticationSetting>();

		internal List<TwoFactorsAuthenticationSetting> Providers
			=> this.Settings?.OrderBy(setting => setting.Type).ThenByDescending(setting => setting.Time).ToList();

		public JArray GetProvidersJson(string authenticationKey)
			=> this.Providers?.ToJArray(setting => setting.ToJson(authenticationKey)) ?? new JArray();

		public JObject ToJson(string authenticationKey, Action<JObject> onCompleted = null)
		{
			var json = new JObject
			{
				{ "Required",  this.Required },
				{ "Providers", this.GetProvidersJson(authenticationKey) }
			};
			onCompleted?.Invoke(json);
			return json;
		}
	}

	public class TwoFactorsAuthenticationSetting
	{
		public TwoFactorsAuthenticationSetting() {}

		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String)]
		public TwoFactorsAuthenticationType Type { get; set; } = TwoFactorsAuthenticationType.App;

		public string Stamp { get; set; } = string.Empty;

		public long Time { get; set; } = DateTime.Now.ToUnixTimestamp();

		public JObject ToJson(string authenticationKey, Action<JObject> onCompleted = null)
		{
			var phone = "**********";
			if (this.Type.Equals(TwoFactorsAuthenticationType.SMS))
				try
				{
					phone = $"******{this.Stamp.Decrypt(authenticationKey, true).Right(4)}";
				}
				catch { }
			var json = new JObject
			{
				{ "Label", this.Type.Equals(TwoFactorsAuthenticationType.App) ? "Authenticator app" : $"SMS ({phone})" },
				{ "Type", $"{this.Type}" },
				{ "Time", this.Time.FromUnixTimestamp() },
				{ "Info", $"{this.Type}|{this.Stamp}".Encrypt(authenticationKey, true) }
			};
			onCompleted?.Invoke(json);
			return json;
		}
	}
	#endregion

}