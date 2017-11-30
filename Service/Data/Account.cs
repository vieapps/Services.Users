#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Converters;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	[Serializable, BsonIgnoreExtraElements, DebuggerDisplay("ID = {ID}, Identity = {AccessIdentity}, Type = {Type}")]
	[Entity(CollectionName = "Accounts", TableName = "T_Users_Accounts", CacheStorageType = typeof(Utility), CacheStorageName = "Cache")]
	public class Account : Repository<Account>
	{
		public Account()
		{
			this.ID = "";
			this.Status = AccountStatus.Activated;
			this.Type = AccountType.BuiltIn;
			this.Joined = DateTime.Now;
			this.LastAccess = DateTime.Now;
			this.OAuthType = "";
			this.AccessMapIdentity = "";
			this.AccessIdentity = "";
			this.AccessKey = "";
			this.AccessRoles = new Dictionary<string, List<string>>();
			this.AccessPrivileges = new List<Privilege>();
		}

		#region Properties
		/// <summary>
		/// Gets or sets the status
		/// </summary>
		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String), Property(NotNull = true), Sortable]
		public AccountStatus Status { get; set; }

		/// <summary>
		/// Gets or sets the type
		/// </summary>
		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String), Property(NotNull = true), Sortable]
		public AccountType Type { get; set; }

		/// <summary>
		/// Gets or sets the joined time of the user account
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime Joined { get; set; }

		/// <summary>
		/// Gets or sets the last activity time of the user account
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime LastAccess { get; set; }

		/// <summary>
		/// Gets or sets the type of the OAuth user account, must be string of <see cref="OAuthType">OAuthType</see> when the type of user account is OAuth
		/// </summary>
		[Property(MaxLength = 20, NotNull = true), Sortable(UniqueIndexName = "Account")]
		public string OAuthType { get; set; }

		/// <summary>
		/// Gets or sets the identity of the mapped user account (when the user account is OAuth and mapped to a built-in user account)
		/// </summary>
		[Property(MaxLength = 32), Sortable(UniqueIndexName = "Account")]
		public string AccessMapIdentity { get; set; }

		/// <summary>
		/// Gets or sets the identiy of the user account (email address when the user is built-in account, OAuth ID if the user is OAuth account, account with full domain if the user is Windows account)
		/// </summary>
		[Property(MaxLength = 250, NotNull = true), Sortable(UniqueIndexName = "Account")]
		public string AccessIdentity { get; set; }

		/// <summary>
		/// Gets or sets the key of the user account in (hashed password when the user is built-in account or access token when the user is OAuth account)
		/// </summary>
		[JsonIgnore]
		public string AccessKey { get; set; }

		/// <summary>
		/// Gets or sets the working roles (means working roles of business services) of the user account
		/// </summary>
		[AsJson]
		public Dictionary<string, List<string>> AccessRoles { get; set; }

		/// <summary>
		/// Gets or sets the working privileges (means scopes/working privileges of services/services' objects) of the user account
		/// </summary>
		[AsJson]
		public List<Privilege> AccessPrivileges { get; set; }

		/// <summary>
		/// Gets or sets the collection of sessions of the user account
		/// </summary>
		[JsonIgnore, BsonIgnore, Ignore]
		public List<Session> Sessions { get; set; }

		[NonSerialized]
		Profile _profile = null;

		[JsonIgnore, BsonIgnore, Ignore]
		public Profile Profile
		{
			get
			{
				if (this._profile == null)
					this._profile = Profile.Get<Profile>(this.ID);
				return this._profile;
			}
		}
		#endregion

		#region IBusiness properties
		[JsonIgnore, BsonIgnore, Ignore]
		public override string Title { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override string SystemID { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override string RepositoryID { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override string EntityID { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override Privileges OriginalPrivileges { get; set; }
		#endregion

		public async Task GetSessionsAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			this.Sessions = await Session.FindAsync(Filters<Session>.Equals("UserID", this.ID), Sorts<Session>.Descending("ExpiredAt"), 0, 1, null, cancellationToken);
		}

		public List<string> GetRoles(string initialized = null)
		{
			var roles = string.IsNullOrWhiteSpace(initialized)
				? new List<string>()
				: initialized.ToList();
			if (this.AccessRoles != null && this.AccessRoles.Count > 0)
				this.AccessRoles.ForEach(sRoles => roles = roles.Concat(sRoles).ToList());
			return roles.Distinct().ToList();
		}

		public JObject GetAccountJson(bool addStatus = false, string idNode = "ID")
		{
			var roles = SystemRole.All.ToString() + "," + SystemRole.Authenticated.ToString()
				+ (User.SystemAdministrators.Contains(this.ID) ? "," + SystemRole.SystemAdministrator.ToString() : "");

			var json = new JObject()
			{
				{ idNode, this.ID },
				{ "Roles", this.GetRoles(roles).ToJArray() },
				{ "Privileges", (this.AccessPrivileges ?? new List<Privilege>()).ToJArray() }
			};

			if (addStatus)
				json.Add(new JProperty("Status", this.Status.ToString()));

			return json;
		}

		/// <summary>
		/// Gets an user account by identity
		/// </summary>
		/// <param name="identity"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task<Account> GetByIdentityAsync(string identity, AccountType type = AccountType.BuiltIn, CancellationToken cancellationToken = default(CancellationToken))
		{
			return Account.GetAsync<Account>(Filters<Account>.And(
					Filters<Account>.Equals("AccessIdentity", identity),
					Filters<Account>.Equals("Type", type.ToString())
				), null, null, cancellationToken);
		}

		/// <summary>
		/// Hashs the password for storing
		/// </summary>
		/// <param name="id">The string that presents the identity of an account</param>
		/// <param name="password">The string that presents the password of an account</param>
		/// <returns></returns>
		public static string HashPassword(string id, string password)
		{
			if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(password) || !id.IsValidUUID())
				throw new InformationInvalidException();
			return (id.Trim().ToLower().Left(13) + ":" + password).GetHMACSHA512(id.Trim().ToLower(), false).ToBase64Url(true);
		}

	}
}