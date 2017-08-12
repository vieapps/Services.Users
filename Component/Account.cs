#region Related components
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	[Serializable, BsonIgnoreExtraElements, DebuggerDisplay("ID = {ID}, Name = {Name}, Email = {Email}")]
	[Entity(CollectionName = "Accounts", TableName = "T_Users_Accounts", CacheStorageType = typeof(Utility), CacheStorageName = "Cache")]
	public class Account : Repository<Account>
	{
		public Account()
		{
			this.ID = "";
			this.Type = AccountType.BuiltIn;
			this.Joined = DateTime.Now;
			this.LastAccess = DateTime.Now;
			this.OAuthType = "";
			this.AccountName = "";
			this.AccountID = "";
			this.AccountKey = "";
			this.AccountRole = SystemRole.All;
			this.AccountRoles = new List<string>();
			this.AccountPrivileges = new List<Privilege>();
		}

		#region Properties
		/// <summary>
		/// Gets or sets type of user account
		/// </summary>
		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String), Property(NotNull = true), Sortable]
		public AccountType Type { get; set; }

		/// <summary>
		/// Gets or sets joined time of the user
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime Joined { get; set; }

		/// <summary>
		/// Gets or sets last activity time of the user
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime LastAccess { get; set; }

		/// <summary>
		/// Gets or sets the type of OAuth account, must be string of <see cref="OAuthType">OAuthType</see> when the type of user account is OAuth
		/// </summary>
		[Property(MaxLength = 20, NotNull = true), Sortable(UniqueIndexName = "Account")]
		public string OAuthType { get; set; }

		/// <summary>
		/// Gets or sets the name of the user account (email address when the user is built-in account, OAuth ID if the user is OAuth account, account with full domain if the user is Windows account)
		/// </summary>
		[Property(MaxLength = 250, NotNull = true), Sortable(UniqueIndexName = "Account")]
		public string AccountName { get; set; }

		/// <summary>
		/// Gets or sets the mapped account identity (when the user account is OAuth and mapped to a built-in user account)
		/// </summary>
		[Property(MaxLength = 32), Sortable(UniqueIndexName = "Account")]
		public string AccountID { get; set; }

		/// <summary>
		/// Gets or sets the key for logging this user account in (hashed password when the user is built-in account or access token when the user is OAuth account)
		/// </summary>
		[JsonIgnore, Property(MaxLength = 250)]
		public string AccountKey { get; set; }

		/// <summary>
		/// Gets or sets the system role of the user account
		/// </summary>
		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String), Property(NotNull = true), Sortable]
		public SystemRole AccountRole { get; set; }

		/// <summary>
		/// Gets or sets the working roles (means working roles of business services) of the user account
		/// </summary>
		[AsJson]
		public List<string> AccountRoles { get; set; }

		/// <summary>
		/// Gets or sets the working privileges (means scopes/working privileges of services/services' objects) of the user account
		/// </summary>
		[AsJson]
		public List<Privilege> AccountPrivileges { get; set; }

		/// <summary>
		/// Gets or sets the collection of sessions of the user account
		/// </summary>
		[JsonIgnore, BsonIgnore, Ignore]
		public List<Session> Sessions { get; set; }
		#endregion

		#region IBusiness properties
		[JsonIgnore, BsonIgnore, Ignore]
		public override string Title { get { return this.AccountName; } }

		[JsonIgnore, BsonIgnore, Ignore]
		public override string SystemID { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override string RepositoryID { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override string EntityID { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override Privileges OriginalPrivileges { get; set; }
		#endregion

		public static string HashPassword(string accountID, string accountKey)
		{
			return (accountID.Trim().ToLower().Left(13) + ":" + accountKey).GetSHA512().ToBase64Url(false, true);
		}

	}
}