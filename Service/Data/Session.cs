#region Related components
using System;
using System.Diagnostics;
using System.Xml.Serialization;

using Newtonsoft.Json;
using MongoDB.Bson.Serialization.Attributes;

using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	[BsonIgnoreExtraElements, DebuggerDisplay("ID = {ID}, IP = {IP}, AppInfo = {AppInfo}")]
	[Entity(CollectionName = "Sessions", TableName = "T_Users_Sessions", CacheClass = typeof(Utility), CacheName = "Cache", CreateNewVersionWhenUpdated = false)]
	public class Session : Repository<Session>
	{
		public Session() : base() { }

		/// <summary>
		/// Gets or sets time when the session is issued
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime IssuedAt { get; set; } = DateTime.Now;

		/// <summary>
		/// Gets or sets time when the session is renewed
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime RenewedAt { get; set; } = DateTime.Now;

		/// <summary>
		/// Gets or sets time when the session is expired
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime ExpiredAt { get; set; } = DateTime.Now.AddDays(90);

		/// <summary>
		/// Gets or sets the identity of the user who performs the actions in this session
		/// </summary>
		[Property(MaxLength = 32, NotNull = true)]
		[Sortable]
		public string UserID { get; set; } = "";

		/// <summary>
		/// Gets or sets the encrypted access token
		/// </summary>
		[Property(NotNull = true, IsCLOB = true)]
		public string AccessToken { get; set; } = "";

		/// <summary>
		/// Gets or sets the IP address of the device that use to performs the actions in this session
		/// </summary>
		[Property(MaxLength = 50)]
		public string IP { get; set; } = "";

		/// <summary>
		/// Gets or sets the identity of the device that use to performs the actions in this session
		/// </summary>
		[Property(MaxLength = 128, NotNull = true)]
		[Sortable]
		public string DeviceID { get; set; } = "";

		/// <summary>
		/// Gets or sets the identity of the developer that associates with this session
		/// </summary>
		[Property(MaxLength = 32)]
		[Sortable]
		public string DeveloperID { get; set; }

		/// <summary>
		/// Gets or sets the identity of the app that associates with this session
		/// </summary>
		[Property(MaxLength = 32)]
		[Sortable]
		public string AppID { get; set; }

		/// <summary>
		/// Gets or sets the platform info of the device that use to performs the actions in this session
		/// </summary>
		[Property(MaxLength = 250)]
		public string AppInfo { get; set; } = "";

		/// <summary>
		/// Gets or sets the OS info of the device that use to performs the actions in this session
		/// </summary>
		[Property(MaxLength = 500)]
		public string OSInfo { get; set; } = "";

		/// <summary>
		/// Gets or sets the verification state of two-factors authentication
		/// </summary>
		[Sortable]
		public bool Verified { get; set; } = false;

		/// <summary>
		/// Gets or sets online status
		/// </summary>
		[Sortable]
		public bool Online { get; set; } = false;

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
	}
}