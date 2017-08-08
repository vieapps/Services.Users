#region Related components
using System;
using System.Diagnostics;

using Newtonsoft.Json;
using MongoDB.Bson.Serialization.Attributes;

using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	[Serializable, BsonIgnoreExtraElements, DebuggerDisplay("ID = {ID}, IP = {IP}, Platform = {AppPlatform}")]
	[Entity(CollectionName = "Sessions", TableName = "T_Users_Sessions", CacheStorageType = typeof(Global), CacheStorageName = "Cache")]
	public class Session : DataAccessor<Session>
	{
		public Session()
		{
			this.ID = "";
			this.IssuedAt = DateTime.Now;
			this.RenewedAt = DateTime.Now;
			this.ExpiredAt = DateTime.Now.AddDays(60);
			this.UserID = "";
			this.AccessToken = "";
			this.IP = "";
			this.DeviceID = "";
			this.AppPlatform = "";
			this.Online = false;
		}

		#region Properties
		/// <summary>
		/// Gets or sets time when the session is issued
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime IssuedAt { get; set; }

		/// <summary>
		/// Gets or sets time when the session is renewed
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime RenewedAt { get; set; }

		/// <summary>
		/// Gets or sets time when the session is expired
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime ExpiredAt { get; set; }

		/// <summary>
		/// Gets or sets the identity of the user who performs the actions in this session
		/// </summary>
		[Property(MaxLength = 32), Sortable(IndexName = "IDs")]
		public string UserID { get; set; }

		/// <summary>
		/// Gets or sets the encrypted access token
		/// </summary>
		[JsonIgnore, Property(IsCLOB = true)]
		public string AccessToken { get; set; }

		/// <summary>
		/// Gets or sets the IP address of the device that use to performs the actions in this session
		/// </summary>
		[Property(MaxLength = 50)]
		public string IP { get; set; }

		/// <summary>
		/// Gets or sets the identity of the device that use to performs the actions in this session
		/// </summary>
		[Property(MaxLength = 128), Sortable(IndexName = "IDs")]
		public string DeviceID { get; set; }

		/// <summary>
		/// Gets or sets the platform info of the device that use to performs the actions in this session
		/// </summary>
		[Property(MaxLength = 250)]
		public string AppPlatform { get; set; }

		/// <summary>
		/// Gets or sets online status
		/// </summary>
		public bool Online { get; set; }
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

	}
}