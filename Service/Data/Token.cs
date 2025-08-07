#region Related components
using System;
using System.Diagnostics;
using System.Xml.Serialization;
using MongoDB.Bson.Serialization.Attributes;
using Newtonsoft.Json;
using net.vieapps.Components.Repository;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.Users
{
	[BsonIgnoreExtraElements, DebuggerDisplay("ID = {ID}, UserID = {UserID}, SessionID = {SessionID}")]
	[Entity(CollectionName = "Tokens", TableName = "T_Users_Tokens", CacheClass = typeof(Utility), CacheName = "Cache", CreateNewVersionWhenUpdated = false)]
	public class Token : Repository<Token>
	{
		public Token() : base() { }

		/// <summary>
		/// Gets or sets the identity of the user
		/// </summary>
		[Property(MaxLength = 32, NotNull = true, NotEmpty = true)]
		[Sortable(IndexName = "IDs")]
		public string UserID { get; set; }

		/// <summary>
		/// Gets or sets the identity of the session
		/// </summary>
		[Property(MaxLength = 32, NotNull = true, NotEmpty = true)]
		[Sortable(IndexName = "IDs")]
		public string SessionID { get; set; }

		/// <summary>
		/// Gets or sets time when the token is expires
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime Expires { get; set; } = DateTime.Now.AddYears(13);

		/// <summary>
		/// Gets or sets time when the toke is accessed at the last time
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime LastAccess { get; set; } = DateTime.Now;

		/// <summary>
		/// Gets or sets time when the toke is created
		/// </summary>
		[Sortable(IndexName = "Times")]
		public DateTime Created { get; set; } = DateTime.Now;

		/// <summary>
		/// Gets or sets the identity of the user who creates that token
		/// </summary>
		[Property(MaxLength = 32)]
		[Sortable(IndexName = "IDs")]
		public string CreatedID { get; set; }

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