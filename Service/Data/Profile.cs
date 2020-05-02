#region Related components
using System;
using System.Diagnostics;
using System.Xml.Serialization;

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
	[Serializable, BsonIgnoreExtraElements, DebuggerDisplay("ID = {ID}, Name = {Name}, Email = {Email}")]
	[Entity(CollectionName = "Profiles", TableName = "T_Users_Profiles", CacheClass = typeof(Utility), CacheName = "Cache", Searchable = true)]
	public class Profile : Repository<Profile>
	{
		public Profile() : base()
			=> this.ID = "";

		[Property(MaxLength = 250, NotNull = true, NotEmpty = true), Searchable, Sortable(IndexName = "Names")]
		public string Name { get; set; } = "";

		[Property(MaxLength = 250), Searchable, Sortable(IndexName = "Names")]
		public string FirstName { get; set; } = "";

		[Property(MaxLength = 250), Searchable, Sortable(IndexName = "Names")]
		public string LastName { get; set; } = "";

		[Property(MaxLength = 10), Sortable]
		public string BirthDay { get; set; }

		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String)]
		public Gender Gender { get; set; } = Gender.NotProvided;

		[Property(MaxLength = 250), Searchable]
		public string Address { get; set; } = "";

		[Property(MaxLength = 50), Searchable, Sortable(IndexName = "Address")]
		public string County { get; set; } = "";

		[Property(MaxLength = 50), Searchable, Sortable(IndexName = "Address")]
		public string Province { get; set; } = "";

		[Property(MaxLength = 2), Sortable(IndexName = "Address")]
		public string Country { get; set; } = "";

		[Property(MaxLength = 20)]
		public string PostalCode { get; set; } = "";

		[Property(MaxLength = 20), Searchable, Sortable(IndexName = "ContactInfo")]
		public string Mobile { get; set; } = "";

		[Property(MaxLength = 250), Searchable, Sortable(IndexName = "ContactInfo")]
		public string Email { get; set; } = "";

		[Property(MaxLength = 5)]
		public string Language { get; set; } = "vi-VN";

		[Property(MaxLength = 1000)]
		public string Avatar { get; set; } = "";

		[Property(MaxLength = 250, NotNull = true), Searchable, Sortable(IndexName = "ContactInfo")]
		public string Alias { get; set; } = "";

		[Property(MaxLength = 250), Searchable]
		public string Bio { get; set; } = "";

		[Searchable]
		public string Notes { get; set; } = "";

		[Sortable]
		public DateTime LastUpdated { get; set; } = DateTime.Now;

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

		public override JObject ToJson(bool addTypeOfExtendedProperties = false, Action<JObject> onPreCompleted = null)
		{
			return base.ToJson(addTypeOfExtendedProperties, json =>
			{
				json["Avatar"] = string.IsNullOrWhiteSpace(this.Avatar) ? "" : this.Avatar.StartsWith("/") ? Utility.FilesHttpURI + this.Avatar : this.Avatar.Replace("~~/", Utility.FilesHttpURI + "/");
				json["Gravatar"] = this.GetGravatarURI();
				onPreCompleted?.Invoke(json);
			});
		}
	}
}