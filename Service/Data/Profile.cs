﻿#region Related components
using System;
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
	[Serializable, BsonIgnoreExtraElements, DebuggerDisplay("ID = {ID}, Name = {Name}, Email = {Email}")]
	[Entity(CollectionName = "Profiles", TableName = "T_Users_Profiles", CacheStorageType = typeof(Utility), CacheStorageName = "Cache", Searchable = true)]
	public class Profile : Repository<Profile>
	{
		public Profile()
		{
			this.ID = "";
			this.Name = "";
			this.FirstName = "";
			this.LastName = "";
			this.BirthDay = null;
			this.Gender = Gender.NotProvided;
			this.Address = "";
			this.County = "";
			this.Province = "";
			this.Country = "";
			this.PostalCode = "";
			this.Email = "";
			this.Mobile = "";
			this.Avatar = "";
			this.Alias = "";
			this.Bio = "";
			this.Notes = "";
			this.LastUpdated = DateTime.Now;
		}

		#region Properties
		[Property(MaxLength = 250, NotNull = true, NotEmpty = true), Searchable, Sortable(IndexName = "Names")]
		public string Name { get; set; }

		[Property(MaxLength = 250), Searchable, Sortable(IndexName = "Names")]
		public string FirstName { get; set; }

		[Property(MaxLength = 250), Searchable, Sortable(IndexName = "Names")]
		public string LastName { get; set; }

		[Property(MaxLength = 10), Sortable]
		public string BirthDay { get; set; }

		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String)]
		public Gender Gender { get; set; }

		[Property(MaxLength = 250), Searchable]
		public string Address { get; set; }

		[Property(MaxLength = 50), Searchable, Sortable(IndexName = "Address")]
		public string County { get; set; }

		[Property(MaxLength = 50), Searchable, Sortable(IndexName = "Address")]
		public string Province { get; set; }

		[Property(MaxLength = 2), Sortable(IndexName = "Address")]
		public string Country { get; set; }

		[Property(MaxLength = 20)]
		public string PostalCode { get; set; }

		[Property(MaxLength = 20), Searchable, Sortable(IndexName = "ContactInfo")]
		public string Mobile { get; set; }

		[Property(MaxLength = 250), Searchable, Sortable(IndexName = "ContactInfo")]
		public string Email { get; set; }

		[Property(MaxLength = 1000)]
		public string Avatar { get; set; }

		[Property(MaxLength = 250, NotNull = true), Searchable, Sortable(IndexName = "ContactInfo")]
		public string Alias { get; set; }

		[Property(MaxLength = 250), Searchable]
		public string Bio { get; set; }

		[Searchable]
		public string Notes { get; set; }

		[Sortable]
		public DateTime LastUpdated { get; set; }
		#endregion

		#region IBusinessEntity Properties
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

		#region To JSON
		public override JObject ToJson(bool addTypeOfExtendedProperties = false, Action<JObject> onPreCompleted = null)
		{
			return base.ToJson(addTypeOfExtendedProperties, (obj) =>
			{
				obj.Add(new JProperty("Gravatar", string.IsNullOrWhiteSpace(this.Email) ? Utility.HttpFilesUri + "/avatars/default.png" : "https://secure.gravatar.com/avatar/" + this.Email.ToLower().Trim().GetMD5() + "?s=300&d=" + (Utility.HttpFilesUri + "/avatars/default.png").UrlEncode()));
				onPreCompleted?.Invoke(obj);
			});
		}
		#endregion

	}
}