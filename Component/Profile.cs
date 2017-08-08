﻿#region Related components
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
	public enum Gender
	{
		NotProvided,
		Male,
		Female
	}

	[Serializable, BsonIgnoreExtraElements, DebuggerDisplay("ID = {ID}, Name = {Name}, Email = {Email}")]
	[Entity(CollectionName = "Profiles", TableName = "T_Users_Profiles", CacheStorageType = typeof(Global), CacheStorageName = "Cache")]
	public class Profile : DataAccessor<Profile>
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
			this.Notes = "";
			this.LastUpdated = DateTime.Now;
		}

		#region Properties
		[Property(MaxLength = 250, NotNull = true)]
		public string Name { get; set; }

		[Property(MaxLength = 250)]
		public string FirstName { get; set; }

		[Property(MaxLength = 250)]
		public string LastName { get; set; }

		[Property(MaxLength = 10)]
		public string BirthDay { get; set; }

		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String)]
		public Gender Gender { get; set; }

		[Property(MaxLength = 250)]
		public string Address { get; set; }

		[Property(MaxLength = 50)]
		public string County { get; set; }

		[Property(MaxLength = 50)]
		public string Province { get; set; }

		[Property(MaxLength = 2)]
		public string Country { get; set; }

		[Property(MaxLength = 20)]
		public string PostalCode { get; set; }

		[Property(MaxLength = 20)]
		public string Mobile { get; set; }

		[Property(MaxLength = 250)]
		public string Email { get; set; }

		[Property(MaxLength = 1000)]
		public string Notes { get; set; }

		[Property(MaxLength = 1000)]
		public string Avatar { get; set; }

		public DateTime LastUpdated { get; set; }
		#endregion

		#region IBusiness properties
		[JsonIgnore, BsonIgnore, Ignore]
		public override string Title { get { return this.Name; } }

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