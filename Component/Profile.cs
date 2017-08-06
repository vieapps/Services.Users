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
			this.ReferID = "";
			this.ReferSection = "";
			this.Notes = "";
			this.LastUpdated = DateTime.Now;
		}

		#region Properties
		public string Name { get; set; }

		public string FirstName { get; set; }

		public string LastName { get; set; }

		[Property(MaxLength = 10)]
		public string BirthDay { get; set; }

		[JsonConverter(typeof(StringEnumConverter)), BsonRepresentation(BsonType.String)]
		public Gender Gender { get; set; }

		public string Address { get; set; }

		public string County { get; set; }

		public string Province { get; set; }

		public string Country { get; set; }

		public string PostalCode { get; set; }

		public string Mobile { get; set; }

		public string Email { get; set; }

		public string Notes { get; set; }

		public string Avatar { get; set; }

		public string ReferID { get; set; }

		public string ReferSection { get; set; }

		public DateTime LastUpdated { get; set; }

		[Ignore, BsonIgnore]
		public override string Title
		{
			get { return this.Name; }
		}
		#endregion

	}
}