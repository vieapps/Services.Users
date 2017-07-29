#region Related components
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using System.Diagnostics;

using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

using MongoDB.Bson.Serialization.Attributes;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	[Serializable, BsonIgnoreExtraElements, DebuggerDisplay("ID = {ID}, Platform = {AppPlatform}, IP = {IP}")]
	[Entity(CollectionName = "Sessions", CacheStorageType = typeof(Global), CacheStorageName = "Cache")]
	public class Session : DataAccessor<Session>
	{
		public Session()
		{
			this.ID = "";
			this.IssuedAt = DateTime.Now;
			this.RenewedAt = DateTime.Now;
			this.ExpiredAt = DateTime.Now.AddDays(30);
			this.UserID = "";
			this.DeviceID = "";
			this.AppPlatform = "";
			this.IP = "";
			this.AccessToken = "";
		}

		#region Properties
		/// <summary>
		/// Gets or sets time when the session is issued
		/// </summary>
		public DateTime IssuedAt { get; set; }

		/// <summary>
		/// Gets or sets time when the session is renewed
		/// </summary>
		public DateTime RenewedAt { get; set; }

		/// <summary>
		/// Gets or sets time when the session is expired
		/// </summary>
		public DateTime ExpiredAt { get; set; }

		/// <summary>
		/// Gets or sets the identity of the user who performs the actions in this session
		/// </summary>
		[Property(MaxLength = 32)]
		public string UserID { get; set; }

		/// <summary>
		/// Gets or sets the identity of the device that use to performs the actions in this session
		/// </summary>
		[Property(MaxLength = 128)]
		public string DeviceID { get; set; }

		/// <summary>
		/// Gets or sets the platform info of the device that use to performs the actions in this session
		/// </summary>
		[Property(MaxLength = 100)]
		public string AppPlatform { get; set; }

		/// <summary>
		/// Gets or sets the IP address of the device that use to performs the actions in this session
		/// </summary>
		[Property(MaxLength = 50)]
		public string IP { get; set; }

		/// <summary>
		/// Gets or sets the encrypted access token
		/// </summary>
		public string AccessToken { get; set; }
		#endregion

	}
}