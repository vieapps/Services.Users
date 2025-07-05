#region Related components
using System;
using System.Dynamic;
using System.Diagnostics;
using System.Xml.Serialization;
using MongoDB.Bson.Serialization.Attributes;
using Newtonsoft.Json;
using net.vieapps.Components.Repository;
using net.vieapps.Components.Security;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.Users
{
	[BsonIgnoreExtraElements, DebuggerDisplay("ID = {ID}, IP = {IP}, AppInfo = {AppInfo}")]
	[Entity(CollectionName = "Sessions", TableName = "T_Users_Sessions", CacheClass = typeof(Utility), CacheName = "Cache", CreateNewVersionWhenUpdated = false)]
	public class Session : Repository<Session>
	{
		public Session() : base() { }

		public Session(Services.Session session, string osInfo = null) : base()
		{
			this.ID = session?.SessionID ?? "";
			this.UserID = session?.User?.ID ?? "";
			this.Verified = session != null && session.Verified;
			this.DeviceID = session?.DeviceID ?? "";
			this.IP = session?.IP ?? "";
			this.DeveloperID = session?.DeveloperID ?? "";
			this.AppID = session?.AppID ?? "";
			this.AppInfo = $"{session?.AppName ?? "Generic App"} @ {session?.AppPlatform ?? "Dekstop WPA"}";
			this.OSInfo = osInfo ?? $"{Extensions.GetOSInfo(session?.AppAgent)} [{session?.AppAgent ?? "N/A"}]";
		}

		internal Services.Session ToSession(Account account = null)
			=> new Services.Session
			{
				SessionID = this.ID,
				User = account != null ? new User(account.ID, this.ID, account.Roles, account.AccessPrivileges ?? [], "APIs") : User.GetDefault(this.ID),
				Verified = this.Verified,
				DeviceID = this.DeviceID,
				IP = this.IP,
				DeveloperID = this.DeveloperID,
				AppID = this.AppID,
				AppMode = "Client"
			};

		internal static Services.Session ToSession(System.Dynamic.ExpandoObject data)
			=> new Services.Session
			{
				SessionID = data.Get<string>("SessionID"),
				User = data.Get<User>("User") ?? User.GetDefault(data.Get<string>("SessionID")),
				Verified = data.Get("Verified", false),
				DeviceID = data.Get<string>("DeviceID"),
				IP = data.Get<string>("IP"),
				DeveloperID = data.Get<string>("DeveloperID"),
				AppID = data.Get<string>("AppID"),
				AppName =	data.Get<string>("AppName"),
				AppPlatform = data.Get<string>("AppPlatform"),
				AppAgent = data.Get<string>("AppAgent"),
				AppOrigin = data.Get<string>("AppOrigin"),
				AppMode = data.Get<string>("AppMode") ?? "Client"
			};

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

	public class SessionInfo
	{
		public SessionInfo(ExpandoObject data = null)
		{
			if (data != null)
			{
				this.Session = new Session().CopyFrom(data.Get("Session", new ExpandoObject()));
				this.User = new UserInfo(data.Get("User", new ExpandoObject()));
				this.Service = new ServiceInfo(data.Get("Service", new ExpandoObject()));
				this.LastAccess = data.Get("LastAccess", DateTime.Now);
			}
		}
		public Session Session { get; set; }
		public UserInfo User { get; set; }
		public ServiceInfo Service { get; set; }
		public DateTime LastAccess { get; set; } = DateTime.Now;
	}

	public class UserInfo
	{
		public UserInfo(ExpandoObject data = null)
		{
			if (data != null)
				this.CopyFrom(data);
		}
		public string Name { get; set; }
		public string Email { get; set; }
		public string Location { get; set; }
		public DateTime LastAccess { get; set; } = DateTime.Now;
	}

	public class ServiceInfo
	{
		public ServiceInfo(ExpandoObject data = null)
		{
			if (data != null)
				this.CopyFrom(data);
		}
		public string Name { get; set; }
		public string URI { get; set; }
		public string SystemID { get; set; }
	}

}