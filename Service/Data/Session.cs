#region Related components
using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Xml.Serialization;
using System.Collections.Generic;
using System.Collections.Concurrent;
using MongoDB.Bson.Serialization.Attributes;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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

		internal Services.Session ToSession(Account account = null, Action<Services.Session> onCompleted = null)
		{
			var session = new Services.Session
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
			onCompleted?.Invoke(session);
			return session;
		}

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

	public class UserInfo
	{
		public string Name { get; set; }
		public string Email { get; set; }
		public string Location { get; set; }
		public DateTime LastAccess { get; set; } = DateTime.Now;
		public UserInfo() { }
	}

	public class ServiceInfo
	{
		public string Name { get; set; }
		public string URI { get; set; }
		public string SystemID { get; set; }
		public ServiceInfo() { }
	}

	public class SessionInfo
	{
		internal readonly object Locker = new();
		public Session Session { get; set; }
		public UserInfo User { get; set; }
		public ServiceInfo Service { get; set; }
		public DateTime LastAccess { get; set; } = DateTime.Now;
		public SessionInfo() { }
		public SessionInfo(JObject data) => this.CopyFrom(data);
	}

	public class TrackingInfo
	{
		public string SessionID { get; init; }
		public string DeviceID { get; init; }
		public string UserID { get; init; }
		public string UserName { get; init; }
		public string UserEmail { get; init; }
		public string UserLocation { get; init; }
		public string IP { get; init; }
		public string AppInfo { get; init; }
		public string OSInfo { get; init; }
		public string ServiceName { get; init; }
		public string ServiceURI { get; init; }
		public string ServiceSystemID { get; init; }
		public bool Verified { get; init; }
		public bool Online { get; init; }
		public bool Track { get; init; }
		public bool Crawler { get; init; }
		public string CorrelationID { get; init; }
		public TrackingInfo(JObject data = null)
		{
			var service = data.Get<JObject>("Service");
			var appAgent = data.Get<string>("AppAgent");
			this.SessionID = data.Get<string>("SessionID") ?? data.Get<string>("ID");
			this.DeviceID = data.Get<string>("DeviceID");
			this.UserID = data.Get<string>("UserID");
			this.UserName = data.Get<string>("UserName");
			this.UserEmail = data.Get<string>("UserEmail");
			this.UserLocation = data.Get<string>("UserLocation");
			this.IP = data.Get<string>("IP");
			this.AppInfo = data.Get<string>("AppInfo") ?? $"{data.Get<string>("AppName")} @ {data.Get<string>("AppPlatform")}";
			this.OSInfo = data.Get<string>("OSInfo") ?? $"{Extensions.GetOSInfo(appAgent)} [{appAgent}]";
			this.ServiceName = service?.Get<string>("Name")?.ToLower();
			this.ServiceURI = service?.Get<string>("URI");
			this.ServiceSystemID = service?.Get<string>("SystemID");
			this.Verified = data.Get("Verified", false);
			this.Online = data.Get("Online", false);
			this.Track = data.Get("Track", true);
			this.Crawler = data.Get("Crawler", false);
			this.CorrelationID = data.Get<string>("CorrelationID") ?? data.Get<string>("X-Correlation-ID") ?? UtilityService.NewUUID;
		}
	}

	public class LocationInfo
	{
		public LocationInfo() { }
		public Services.Session Session { get; init; }
		public string CorrelationID { get; init; }
	}

	public class Sessions : IDisposable
	{
		readonly ConcurrentDictionary<string, SessionInfo> _sessions = [];
		readonly bool _trackAuthenticatedOnly = "true".IsEquals(UtilityService.GetAppSetting("Sessions:Track:AuthenticatedOnly", "false"));

		readonly System.Action _trackStatistics;
		readonly System.Action _sendStatistics;
		readonly Func<Exception, string, Task> _onErrorAsync;

		readonly Channel<TrackingInfo> _trackingQueue;
		readonly Channel<LocationInfo> _locationQueue;
		readonly Channel<string> _normalizationQueue;
		readonly Channel<string> _lastAccessQueue;
		readonly int _backgroundTimeout = 30;

		readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _sessionsByIP = [];
		readonly ConcurrentDictionary<string, byte> _pendingLocations = [];
		readonly ConcurrentDictionary<string, string> _locations = [];
		readonly ConcurrentDictionary<string, byte> _pendingSessions = [];
		readonly ConcurrentDictionary<string, byte> _pendingLastAccesses = [];

		readonly CancellationTokenSource _cts = new();
		readonly List<Task> _workers = [];

		public Sessions(System.Action trackStatistics, System.Action sendStatistics, Func<Exception, string, Task> onErrorAsync, int sessionCapacity = 10240, int sessionWorkers = 1, int backgroundCapacity = 1024, int backgroundWorkers = 4, int backgroundTimeout = 30)
		{
			this._trackStatistics = trackStatistics ?? (() => { });
			this._sendStatistics = sendStatistics ?? (() => { });
			this._onErrorAsync = onErrorAsync ?? ((_, _) => Task.CompletedTask);
			this._backgroundTimeout = backgroundTimeout;

			this._trackingQueue = Channel.CreateBounded<TrackingInfo>(new BoundedChannelOptions(sessionCapacity)
			{
				SingleWriter = false,
				SingleReader = sessionWorkers == 1,
				FullMode = BoundedChannelFullMode.DropOldest
			});

			this._locationQueue = Channel.CreateBounded<LocationInfo>(new BoundedChannelOptions(backgroundCapacity)
			{
				SingleWriter = false,
				SingleReader = backgroundWorkers == 1,
				FullMode = BoundedChannelFullMode.DropOldest
			});

			this._normalizationQueue = Channel.CreateBounded<string>(new BoundedChannelOptions(backgroundCapacity)
			{
				SingleWriter = false,
				SingleReader = backgroundWorkers == 1,
				FullMode = BoundedChannelFullMode.DropOldest
			});

			this._lastAccessQueue = Channel.CreateBounded<string>(new BoundedChannelOptions(backgroundCapacity)
			{
				SingleWriter = false,
				SingleReader = backgroundWorkers == 1,
				FullMode = BoundedChannelFullMode.DropOldest
			});

			for (var i = 0; i < Math.Max(1, sessionWorkers); i++)
				this._workers.Add(Task.Run(this.ProcessTrackingsAsync));

			for (var i = 0; i < Math.Max(1, backgroundWorkers); i++)
				this._workers.Add(Task.Run(this.ProcessLocationsAsync));

			for (var i = 0; i < Math.Max(1, backgroundWorkers); i++)
				this._workers.Add(Task.Run(this.ProcessNormalizationsAsync));

			for (var i = 0; i < Math.Max(1, backgroundWorkers); i++)
				this._workers.Add(Task.Run(this.UpdateLastAccessesAsync));
		}

		public void Dispose()
		{
			this._cts.Cancel();
			this._trackingQueue.Writer.TryComplete();
			this._locationQueue.Writer.TryComplete();
			this._normalizationQueue.Writer.TryComplete();
			this._lastAccessQueue.Writer.TryComplete();
			try
			{
				Task.WaitAll(this._workers.Where(worker => worker != null).ToArray(), TimeSpan.FromSeconds(3));
			}
			catch { }
			this._cts.Dispose();
		}

		async Task ProcessTrackingsAsync()
		{
			try
			{
				while (await this._trackingQueue.Reader.WaitToReadAsync(this._cts.Token).ConfigureAwait(false))
					while (this._trackingQueue.Reader.TryRead(out var info))
						try
						{
							this.ProcessTracking(info);
						}
						catch (Exception ex)
						{
							await this._onErrorAsync(ex, info?.CorrelationID).ConfigureAwait(false);
						}
			}
			catch (OperationCanceledException) { }
			catch (Exception ex)
			{
				await this._onErrorAsync(ex, null).ConfigureAwait(false);
			}
		}

		void ProcessTracking(TrackingInfo info)
		{
			if (info == null || string.IsNullOrWhiteSpace(info.SessionID))
				return;

			if (info.Track)
				this._trackStatistics();

			var now = DateTime.Now;
			var sessionInfo = this._sessions.GetOrAdd(info.SessionID, _ => new());

			lock (sessionInfo.Locker)
			{
				sessionInfo.Session ??= new()
				{
					ID = info.SessionID,
					UserID = info.UserID,
					IP = info.IP
				};
				sessionInfo.User ??= new();
				sessionInfo.Service ??= new();

				if (!info.Online)
				{
					this._sessions.TryRemove(info.SessionID, out _);
					if (this._sessionsByIP.TryGetValue(sessionInfo.Session.IP, out var set))
					{
						set.TryRemove(info.SessionID, out _);
						if (set.IsEmpty)
							this._sessionsByIP.TryRemove(sessionInfo.Session.IP, out _);
					}
					if (!string.IsNullOrWhiteSpace(info.UserID))
						this._sendStatistics();
					return;
				}

				var oldIP = sessionInfo.Session.IP;

				sessionInfo.LastAccess = now;
				sessionInfo.Session.Online = info.Online;

				if (!string.IsNullOrWhiteSpace(info.DeviceID))
					sessionInfo.Session.DeviceID = info.DeviceID;
				if (!string.IsNullOrWhiteSpace(info.UserID))
					sessionInfo.Session.UserID = info.UserID;
				if (!string.IsNullOrWhiteSpace(info.IP))
					sessionInfo.Session.IP = info.IP;
				if (!string.IsNullOrWhiteSpace(info.AppInfo))
					sessionInfo.Session.AppInfo = info.AppInfo;
				if (!string.IsNullOrWhiteSpace(info.OSInfo))
					sessionInfo.Session.OSInfo = info.OSInfo;

				sessionInfo.User.Name = sessionInfo.User.Name ?? (string.IsNullOrWhiteSpace(info.UserName) ? info.Crawler ? "Crawler" : null : info.UserName);
				if (!string.IsNullOrWhiteSpace(info.UserEmail))
					sessionInfo.User.Email = info.UserEmail;
				if (!string.IsNullOrWhiteSpace(info.UserLocation))
					sessionInfo.User.Location = info.UserLocation;

				if (!string.IsNullOrWhiteSpace(info.ServiceName))
					sessionInfo.Service.Name = info.ServiceName;
				if (!string.IsNullOrWhiteSpace(info.ServiceURI))
					sessionInfo.Service.URI = info.ServiceURI;
				if (!string.IsNullOrWhiteSpace(info.ServiceSystemID))
					sessionInfo.Service.SystemID = info.ServiceSystemID;

				var newIP = sessionInfo.Session.IP;
				if (!string.IsNullOrWhiteSpace(oldIP) && oldIP != newIP)
					if (this._sessionsByIP.TryGetValue(oldIP, out var oldSet))
					{
						oldSet.TryRemove(info.SessionID, out _);
						if (oldSet.IsEmpty)
							this._sessionsByIP.TryRemove(oldIP, out _);
					}

				if (!string.IsNullOrWhiteSpace(newIP))
				{
					var set = this._sessionsByIP.GetOrAdd(newIP, _ => []);
					set.TryAdd(info.SessionID, 0);
				}

				this.ScheduleLocation(sessionInfo, info.CorrelationID);
				this.ScheduleNormalization(sessionInfo);

				var updateLastAccess = (now - sessionInfo.User.LastAccess).TotalMinutes > 9;
				if (updateLastAccess)
				{
					sessionInfo.User.LastAccess = now;
					this.ScheduleLastAccess(sessionInfo.Session.UserID);
				}
			}
		}

		async Task ProcessLocationsAsync()
		{
			try
			{
				while (await this._locationQueue.Reader.WaitToReadAsync(this._cts.Token).ConfigureAwait(false))
					while (this._locationQueue.Reader.TryRead(out var info))
						try
						{
							await this.ProcessLocationAsync(info).ConfigureAwait(false);
						}
						catch (Exception ex)
						{
							await this._onErrorAsync(ex, info?.CorrelationID).ConfigureAwait(false);
						}
			}
			catch (OperationCanceledException) { }
			catch (Exception ex)
			{
				await this._onErrorAsync(ex, null).ConfigureAwait(false);
			}
		}

		async Task ProcessLocationAsync(LocationInfo info)
		{
			if (info == null || info.Session == null || string.IsNullOrWhiteSpace(info.Session.IP))
				return;

			try
			{
				if (this._locations.TryGetValue(info.Session.IP, out var location))
				{
					this.ApplyLocation(info.Session.IP, location);
					return;
				}

				using var cts = CancellationTokenSource.CreateLinkedTokenSource(this._cts.Token);
				cts.CancelAfter(TimeSpan.FromSeconds(this._backgroundTimeout));

				location = await info.Session.GetLocationAsync(info.CorrelationID, cts.Token).ConfigureAwait(false);
				if (!string.IsNullOrWhiteSpace(location))
				{
					this._locations[info.Session.IP] = location;
					this.ApplyLocation(info.Session.IP, location);
				}
			}
			catch (OperationCanceledException) { }
			finally
			{
				this._pendingLocations.TryRemove(info.Session.IP, out _);
			}
		}

		void ScheduleLocation(Services.Session session, string correlationID)
		{
			if (this._locations.TryGetValue(session.IP, out var location))
			{
				this.ApplyLocation(session.IP, location);
				return;
			}

			if (!this._pendingLocations.TryAdd(session.IP, 0))
				return;

			var info = new LocationInfo
			{
				Session = session,
				CorrelationID = correlationID
			};
			if (!this._locationQueue.Writer.TryWrite(info))
				this._pendingLocations.TryRemove(session.IP, out _);
		}

		void ScheduleLocation(SessionInfo sessionInfo, string correlationID)
		{
			if (string.IsNullOrWhiteSpace(sessionInfo.User.Location))
				this.ScheduleLocation(sessionInfo.Session.ToSession(), correlationID);
		}

		void ApplyLocation(string ip, string location)
		{
			if (string.IsNullOrWhiteSpace(ip) || string.IsNullOrWhiteSpace(location))
				return;

			if (!this._sessionsByIP.TryGetValue(ip, out var sessionIDs))
				return;

			foreach (var sessionID in sessionIDs.Keys)
			{
				if (!this._sessions.TryGetValue(sessionID, out var sessionInfo) || sessionInfo?.User == null)
					continue;

				lock (sessionInfo.Locker)
				{
					if (sessionInfo.Session?.IP == ip && sessionInfo.User.Location == null)
						sessionInfo.User.Location = location;
				}
			}
		}

		async Task ProcessNormalizationsAsync()
		{
			try
			{
				while (await this._normalizationQueue.Reader.WaitToReadAsync(this._cts.Token).ConfigureAwait(false))
					while (this._normalizationQueue.Reader.TryRead(out var sessionID))
						try
						{
							await this.ProcessNormalizationAsync(sessionID).ConfigureAwait(false);
						}
						catch (Exception ex)
						{
							await this._onErrorAsync(ex, null).ConfigureAwait(false);
						}
			}
			catch (OperationCanceledException) { }
			catch (Exception ex)
			{
				await this._onErrorAsync(ex, null).ConfigureAwait(false);
			}
		}

		async Task ProcessNormalizationAsync(string sessionID)
		{
			if (string.IsNullOrWhiteSpace(sessionID) || !this._sessions.TryGetValue(sessionID, out var sessionInfo))
				return;

			try
			{
				using var cts = CancellationTokenSource.CreateLinkedTokenSource(this._cts.Token);
				cts.CancelAfter(TimeSpan.FromSeconds(this._backgroundTimeout));

				if (string.IsNullOrWhiteSpace(sessionInfo.Session.DeviceID))
				{
					var session = string.IsNullOrWhiteSpace(sessionInfo.Session.UserID)
						? await Utility.Cache.GetAsync<Session>(sessionID.GetCacheKey<Session>(), cts.Token).ConfigureAwait(false)
						: await Session.GetAsync(sessionID, cts.Token).ConfigureAwait(false);
					lock (sessionInfo.Locker)
						sessionInfo.Session.DeviceID = session?.DeviceID;
				}

				if (string.IsNullOrWhiteSpace(sessionInfo.User.Name) || string.IsNullOrWhiteSpace(sessionInfo.User.Email))
				{
					var profile = await Profile.GetAsync(sessionInfo.Session.UserID, cts.Token).ConfigureAwait(false);
					if (profile != null)
						lock (sessionInfo.Locker)
						{
							sessionInfo.User.Name = profile?.Name;
							sessionInfo.User.Email = profile?.Email;
						}
				}
			}
			catch (OperationCanceledException) { }
			finally
			{
				this._pendingSessions.TryRemove(sessionID, out _);
			}
		}

		void ScheduleNormalization(string sessionID)
		{
			if (this._sessions.ContainsKey(sessionID) && this._pendingSessions.TryAdd(sessionID, 0))
			{
				if (!this._normalizationQueue.Writer.TryWrite(sessionID))
					this._pendingSessions.TryRemove(sessionID, out var _);
			}
		}

		void ScheduleNormalization(SessionInfo sessionInfo)
		{
			if (string.IsNullOrWhiteSpace(sessionInfo.Session.DeviceID) || (!string.IsNullOrWhiteSpace(sessionInfo.Session.UserID) && (string.IsNullOrWhiteSpace(sessionInfo.User.Name) || string.IsNullOrWhiteSpace(sessionInfo.User.Email))))
				this.ScheduleNormalization(sessionInfo.Session.ID);
		}

		async Task UpdateLastAccessesAsync()
		{
			try
			{
				while (await this._lastAccessQueue.Reader.WaitToReadAsync(this._cts.Token).ConfigureAwait(false))
					while (this._lastAccessQueue.Reader.TryRead(out var userID))
						try
						{
							await this.UpdateLastAccessAsync(userID).ConfigureAwait(false);
						}
						catch (Exception ex)
						{
							await this._onErrorAsync(ex, null).ConfigureAwait(false);
						}
			}
			catch (OperationCanceledException) { }
			catch (Exception ex)
			{
				await this._onErrorAsync(ex, null).ConfigureAwait(false);
			}
		}

		async Task UpdateLastAccessAsync(string userID)
		{
			try
			{
				using var cts = CancellationTokenSource.CreateLinkedTokenSource(this._cts.Token);
				cts.CancelAfter(TimeSpan.FromSeconds(this._backgroundTimeout));

				var account = await Account.GetAsync(userID, cts.Token).ConfigureAwait(false);
				if (account != null)
				{
					account.LastAccess = DateTime.UtcNow;
					await Account.UpdateAsync(account, true, cts.Token).ConfigureAwait(false);
				}
			}
			catch (OperationCanceledException) { }
			finally
			{
				this._pendingLastAccesses.TryRemove(userID, out _);
			}
		}

		void ScheduleLastAccess(string userID)
		{
			if (!string.IsNullOrWhiteSpace(userID) && this._pendingLastAccesses.TryAdd(userID, 0))
			{
				if (!this._lastAccessQueue.Writer.TryWrite(userID))
					this._pendingLastAccesses.TryRemove(userID, out var _);
			}
		}

		public int Count => this._sessions.Count;

		public IEnumerable<SessionInfo> Get(DateTime? checkpoint = null)
			=> checkpoint == null ? this._sessions.Values : this._sessions.Values.Where(sessionInfo => sessionInfo.LastAccess > checkpoint.Value);

		public void Update(string sessionID, SessionInfo sessionInfo)
			=> this._sessions.GetOrAdd(sessionID, _ => sessionInfo);

		public bool Track(TrackingInfo info)
			=> info != null && (!this._trackAuthenticatedOnly || !string.IsNullOrWhiteSpace(info.UserID)) && this._trackingQueue.Writer.TryWrite(info);

		public bool Track(JObject data)
			=> data != null && this.Track(new TrackingInfo(data));

		public bool Exist(string sessionID)
			=> !string.IsNullOrWhiteSpace(sessionID) && this._sessions.ContainsKey(sessionID);

		public bool Remove(string sessionID)
			=> this._sessions.TryRemove(sessionID, out _);

		public Task ClearAsync(Func<IEnumerable<string>, Task> onCompletedAsync = null)
		{
			var ids = this._sessions.Where(kvp => string.IsNullOrWhiteSpace(kvp.Value.Session.UserID)).Select(kvp => kvp.Key).ToList();
			ids.ForEach(id => this.Remove(id));
			return onCompletedAsync != null ? onCompletedAsync(ids) : Task.CompletedTask;
		}

		public async Task ReloadAsync(string correlationID, CancellationToken cancellationToken, Func<IEnumerable<SessionInfo>, Task> onCompletedAsync = null)
		{
			var sessions = new List<SessionInfo>();
			var reloadeds = await Session.FindAsync(Filters<Session>.Equals("Online", true), Sorts<Session>.Descending("RenewedAt"), 0, 1, null, false, null, 0, cancellationToken).ConfigureAwait(false);
			await reloadeds.ForEachAsync(async session =>
			{
				var profile = await Profile.GetAsync(session.UserID, cancellationToken).ConfigureAwait(false);
				var sessionInfo = new SessionInfo
				{
					Session = session,
					User = new()
					{
						Name = profile?.Name,
						Email = profile?.Email,
						LastAccess = session.RenewedAt
					},
					Service = new(),
					LastAccess = session.RenewedAt
				};
				this._sessions.AddOrUpdate(sessionInfo.Session.ID, sessionInfo, (_, _) => sessionInfo);
				this.ScheduleLocation(sessionInfo, correlationID);
				if (onCompletedAsync != null)
					sessions.Add(sessionInfo);
			}, true, false).ConfigureAwait(false);
			if (onCompletedAsync != null)
				await onCompletedAsync(sessions).ConfigureAwait(false);
		}

		public Task CleanupAsync(TimeSpan userIdle, TimeSpan visitorIdle, Func<IEnumerable<SessionInfo>, Task> onCompletedAsync)
		{
			var now = DateTime.Now;
			var sessions = new List<SessionInfo>();
			foreach (var kvp in this._sessions)
			{
				var sessionInfo = kvp.Value;
				if (sessionInfo != null)
				{
					var expired = false;
					lock (sessionInfo.Locker)
						expired = (now - sessionInfo.LastAccess) > (string.IsNullOrWhiteSpace(sessionInfo.Session.UserID) ? visitorIdle : userIdle);
					if (expired && this._sessions.TryRemove(kvp.Key, out _) && onCompletedAsync != null)
						sessions.Add(sessionInfo);
				}
			}
			return onCompletedAsync != null ? onCompletedAsync(sessions) : Task.CompletedTask;
		}

		public Task CleanupAsync(Func<IEnumerable<SessionInfo>, Task> onCompletedAsync = null)
			=> this.CleanupAsync(TimeSpan.FromMinutes(25), TimeSpan.FromMinutes(15), onCompletedAsync);

		public Task DumpAsync(CancellationToken cancellationToken)
			=> this._sessions.Values.ToJArray().SaveAsTextAsync(Path.Combine(UtilityService.GetAppSetting("Path:Status", "status"), "statistics.session.json"), cancellationToken);

		public async Task LoadDumpAsync(CancellationToken cancellationToken)
		{
			var filePath = Path.Combine(UtilityService.GetAppSetting("Path:Status", "status"), "statistics.session.json");
			if (File.Exists(filePath))
				try
				{
					var json = await UtilityService.ReadAsJsonAsync(filePath, cancellationToken).ConfigureAwait(false) as JArray;
					json.Select(sessionJson => sessionJson as JObject).ForEach(sessionJson =>
					{
						var sessionInfo = new SessionInfo(sessionJson);
						this._sessions.TryAdd(sessionInfo.Session.ID, sessionInfo);
					});
				}
				catch (Exception ex)
				{
					Utility.Logger?.LogInformation($"Load dump JSONs error => {ex.Message}", ex);
				}
		}
	}

}