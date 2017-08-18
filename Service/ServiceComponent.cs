#region Related components
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	public class ServiceComponent : BaseService
	{

		#region Start
		public ServiceComponent() { }

		void WriteInfo(string info, Exception ex = null)
		{
			var msg = string.IsNullOrWhiteSpace(info)
				? ex != null ? ex.Message : ""
				: info;

			Console.WriteLine("~~~~~~~~~~~~~~~~~~~~>");
			Console.WriteLine(msg);
			if (ex != null)
				Console.WriteLine("-----------------------\r\n" + "==> [" + ex.GetType().GetTypeName(true) + "]: " + ex.Message + "\r\n" + ex.StackTrace + "\r\n-----------------------");
		}

		internal void Start(string[] args = null, System.Action nextAction = null, Func<Task> nextActionAsync = null)
		{
			// initialize repositorites
			try
			{
				this.WriteInfo("Initializing the repository");
				RepositoryStarter.Initialize();
			}
			catch (Exception ex)
			{
				this.WriteInfo("Error occurred while initializing the repository", ex);
			}

			// start the service
			Task.Run(async () =>
			{
				try
				{
					await this.StartAsync(
						() => {
							var pid = Process.GetCurrentProcess().Id.ToString();
							this.WriteInfo("The service is registered - PID: " + pid);
							this.WriteLog(UtilityService.BlankUID, this.ServiceName, null, "The service [" + this.ServiceURI + "] is registered - PID: " + pid);
						},
						ex => this.WriteInfo("Error occurred while registering the service", ex),
						this.OnInterCommunicateMessageReceived
					);
				}
				catch (Exception ex)
				{
					this.WriteInfo("Error occurred while starting the service", ex);
				}
			})
			.ContinueWith(async (task) =>
			{
				try
				{
					nextAction?.Invoke();
				}
				catch (Exception ex)
				{
					this.WriteInfo("Error occurred while running the next action (sync)", ex);
				}
				if (nextActionAsync != null)
					try
					{
						await nextActionAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						this.WriteInfo("Error occurred while running the next action (async)", ex);
					}
			})
			.ConfigureAwait(false);
		}
		#endregion

		public override string ServiceName { get { return "users"; } }

		public override async Task<JObject> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
		{
			try
			{
				switch (requestInfo.ObjectName.ToLower())
				{

					#region Sessions
					case "session":
						switch (requestInfo.Verb)
						{
							// initialize or register
							case "GET":
								if (requestInfo.Session.User.ID.Equals("") && !requestInfo.Query.ContainsKey("anonymous"))
									return await this.InitializeSessionAsync(requestInfo);
								else
									return await this.RegisterSessionAsync(requestInfo);

							// sign-in
							case "POST":
								return await this.SignInAsync(requestInfo);

							// update session with access token
							case "PUT":
								return await this.RegisterSessionAsync(requestInfo.Session, (requestInfo.GetBodyJson()["AccessToken"] as JValue).Value.ToString().Decrypt());

							// sign-out
							case "DELETE":
								return await this.SignOutAsync(requestInfo);
						}
						break;
					#endregion

					#region Profiles
					case "search":
						return await this.SearchProfilesAsync(requestInfo);

					case "fetch":
						break;

					case "profile":
						switch (requestInfo.Verb)
						{
							// get detail
							case "GET":
								return await this.GetProfileAsync(requestInfo);

							// update profile
							case "POST":
								return await this.UpdateProfileAsync(requestInfo);
						}
						break;
					#endregion

					#region Mediator
					case "mediator":
						if (requestInfo.Verb.IsEquals("GET") && requestInfo.Extra != null)
						{
							if (requestInfo.Extra.ContainsKey("Exist"))
								return await this.CheckSessionExistedAsync(requestInfo);
							else if (requestInfo.Extra.ContainsKey("Verify"))
								return await this.ValidateSessionAsync(requestInfo);
							else if (requestInfo.Extra.ContainsKey("Account"))
								return await this.GetAccountInfoAsync(requestInfo);
						}
						break;
					#endregion

				}

				// unknown
				var msg = "The request is invalid [" + this.ServiceURI + "]: " + requestInfo.Verb + " /";
				if (!string.IsNullOrWhiteSpace(requestInfo.ObjectName))
					msg +=  requestInfo.ObjectName + (requestInfo.Query.ContainsKey("object-identity") ? "/" + requestInfo.Query["object-identity"] : "");
				throw new InvalidRequestException(msg);
			}
			catch (Exception ex)
			{
#if DEBUG
				this.WriteInfo("Error occurred while processing\r\n==> Request:\r\n" + requestInfo.ToJson().ToString(Newtonsoft.Json.Formatting.Indented), ex);
#else
				this.WriteInfo("Error occurred while processing - Correlation ID: " + requestInfo.CorrelationID);
#endif
				throw this.GetRuntimeException(requestInfo, ex);
			} 
		}

		#region Session
		async Task<JObject> InitializeSessionAsync(RequestInfo requestInfo)
		{
			// prepare
			if (string.IsNullOrWhiteSpace(requestInfo.GetDeviceID()))
			{
				var appName = requestInfo.GetAppName();
				if (string.IsNullOrWhiteSpace(appName))
					appName = "N/A (" + UtilityService.NewUID + ")";

				var appPlatform = requestInfo.GetAppPlatform();
				if (string.IsNullOrWhiteSpace(appPlatform))
					appPlatform = "N/A (" + UtilityService.NewUID + ")";

				requestInfo.Session.DeviceID = "pwa@" + (appName + "/" + appPlatform + "@" + requestInfo.Session.AppAgent).GetHMACSHA384(requestInfo.Session.SessionID, true);
			}

			// update into cache to mark the session is issued by the system
			await Utility.Cache.SetAbsoluteAsync(requestInfo.Session.SessionID.GetCacheKey<Session>(), requestInfo.Session.DeviceID, 7);

#if DEBUG
			this.WriteInfo("A session has been initialized" + "\r\n" + requestInfo.ToJson().ToString(Newtonsoft.Json.Formatting.Indented));
#endif

			// response
			return new JObject()
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "DeviceID", requestInfo.Session.DeviceID }
			};
		}

		async Task<JObject> RegisterSessionAsync(RequestInfo requestInfo)
		{
			// anonymous/visitor
			if (string.IsNullOrWhiteSpace(requestInfo.Session.User.ID))
			{
				var sessionID = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("SessionID")
					? requestInfo.Extra["SessionID"].Decrypt()
					: null;

				if (string.IsNullOrWhiteSpace(sessionID) || string.IsNullOrWhiteSpace(requestInfo.Session.SessionID) || !await Utility.Cache.ExistsAsync<Session>(sessionID))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

				// register new session
				var session = new Session()
				{
					ID = requestInfo.Session.SessionID,
					IP = requestInfo.Session.IP,
					DeviceID = requestInfo.Session.DeviceID,
					AppPlatform = requestInfo.Session.AppName + " / " + requestInfo.Session.AppPlatform,
					AccessToken = requestInfo.Extra.ContainsKey("AccessToken") ? requestInfo.Extra["AccessToken"].Decrypt() : null
				};

				// update cache
				await Utility.Cache.SetAsync(session, 120);

#if DEBUG
				this.WriteInfo("A session of visitor has been registered" + "\r\n" + session.ToJson().ToString(Newtonsoft.Json.Formatting.Indented));
#endif

				// response
				return new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
			}

			// user
			else
				return await this.RegisterSessionAsync(requestInfo.Session);
		}

		async Task<JObject> RegisterSessionAsync(Services.Session requestSession, string accessToken = null)
		{
			// check account
			var userAccount = await Account.GetAsync<Account>(requestSession.User.ID);
			if (userAccount == null)
				throw new InvalidSessionException("Account is not found");

			// check session
			var userSession = await Session.GetAsync<Session>(requestSession.SessionID);
			if (userSession == null || !userSession.UserID.Equals(userAccount.ID))
				throw new InvalidSessionException("Session is not found");

			// update (renew) session
			userSession.ExpiredAt = DateTime.Now.AddDays(60);
			userSession.AccessToken = string.IsNullOrWhiteSpace(accessToken)
				? userSession.AccessToken
				: accessToken;
			await Session.UpdateAsync(userSession);

			// update statistics of the account
			userAccount.LastAccess = DateTime.Now;
			if (userAccount.Sessions == null)
				userAccount.Sessions = await Session.FindAsync<Session>(Filters<Session>.Equals("UserID", userAccount.ID), Sorts<Session>.Descending("ExpiredAt"), 0, 1);
			else
			{
				userAccount.Sessions.Insert(0, userSession);
				userAccount.Sessions = userAccount.Sessions.ToDictionary(s => s.ID).Select(i => i.Value).ToList();
			}
			await Account.UpdateAsync(userAccount);

#if DEBUG
			this.WriteInfo("A session of user has been registered" + "\r\n" + userSession.ToJson().ToString(Newtonsoft.Json.Formatting.Indented));
#endif

			// response
			return new JObject()
			{
				{ "ID", requestSession.SessionID },
				{ "DeviceID", requestSession.DeviceID }
			};
		}

		async Task<JObject> CheckSessionExistedAsync(RequestInfo requestInfo)
		{
			var isExisted = string.IsNullOrWhiteSpace(requestInfo.Session.User.ID)
				? await Utility.Cache.ExistsAsync<Session>(requestInfo.Session.SessionID)
				: (await Session.GetAsync<Session>(requestInfo.Session.SessionID)) != null;

			return new JObject()
			{
				{ "Existed", isExisted }
			};
		}

		async Task<JObject> ValidateSessionAsync(RequestInfo requestInfo)
		{
			var session = string.IsNullOrWhiteSpace(requestInfo.Session.User.ID)
				? await Utility.Cache.GetAsync<Session>(requestInfo.Session.SessionID)
				: await Session.GetAsync<Session>(requestInfo.Session.SessionID);

			if (session == null)
				throw new SessionNotFoundException();
			else if (session.ExpiredAt < DateTime.Now)
				throw new SessionExpiredException();

			var accessToken = requestInfo.Extra.ContainsKey("AccessToken")
				? requestInfo.Extra["AccessToken"].Decrypt()
				: null;

			if (string.IsNullOrWhiteSpace(accessToken))
				throw new InvalidSessionException();
			else if (requestInfo.Session.User != null && (!string.IsNullOrWhiteSpace(requestInfo.Session.User.ID) || !session.AccessToken.Equals(accessToken)))
				throw new TokenRevokedException();

			return new JObject()
			{
				{ "Status", "OK" }
			};
		}

		async Task<JObject> GetAccountInfoAsync(RequestInfo requestInfo)
		{
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID);
			if (account == null)
				throw new InvalidSessionException("Account is not found");

			var json = new JObject()
			{
				{ "ID", account.ID },
				{ "Role", account.AccountRole.ToString() }
			};

			if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Full"))
			{
				json.Add(new JProperty("Roles", account.AccountRoles));
				json.Add(new JProperty("Privileges", account.AccountPrivileges));
			}

			return json;
		}
		#endregion

		#region Sign In
		async Task<JObject> SignInAsync(RequestInfo requestInfo)
		{
			var key = "Attempt#" + requestInfo.Session.IP;
			try
			{
				var accountType = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Type")
					? requestInfo.Extra["Type"].ToEnum<AccountType>()
					: AccountType.BuiltIn;

				JObject result = null;
				switch (accountType)
				{
					default:
						result = await this.SignBuiltInAccountInAsync(requestInfo);
						break;
				}

				Utility.Cache.Remove(key);
				return result;
			}
			catch (Exception ex)
			{
				var attempt = await Utility.Cache.ExistsAsync(key)
					? await Utility.Cache.GetAsync<int>(key)
					: 1;

				await Task.WhenAll(
						Task.Delay((attempt - 1) * 5000),
						Utility.Cache.SetAbsoluteAsync(key, attempt, 15)
					);

				throw ex;
			}
		}

		async Task<JObject> SignBuiltInAccountInAsync(RequestInfo requestInfo)
		{
			// prepare
			var email = requestInfo.Extra.ContainsKey("Email")
				? requestInfo.Extra["Email"].Decrypt()
				: null;
			var password = requestInfo.Extra.ContainsKey("Password")
				? requestInfo.Extra["Password"].Decrypt()
				: null;

			// find account & check
			var account = await Account.GetAsync<Account>(Filters<Account>.Equals("AccountName", email.Trim().ToLower()));
			if (account == null || !account.AccountKey.Equals(Account.HashPassword(account.ID, password)))
				throw new WrongAccountException();

			// register session
			Session.Create(new Session()
			{
				ID = requestInfo.Session.SessionID,
				UserID = account.ID,
				AccessToken = "",
				IP = requestInfo.Session.IP,
				DeviceID = requestInfo.Session.DeviceID,
				AppPlatform = requestInfo.Session.AppName + "/" + requestInfo.Session.AppPlatform,
				Online = true
			});

			// response
			return new JObject()
			{
				{ "ID", account.ID }
			};
		}
		#endregion

		#region Sign Out
		async Task<JObject> SignOutAsync(RequestInfo requestInfo)
		{
			// get account and perform sign-out
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID);
			if (account != null)
			{
				if (account.Sessions == null)
					account.Sessions = await Session.FindAsync<Session>(Filters<Session>.Equals("UserID", requestInfo.Session.User.ID), Sorts<Session>.Descending("ExpiredAt"), 0, 1);
				account.Sessions = account.Sessions.Where(s => !s.ID.Equals(requestInfo.Session.SessionID)).ToList();
				account.LastAccess = DateTime.Now;

				await Task.WhenAll(
						Session.DeleteAsync<Session>(requestInfo.Session.SessionID),
						Account.UpdateAsync(account)
					);
			}

			// update into cache to mark the session is issued by the system
			var sessionID = UtilityService.GetUUID();
			await Utility.Cache.SetAbsoluteAsync(sessionID.GetCacheKey<Session>(), requestInfo.Session.DeviceID, 7);

			// response
			return new JObject()
			{
				{ "ID", sessionID },
				{ "DeviceID", requestInfo.Session.DeviceID }
			};
		}
		#endregion

		#region Search profiles
		void NormalizeProfile(JObject json)
		{
			var value = json["Email"] != null && json["Email"] is JValue && (json["Email"] as JValue).Value != null
				? (json["Email"] as JValue).Value.ToString()
				: null;
			if (!string.IsNullOrWhiteSpace(value))
				(json["Email"] as JValue).Value = value.Left(value.Length - value.IndexOf("@"));

			value = json["Mobile"] != null && json["Mobile"] is JValue && (json["Mobile"] as JValue).Value != null
				? (json["Mobile"] as JValue).Value.ToString()
				: null;
			if (!string.IsNullOrWhiteSpace(value))
				(json["Mobile"] as JValue).Value = "xxxxxx" + value.Trim().Replace(" ", "").Right(4);
		}

		async Task<JObject> SearchProfilesAsync(RequestInfo requestInfo)
		{
			// check
			if (!this.IsAuthenticated(requestInfo))
				throw new AccessDeniedException();
			else if (!this.IsAuthorized(requestInfo, Components.Security.Action.Vote))
				throw new AccessDeniedException();

			// prepare
			var request = requestInfo.GetRequestExpando();

			var query = request.Get<string>("FilterBy.Query");
			var province = request.Get<string>("FilterBy.Province");
			var filter = string.IsNullOrWhiteSpace(province)
				? null
				: Filters<Profile>.Equals("Province", province);


			var pageNumber = request.Has("Pagination.PageNumber")
				? request.Get<int>("Pagination.PageNumber")
				: 1;
			if (pageNumber < 1)
				pageNumber = 1;

			var pageSize = request.Has("Pagination.PageSize")
				? request.Get<int>("Pagination.PageSize")
				: 20;
			if (pageSize < 0)
				pageSize = 20;

			// get total of records
			var totalRecords = request.Has("Pagination.TotalRecords")
				? request.Get<long>("Pagination.TotalRecords")
				: -1;
			if (totalRecords < 0)
				totalRecords = string.IsNullOrWhiteSpace(query)
					? await Profile.CountAsync(filter)
					: await Profile.CountByQueryAsync(query, filter);

			var totalPages = (int)(totalRecords / pageSize);
			if (totalRecords - (totalPages * pageSize) > 0)
				totalPages += 1;
			if (totalPages > 0 && pageNumber > totalPages)
				pageNumber = totalPages;

			// get objects
			var objects = string.IsNullOrWhiteSpace(query)
				? await Profile.FindAsync(filter, Sorts<Profile>.Ascending("Name"), pageSize, pageNumber)
				: await Profile.SearchAsync(query, filter, pageSize, pageNumber);

			// generate JSONs
			var data = objects.ToJsonArray();
			if (!requestInfo.Session.User.Role.Equals(SystemRole.SystemAdministrator))
				foreach (JObject json in data)
					this.NormalizeProfile(json);

			// return information
			return new JObject()
			{
				{ "FilterBy", new JObject()
					{
						{ "Query", !string.IsNullOrWhiteSpace(query) ? query : "" },
						{ "Province", !string.IsNullOrWhiteSpace(province) ? province : "" }
					}
				},
				{ "Pagination", new JObject()
					{
						{ "TotalRecords", totalRecords },
						{ "TotalPages", totalPages},
						{ "PageSize", pageSize },
						{ "PageNumber", pageNumber },
					}
				},
				{ "Objects", data }
			};
		}
		#endregion

		#region Get profile
		async Task<JObject> GetProfileAsync(RequestInfo requestInfo)
		{
			// check
			if (!this.IsAuthenticated(requestInfo))
				throw new AccessDeniedException();
			else if (!this.IsAuthorized(requestInfo, Components.Security.Action.Vote))
				throw new AccessDeniedException();

			// get information
			var profile = await Profile.GetAsync<Profile>(requestInfo.Query.ContainsKey("object-identity") ? requestInfo.Query["object-identity"] : requestInfo.Session.User.ID);
			if (profile == null)
				throw new InformationNotFoundException();

			// return information
			var json = profile.ToJson();
			if (!requestInfo.Session.User.ID.Equals(profile.ID))
				this.NormalizeProfile(json);
			return json;
		}
		#endregion

		#region Update profile
		async Task<JObject> UpdateProfileAsync(RequestInfo requestInfo)
		{
			await Task.Delay(0);
			return new JObject();
		}
		#endregion

		void OnInterCommunicateMessageReceived(CommunicateMessage message)
		{

		}

		~ServiceComponent()
		{
			this.Dispose(false);
		}
	}
}