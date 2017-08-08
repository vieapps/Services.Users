#region Related components
using System;
using System.Linq;
using System.Threading.Tasks;

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

		internal void Start(string[] args = null, Func<Task> continuationAsync = null)
		{
			// initialize repositorites
			try
			{
				RepositoryStarter.Initialize();
			}
			catch (Exception ex)
			{
				Console.WriteLine("Error occurred while initializing the repository: " + ex.Message + "\r\n" + ex.StackTrace);
			}

			// start the service
			Task.Run(async () =>
			{
				try
				{
					await this.StartAsync(
						() => {
							Console.WriteLine("The service [" + this.ServiceURI + "] is registered");
						},
						(ex) => {
							Console.WriteLine("Error occurred while registering the service [" + this.ServiceURI + "]: " + ex.Message + "\r\n" + ex.StackTrace);
						},
						this.OnInterCommunicateMessageReceived
					);
				}
				catch (Exception ex)
				{
					Console.WriteLine("Error occurred while starting the service [" + this.ServiceURI + "]: " + ex.Message + "\r\n" + ex.StackTrace);
				}
			})
			.ContinueWith(async (task) =>
			{
				if (continuationAsync != null)
					try
					{
						await continuationAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Console.WriteLine("Error occurred while running the continuation function: " + ex.Message + "\r\n" + ex.StackTrace);
					}
			})
			.ConfigureAwait(false);
		}
		#endregion

		public override string ServiceName { get { return "users"; } }

		public override async Task<JObject> ProcessRequestAsync(RequestInfo requestInfo)
		{
			try
			{
				switch (requestInfo.ObjectName.ToLower())
				{

					#region Session
					case "session":
						switch (requestInfo.Verb)
						{
							// initialize or register
							case "GET":
								if (requestInfo.Session.User == null)
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
					
					#region Profile
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
				throw new InvalidRequestException("Invalid request [" + this.ServiceURI + "]: " + requestInfo.Verb + (!string.IsNullOrWhiteSpace(requestInfo.ObjectName) ? " (" + requestInfo.ObjectName + ")" : ""));
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex.Message + " - Correlation ID: " + requestInfo.CorrelationID);
				throw this.GetRuntimeException(requestInfo, ex);
			} 
		}

		#region Session
		async Task<JObject> InitializeSessionAsync(RequestInfo requestInfo)
		{
			// prepare
			if (string.IsNullOrWhiteSpace(requestInfo.Session.SessionID))
				requestInfo.Session.SessionID = UtilityService.GetUUID();

			var deviceID = requestInfo.GetDeviceID();
			if (string.IsNullOrWhiteSpace(deviceID))
			{
				var appName = requestInfo.GetAppName();
				if (string.IsNullOrWhiteSpace(appName))
					appName = "N/A (" + UtilityService.NewUID + ")";

				var appPlatform = requestInfo.GetAppPlatform();
				if (string.IsNullOrWhiteSpace(appPlatform))
					appPlatform = "N/A (" + UtilityService.NewUID + ")";

				deviceID = "pwa@" + (appName + "/" + appPlatform + "@" + requestInfo.Session.AppAgent).GetHMACSHA384(requestInfo.Session.SessionID, true);
			}

			// update into cache to mark the session is issued by the system
			await Global.Cache.SetAbsoluteAsync(requestInfo.Session.SessionID.GetCacheKey<Session>(), deviceID, 7);

			// response
			return new JObject()
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "DeviceID", deviceID }
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

				if (string.IsNullOrWhiteSpace(sessionID) || string.IsNullOrWhiteSpace(requestInfo.Session.SessionID) || !await Global.Cache.ExistsAsync<Session>(sessionID))
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
				await Global.Cache.SetAsync(session, 120);

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

			// response
			return new JObject()
			{
				{ "ID", requestSession.SessionID },
				{ "DeviceID", requestSession.DeviceID }
			};
		}

		async Task<JObject> CheckSessionExistedAsync(RequestInfo requestInfo)
		{
			var isExisted = requestInfo.Session.User == null
				? await Global.Cache.ExistsAsync<Session>(requestInfo.Session.SessionID)
				: (await Session.GetAsync<Session>(requestInfo.Session.SessionID)) != null;

			return new JObject()
			{
				{ "Existed", isExisted }
			};
		}

		async Task<JObject> ValidateSessionAsync(RequestInfo requestInfo)
		{
			var session = requestInfo.Session.User == null || string.IsNullOrWhiteSpace(requestInfo.Session.User.ID)
				? await Global.Cache.GetAsync<Session>(requestInfo.Session.SessionID)
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
			else if (requestInfo.Session.User != null && !string.IsNullOrWhiteSpace(requestInfo.Session.User.ID) && !session.AccessToken.Equals(accessToken))
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

				Global.Cache.Remove(key);
				return result;
			}
			catch (Exception ex)
			{
				var attempt = await Global.Cache.ExistsAsync(key)
					? await Global.Cache.GetAsync<int>(key)
					: 1;

				await Task.WhenAll(
						Task.Delay((attempt - 1) * 5000),
						Global.Cache.SetAbsoluteAsync(key, attempt, 15)
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
			await Global.Cache.SetAbsoluteAsync(sessionID.GetCacheKey<Session>(), requestInfo.Session.DeviceID, 7);

			// response
			return new JObject()
			{
				{ "ID", sessionID },
				{ "DeviceID", requestInfo.Session.DeviceID }
			};
		}
		#endregion

		#region Profile
		#endregion

		#region Update with inter-communicate messages
		void OnInterCommunicateMessageReceived(BaseMessage message)
		{

		}
		#endregion

		~ServiceComponent()
		{
			this.Dispose();
		}
	}
}