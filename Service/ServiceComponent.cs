#region Related components
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.Dynamic;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
using net.vieapps.Components.Caching;
#endregion

namespace net.vieapps.Services.Users
{
	public class ServiceComponent : BaseService
	{

		#region Attributes
		static string _ActivationKey = null;

		internal static string ActivationKey
		{
			get
			{
				if (ServiceComponent._ActivationKey == null)
					ServiceComponent._ActivationKey = UtilityService.GetAppSetting("ActivationKey", "VIEApps-56BA2999-Services-A2E4-Users-4B54-Activation-83EB-Key-693C250DC95D");
				return ServiceComponent._ActivationKey;
			}
		}
		#endregion

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
				var objectIdentity = requestInfo.GetObjectIdentity();
				switch (requestInfo.ObjectName.ToLower())
				{

					#region Sessions
					case "session":
						switch (requestInfo.Verb)
						{
							// initialize or register
							case "GET":
								if ((requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.ID.Equals(User.SystemAccountID)) && !requestInfo.Query.ContainsKey("register"))
									return await this.InitializeSessionAsync(requestInfo);
								else
									return await this.RegisterSessionAsync(requestInfo, cancellationToken);

							// sign-in
							case "POST":
								return await this.SignInAsync(requestInfo, cancellationToken);

							// update session with access token
							case "PUT":
								return await this.RegisterSessionAsync(requestInfo.Session, (requestInfo.GetBodyJson()["AccessToken"] as JValue).Value.ToString().Decrypt(), cancellationToken);

							// sign-out
							case "DELETE":
								return await this.SignOutAsync(requestInfo);
						}
						break;
					#endregion

					#region Accounts
					case "account":
						switch (requestInfo.Verb)
						{
							case "GET":
								throw new MethodNotAllowedException(requestInfo.Verb);

							case "POST":
								if (requestInfo.Query.ContainsKey("x-convert"))
									return await this.CreateAccountAsync(requestInfo, cancellationToken);
								throw new MethodNotAllowedException(requestInfo.Verb);

							case "PUT":
								return await this.ResetPasswordAsync(requestInfo, cancellationToken);

							default:
								throw new MethodNotAllowedException(requestInfo.Verb);
						}
					#endregion

					#region Profiles
					case "profile":
						switch (requestInfo.Verb)
						{
							case "GET":
								// search
								if ("search".IsEquals(objectIdentity))
									return await this.SearchProfilesAsync(requestInfo, cancellationToken);

								// fetch
								else if ("fetch".IsEquals(objectIdentity))
									return await this.FetchProfilesAsync(requestInfo, cancellationToken);
								
								// get details of a profile
								else
									return await this.GetProfileAsync(requestInfo, cancellationToken);

							case "POST":
								// create profile
								if (requestInfo.Query.ContainsKey("x-convert"))
									return await this.CreateProfileAsync(requestInfo, cancellationToken);

								// update profile
								else
									return await this.UpdateProfileAsync(requestInfo, cancellationToken);
						}
						break;
					#endregion

					#region Activate
					case "activate":
						if (requestInfo.Verb.IsEquals("GET"))
							return await this.ActivateAsync(requestInfo, cancellationToken);
						throw new MethodNotAllowedException(requestInfo.Verb);
					#endregion

					#region Mediator & Captcha
					case "mediator":
						if (requestInfo.Verb.IsEquals("GET") && requestInfo.Extra != null)
						{
							// check exist
							if (requestInfo.Extra.ContainsKey("Exist"))
								return await this.CheckSessionExistedAsync(requestInfo, cancellationToken);

							// verify/validate
							else if (requestInfo.Extra.ContainsKey("Verify"))
								return await this.ValidateSessionAsync(requestInfo, cancellationToken);

							// get account information
							else if (requestInfo.Extra.ContainsKey("Account"))
								return await this.GetAccountInfoAsync(requestInfo, cancellationToken);
						}
						throw new MethodNotAllowedException(requestInfo.Verb);

					case "captcha":
						if (requestInfo.Verb.IsEquals("GET"))
							return this.RegisterSessionCaptcha(requestInfo);
						throw new MethodNotAllowedException(requestInfo.Verb);
					#endregion

				}

				// unknown
				var msg = "The request is invalid [" + this.ServiceURI + "]: " + requestInfo.Verb + " /";
				if (!string.IsNullOrWhiteSpace(requestInfo.ObjectName))
					msg +=  requestInfo.ObjectName + (!string.IsNullOrWhiteSpace(objectIdentity) ? "/" + objectIdentity : "");
				throw new InvalidRequestException(msg);
			}
			catch (Exception ex)
			{
#if DEBUG
				this.WriteInfo("Error occurred while processing\r\n==> Request:\r\n" + requestInfo.ToJson().ToString(Formatting.Indented), ex);
#else
				this.WriteInfo("Error occurred while processing - Correlation ID: " + requestInfo.CorrelationID);
#endif
				throw this.GetRuntimeException(requestInfo, ex);
			} 
		}

		#region Initialize session
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

				requestInfo.Session.DeviceID = "pwa@" + (appName + "/" + appPlatform + "@" + (requestInfo.Session.AppAgent ?? "N/A")).GetHMACSHA384(requestInfo.Session.SessionID, true);
			}

			// update into cache to mark the session is issued by the system
			await Utility.Cache.SetAbsoluteAsync(requestInfo.Session.SessionID.GetCacheKey<Session>(), requestInfo.Session.DeviceID, 7);

#if DEBUG
			this.WriteInfo("A session has been initialized" + "\r\n" + requestInfo.ToJson().ToString(Formatting.Indented));
#endif

			// response
			return new JObject()
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "DeviceID", requestInfo.Session.DeviceID }
			};
		}
		#endregion

		#region Register session
		async Task<JObject> RegisterSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// anonymous/visitor or system account
			if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.ID.IsEquals(User.SystemAccountID))
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
					AppInfo = requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform,
					AccessToken = requestInfo.Extra.ContainsKey("AccessToken") ? requestInfo.Extra["AccessToken"].Decrypt() : null
				};

				// update cache
				await Utility.Cache.SetAsync(session, 180);

#if DEBUG
				this.WriteInfo("A session of " + (requestInfo.Session.User.ID.Equals("") ? "visitor" : "system account") + " has been registered" + "\r\n" + session.ToJson().ToString(Formatting.Indented));
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
				return await this.RegisterSessionAsync(requestInfo.Session, null, cancellationToken);
		}

		async Task<JObject> RegisterSessionAsync(Services.Session requestSession, string accessToken = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			// check account
			var userAccount = await Account.GetAsync<Account>(requestSession.User.ID, cancellationToken);
			if (userAccount == null)
				throw new InvalidSessionException("Account is not found");

			// check session
			var userSession = await Session.GetAsync<Session>(requestSession.SessionID, cancellationToken);
			if (userSession == null || !userSession.UserID.Equals(userAccount.ID))
				throw new InvalidSessionException("Session is not found");

			// update (renew) session
			userSession.ExpiredAt = DateTime.Now.AddDays(60);
			userSession.AccessToken = accessToken ?? userSession.AccessToken;
			userSession.AppInfo = requestSession.AppName + " @ " + requestSession.AppPlatform;
			await Session.UpdateAsync(userSession, cancellationToken);

			// update statistics of the account
			userAccount.LastAccess = DateTime.Now;
			if (userAccount.Sessions == null)
				userAccount.Sessions = await Session.FindAsync(Filters<Session>.Equals("UserID", userAccount.ID), Sorts<Session>.Descending("ExpiredAt"), 0, 1);
			else
			{
				var sessions = userAccount.Sessions.ToDictionary(s => s.ID);
				if (sessions.ContainsKey(userSession.ID))
					sessions[userSession.ID] = userSession;
				else
					sessions.Add(userSession.ID, userSession);
				userAccount.Sessions = sessions.Select(i => i.Value).ToList();
			}
			await Account.UpdateAsync(userAccount, cancellationToken);

#if DEBUG
			this.WriteInfo("A session of user has been registered" + "\r\n" + userSession.ToJson().ToString(Formatting.Indented));
#endif

			// response
			return new JObject()
			{
				{ "ID", requestSession.SessionID },
				{ "DeviceID", requestSession.DeviceID }
			};
		}
		#endregion

		#region Sign In
		async Task<JObject> SignInAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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
						result = await this.SignBuiltInAccountInAsync(requestInfo, cancellationToken);
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

		async Task<JObject> SignBuiltInAccountInAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var email = requestInfo.Extra.ContainsKey("Email")
				? requestInfo.Extra["Email"].Decrypt()
				: null;
			var password = requestInfo.Extra.ContainsKey("Password")
				? requestInfo.Extra["Password"].Decrypt()
				: null;

			// find account & check
			var account = await Account.GetAsync<Account>(Filters<Account>.And(Filters<Account>.Equals("AccountName", email), Filters<Account>.Equals("Type", AccountType.BuiltIn.ToString())));
			if (account == null || !account.AccountKey.Equals(Account.HashPassword(account.ID, password)))
				throw new WrongAccountException();

			// register session
			await Session.CreateAsync(new Session()
			{
				ID = requestInfo.Session.SessionID,
				UserID = account.ID,
				AccessToken = "",
				IP = requestInfo.Session.IP,
				DeviceID = requestInfo.Session.DeviceID,
				AppInfo = requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform,
				Online = true
			}, cancellationToken);

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
					account.Sessions = await Session.FindAsync(Filters<Session>.Equals("UserID", requestInfo.Session.User.ID), Sorts<Session>.Descending("ExpiredAt"), 0, 1);
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

		#region Create account
		async Task<JObject> CreateAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (!this.IsAuthenticated(requestInfo) || !requestInfo.Session.User.IsSystemAdministrator)
				throw new AccessDeniedException();

			var json = requestInfo.GetBodyJson();
			var account = new Account();
			account.CopyFrom(json);
			if (json["AccountKey"] != null)
				account.AccountKey = (json["AccountKey"] as JValue).Value as string;
			await Account.CreateAsync(account, cancellationToken);
			return account.ToJson();
		}
		#endregion

		#region Reset password
		async Task<Tuple<string, string, string, string, Tuple<string, int, bool, string, string>>> GetPasswordInstructionsAsync(RequestInfo requestInfo, CancellationToken cancellationToken, string mode = "reset")
		{
			string subject = "", body = "", signature = "", sender = "";
			string smtpServer = "", smtpUser = "", smtpUserPassword = "";
			var smtpServerPort = 25;
			var smtpServerEnableSsl = false;

			if (requestInfo.Query.ContainsKey("related-service"))
				try
				{
					var data = await this.CallServiceAsync(requestInfo, requestInfo.Query["related-service"], cancellationToken);

					subject = data["Subject"] != null && data["Subject"] is JValue && (data["Subject"] as JValue).Value != null
						? (data["Subject"] as JValue).Value as string
						: "";

					body = data["Body"] != null && data["Body"] is JValue && (data["Body"] as JValue).Value != null
						? (data["Body"] as JValue).Value as string
						: "";

					signature = data["Body"] != null && data["Signature"] is JValue && (data["Signature"] as JValue).Value != null
						? (data["Signature"] as JValue).Value as string
						: "";

					sender = data["Sender"] != null && data["Sender"] is JValue && (data["Sender"] as JValue).Value != null
						? (data["Sender"] as JValue).Value as string
						: "";

					smtpServer = data["SmtpServer"] != null && data["SmtpServer"] is JValue && (data["SmtpServer"] as JValue).Value != null
						? (data["SmtpServer"] as JValue).Value as string
						: "";

					smtpServerPort = data["SmtpServerPort"] != null && data["SmtpServerPort"] is JValue && (data["SmtpServerPort"] as JValue).Value != null
						? (data["SmtpServerPort"] as JValue).Value.CastAs<int>()
						: 25;

					smtpServerEnableSsl = data["SmtpServerEnableSsl"] != null && data["SmtpServerEnableSsl"] is JValue && (data["SmtpServerEnableSsl"] as JValue).Value != null
						? (data["SmtpServerEnableSsl"] as JValue).Value.CastAs<bool>()
						: false;

					smtpUser = data["SmtpUser"] != null && data["SmtpUser"] is JValue && (data["SmtpUser"] as JValue).Value != null
						? (data["SmtpUser"] as JValue).Value as string
						: "";

					smtpUserPassword = data["SmtpUserPassword"] != null && data["SmtpUserPassword"] is JValue && (data["SmtpUserPassword"] as JValue).Value != null
						? (data["SmtpUserPassword"] as JValue).Value as string
						: "";
				}
				catch { }

			if (string.IsNullOrWhiteSpace(subject))
				subject = "[{Host}] Kích hoạt mật khẩu đăng nhập mới";

			if (string.IsNullOrWhiteSpace(body))
				body = @"
				Xin chào <b>{Name}</b>
				<br/><br/>
				Tài khoản đăng nhập của bạn đã được yêu cầu " + ("reset".IsEquals(mode) ? "đặt lại" : "thay đổi") + @" thông tin đăng nhập như sau:
				<blockquote>
					Email đăng nhập: <b>{Email}</b>
					<br/>
					Mật khẩu đăng nhập (mới): <b>{Password}</b>
				</blockquote>
				<br/>
				Để hoàn tất quá trình thay đổi mật khẩu mới, bạn vui lòng kích hoạt bằng cách mở liên kết dưới:
				<br/><br/>
				<span style='display:inline-block;padding:15px;border-radius:5px;background-color:#eee;font-weight:bold'>
				<a href='{Uri}' style='color:red'>Kích hoạt mật khẩu đăng nhập mới</a>
				</span>
				<br/><br/>
				<br/>
				<i>Thông tin thêm:</i>
				<ul>
					<li>
						Hoạt động này được thực hiện lúc <b>{Time}</b> với thiết bị <b>{AppPlatform}</b> có địa chỉ IP là <b>{IP}</b>
					</li>
					<li>
						Mã kích hoạt chỉ có giá trị trong vòng 01 ngày kể từ thời điểm nhận được email này.
					</li>
					<li>
						Nếu không phải bạn thực hiện hoạt động này, bạn nên kiểm tra lại thông tin đăng nhập cũng như email liên quan
						vì có thể một điểm nào đó trong hệ thống thông tin bị rò rỉ (và có thể gây hại cho bạn).
						<br/>
						Khi bạn chưa kích hoạt thì mật khẩu đăng nhập mới là chưa có tác dụng.
					</li>
				</ul>
				<br/><br/>
				{Signature}
				";

			return new Tuple<string, string, string, string, Tuple<string, int, bool, string, string>>(subject, body, signature, sender, new Tuple<string, int, bool, string, string>(smtpServer, smtpServerPort, smtpServerEnableSsl, smtpUser, smtpUserPassword));
		}

		async Task<JObject> ResetPasswordAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account
			var email = requestInfo.Extra["Email"].Decrypt();
			var account = Account.Get<Account>(Filters<Account>.And(Filters<Account>.Equals("AccountName", email), Filters<Account>.Equals("Type", AccountType.BuiltIn.ToString())));
			if (account == null)
				return new JObject();

			// prepare
			var password = email.IndexOf("-") > 0
				? email.Substring(email.IndexOf("-"), 1)
				: email.IndexOf(".") > 0
					? email.Substring(email.IndexOf("."), 1)
					: email.IndexOf("_") > 0
						? email.Substring(email.IndexOf("_"), 1)
						: "#";

			password = Captcha.GenerateRandomCode(true, true).ToUpper() + password
				+ Captcha.GenerateRandomCode(true, false).ToLower()
				+ UtilityService.GetUUID().GetHMACSHA1(email, false).Left(3).GetCapitalizedFirstLetter()
				+ UtilityService.GetUUID().Right(3).ToLower();

			var code = (new JObject()
			{
				{ "ID", account.ID },
				{ "Name", account.Profile.Name },
				{ "Email", email },
				{ "Password", password },
				{ "Time", DateTime.Now },
				{ "SessionID", requestInfo.Session.SessionID },
				{ "DeviceID", requestInfo.Session.DeviceID },
				{ "AppName", requestInfo.Session.AppName },
				{ "AppPlatform", requestInfo.Session.AppPlatform },
				{ "IP", requestInfo.Session.IP }
			}).ToString(Formatting.None).Encrypt(ServiceComponent.ActivationKey).ToBase64Url(true);

			var uri = requestInfo.Query.ContainsKey("uri")
				? requestInfo.Query["uri"].Url64Decode()
				: "http://localhost/#?prego=activate&mode={mode}&code={code}";
			uri = uri.Replace(StringComparison.OrdinalIgnoreCase, "{mode}", "password");
			uri = uri.Replace(StringComparison.OrdinalIgnoreCase, "{code}", code);

			// prepare activation email
			var instructions = await this.GetPasswordInstructionsAsync(requestInfo, cancellationToken, "reset");
			var data = new Dictionary<string, string>()
			{
				{ "Host", requestInfo.Query.ContainsKey("host") ? requestInfo.Query["host"] : "unknown" },
				{ "Email", email },
				{ "Password", password },
				{ "Name", account.Profile.Name },
				{ "Time", DateTime.Now.ToString("hh:mm tt @ dd/MM/yyyy") },
				{ "AppPlatform", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
				{ "IP", requestInfo.Session.IP },
				{ "Uri", uri },
				{ "Code", code },
				{ "Signature", instructions.Item3 }
			};

			// send an email
			var subject = instructions.Item1;
			var body = instructions.Item2;
			data.ForEach(info =>
			{
				subject = subject.Replace(StringComparison.OrdinalIgnoreCase, "{" + info.Key + "}", info.Value);
				body = body.Replace(StringComparison.OrdinalIgnoreCase, "{" + info.Key + "}", info.Value);
			});

			var smtp = instructions.Item5;
			await this.SendEmailAsync(instructions.Item4, account.Profile.Name + " <" + email + ">", subject, body, smtp.Item1, smtp.Item2, smtp.Item3, smtp.Item4, smtp.Item5, cancellationToken);

			// return info
			return new JObject();
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

		async Task<JObject> SearchProfilesAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// check
			if (!this.IsAuthenticated(requestInfo))
				throw new AccessDeniedException();
			else if (!this.IsAuthorized(requestInfo, Components.Security.Action.View))
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
			if (!requestInfo.Session.User.IsSystemAdministrator)
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

		#region Fetch profiles
		async Task<JObject> FetchProfilesAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			await Task.Delay(0);
			return new JObject();
		}
		#endregion

		#region Get profile
		async Task<JObject> GetProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var userID = requestInfo.GetObjectIdentity() ?? requestInfo.Session.User.ID;
			var gotRights = this.IsAuthenticated(requestInfo) && requestInfo.Session.User.ID.IsEquals(userID);
			if (!gotRights)
				gotRights = this.IsAuthorized(requestInfo, Components.Security.Action.View);
			if (!gotRights)
				throw new AccessDeniedException();

			// get information
			var profile = await Profile.GetAsync<Profile>(userID);
			if (profile == null)
				throw new InformationNotFoundException();

			// return information
			var json = profile.ToJson();
			if (!requestInfo.Session.User.ID.Equals(profile.ID))
				this.NormalizeProfile(json);
			return json;
		}
		#endregion

		#region Create profile
		async Task<JObject> CreateProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (!this.IsAuthenticated(requestInfo) || !requestInfo.Session.User.IsSystemAdministrator)
				throw new AccessDeniedException();

			var profile = new Profile();
			profile.CopyFrom(requestInfo.GetBodyJson());
			await Profile.CreateAsync(profile, cancellationToken);
			return profile.ToJson();
		}
		#endregion

		#region Update profile
		async Task<JObject> UpdateProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			await Task.Delay(0);
			return new JObject();
		}
		#endregion

		#region Activate
		async Task<JObject> ActivateAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var mode = requestInfo.Query.ContainsKey("mode")
				? requestInfo.Query["mode"]
				: null;
			if (string.IsNullOrWhiteSpace(mode))
				throw new InvalidActivateInformationException();

			var code = requestInfo.Query.ContainsKey("code")
				? requestInfo.Query["code"]
				: null;
			if (string.IsNullOrWhiteSpace(code))
				throw new InvalidActivateInformationException();

			try
			{
				code = code.ToBase64(false, true).Decrypt(ServiceComponent.ActivationKey);
			}
			catch (Exception ex)
			{
				throw new InvalidActivateInformationException(ex);
			}

			ExpandoObject activationInfo = null;
			try
			{
				activationInfo = code.ToExpandoObject();
			}
			catch (Exception ex)
			{
				throw new InvalidActivateInformationException(ex);
			}

			// check time
			if (!activationInfo.Has("Time"))
				throw new InvalidActivateInformationException();

			var time = activationInfo.Get<DateTime>("Time");
			if (mode.IsEquals("account") && (DateTime.Now - time).TotalDays > 30)
				throw new ActivateInformationExpiredException();
			else if ((DateTime.Now - time).TotalHours > 24)
				throw new ActivateInformationExpiredException();

			// activate
			if (mode.IsEquals("password"))
				return await this.ActivatePasswordAsync(requestInfo, activationInfo, cancellationToken);

			return new JObject();
		}

		async Task<JObject> ActivatePasswordAsync(RequestInfo requestInfo, ExpandoObject  activationInfo, CancellationToken cancellationToken)
		{
			// prepare
			var id = activationInfo.Get<string>("ID");
			var password = activationInfo.Get<string>("Password");
			var sessionID = requestInfo.Session.SessionID;
			if (string.IsNullOrWhiteSpace(sessionID))
				sessionID = activationInfo.Get<string>("SessionID");
			var deviceID = requestInfo.GetDeviceID();
			if (string.IsNullOrWhiteSpace(deviceID))
				deviceID = activationInfo.Get<string>("DeviceID");
			var appName = requestInfo.GetAppName();
			if (string.IsNullOrWhiteSpace(appName))
				appName = activationInfo.Get<string>("AppName");
			var appPlatform = requestInfo.GetAppPlatform();
			if (string.IsNullOrWhiteSpace(appPlatform))
				appPlatform = activationInfo.Get<string>("AppPlatform");

			// load account
			var account = await Account.GetAsync<Account>(id);
			if (account == null)
				throw new InvalidActivateInformationException();

			// update new password
			account.AccountKey = Account.HashPassword(account.ID, password);
			account.LastAccess = DateTime.Now;
			account.Sessions = null;
			await Account.UpdateAsync(account);

			// register session
			var session = await Session.GetAsync<Session>(sessionID);
			if (session == null)
			{
				session = new Session()
				{
					ID = sessionID,
					UserID = account.ID,
					IP = requestInfo.Session.IP,
					DeviceID = deviceID,
					AppInfo = appName + " @ " + appPlatform,
					Online = true
				};
				await Session.CreateAsync(session, cancellationToken);
			}
			else
			{
				session.IP = requestInfo.Session.IP;
				session.DeviceID = deviceID;
				session.AppInfo = appName + " / " + appPlatform;
				session.Online = true;
				await Session.UpdateAsync(session, cancellationToken);
			}

			// response
			return new JObject()
			{
				{ "UserID", account.ID },
				{ "SessionID", sessionID },
				{ "DeviceID", deviceID }
			};
		}
		#endregion

		#region Mediators: check exist, verify, account info
		async Task<JObject> CheckSessionExistedAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// 1st step: check cached session
			var isExisted = await Utility.Cache.ExistsAsync<Session>(requestInfo.Session.SessionID);

			// 2nd step: load from data repository (user) if has no cache
			if (!isExisted && !requestInfo.Session.User.ID.Equals("") && !requestInfo.Session.User.ID.Equals(User.SystemAccountID))
			{
				var session = await Session.GetAsync<Session>(requestInfo.Session.SessionID, cancellationToken);
				isExisted = session != null;
			}

			// return
			return new JObject()
			{
				{ "Existed", isExisted }
			};
		}

		async Task<JObject> ValidateSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// 1st step: get cached session
			var session = await Utility.Cache.FetchAsync<Session>(requestInfo.Session.SessionID);
			if (session == null && !requestInfo.Session.User.ID.Equals("") && !requestInfo.Session.User.ID.Equals(User.SystemAccountID))
				session = await Session.GetAsync<Session>(requestInfo.Session.SessionID, cancellationToken);

			// validate
			if (session == null)
				throw new SessionNotFoundException();
			else if (session.ExpiredAt < DateTime.Now)
				throw new SessionExpiredException();

			var accessToken = requestInfo.Extra.ContainsKey("AccessToken")
				? requestInfo.Extra["AccessToken"].Decrypt()
				: null;

			if (string.IsNullOrWhiteSpace(accessToken))
				throw new InvalidSessionException();
			else if (!session.AccessToken.Equals(accessToken))
				throw new TokenRevokedException();

			// return the result
			return new JObject()
			{
				{ "Status", "OK" }
			};
		}

		async Task<JObject> GetAccountInfoAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken);
			if (account == null)
				throw new InvalidSessionException("Account is not found");

			var json = new JObject()
			{
				{ "ID", account.ID }
			};

			if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Full"))
			{
				json.Add(new JProperty("Roles", (account.AccountRoles ?? new List<string>()).Concat("All,Authenticated".ToList()).Distinct().ToList()));
				json.Add(new JProperty("Privileges", account.AccountPrivileges ?? new List<Privilege>()));
			}

			return json;
		}
		#endregion

		#region Captchas
		JObject RegisterSessionCaptcha(RequestInfo requestInfo)
		{
			if (!requestInfo.Query.ContainsKey("register"))
				throw new InvalidRequestException();

			var code = Captcha.GenerateCode();
			var uri = UtilityService.GetAppSetting("HttpFilesUri", "https://afs.vieapps.net")
				+ "/captchas/" + code.Url64Encode() + "/"
				+ requestInfo.Query["register"].Substring(UtilityService.GetRandomNumber(1, 32), 13).Reverse() + ".jpg";

			return new JObject()
			{
				{ "Code", code },
				{ "Uri", uri }
			};
		}
		#endregion

		#region Process inter-communicate messages
		void OnInterCommunicateMessageReceived(CommunicateMessage message)
		{
			// check
			if (message.Data == null)
				return;

			// prepare
			var data = message.Data.ToExpandoObject();

			var verb = data.Get<string>("Verb");
			if (string.IsNullOrWhiteSpace(verb))
				return;

			// online status
			if (verb.IsEquals("Status"))
				try
				{
					var session = Session.Get<Session>(data.Get<string>("SessionID"));
					if (session != null && !session.UserID.Equals(""))
					{
						session.Online = data.Get<bool>("IsOnline");
						Session.Update(session);
					}
#if DEBUG
					this.WriteInfo("Update online status successful" + "\r\n" + "=====>" + "\r\n" + message.ToJson().ToString(Formatting.Indented));
#endif
				}
#if DEBUG
				catch (Exception ex)
				{
					this.WriteInfo("Error occurred while updating online status", ex);
				}
#else
				catch { }
#endif
		}
		#endregion

		~ServiceComponent()
		{
			this.Dispose(false);
		}
	}
}