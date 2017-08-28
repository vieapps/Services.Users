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
						(ex) => {
							this.WriteInfo("Error occurred while registering the service", ex);
						}
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
					case "session":
						return await this.ProcessSessionAsync(requestInfo, cancellationToken);

					case "account":
						return await this.ProcessAccountAsync(requestInfo, cancellationToken);

					case "profile":
						return await this.ProcessProfileAsync(requestInfo, cancellationToken);

					case "activate":
						return await this.ProcessActivationAsync(requestInfo, cancellationToken);

					case "captcha":
						return this.RegisterSessionCaptcha(requestInfo);
				}

				// unknown
				var msg = "The request is invalid [" + this.ServiceURI + "]: " + requestInfo.Verb + " /";
				if (!string.IsNullOrWhiteSpace(requestInfo.ObjectName))
					msg +=  requestInfo.ObjectName + (!string.IsNullOrWhiteSpace(requestInfo.GetObjectIdentity()) ? "/" + requestInfo.GetObjectIdentity() : "");
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

		Task<JObject> ProcessSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			switch (requestInfo.Verb)
			{
				// get information of a session
				case "GET":
					return this.GetSessionAsync(requestInfo, cancellationToken);

				// register a session
				case "POST":
					return this.RegisterSessionAsync(requestInfo, cancellationToken);

				// sign a session in
				case "PUT":
					return this.SignSessionInAsync(requestInfo, cancellationToken);

				// sign a session out
				case "DELETE":
					return this.SignSessionOutAsync(requestInfo, cancellationToken);
			}
			
			return Task.FromException<JObject>(new MethodNotAllowedException(requestInfo.Verb));
		}

		#region Get a session
		async Task<JObject> GetSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var session = string.IsNullOrWhiteSpace(requestInfo.Session.SessionID) || requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.ID.Equals(User.SystemAccountID)
				? null
				: await Session.GetAsync<Session>(requestInfo.Session.SessionID, cancellationToken);
			return session?.ToJson();
		}
		#endregion

		#region Register a session
		async Task<JObject> RegisterSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(requestInfo.Session.SessionID) || requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.ID.Equals(User.SystemAccountID))
				throw new InvalidRequestException();

			var data = requestInfo.GetBodyExpando();
			if (data == null)
				throw new InformationRequiredException();

			var session = await Session.GetAsync<Session>(requestInfo.Session.SessionID, cancellationToken);
			if (session == null)
			{
				session = new Session();
				session.CopyFrom(data);
				await Session.CreateAsync(session, cancellationToken);
			}
			else
			{
				if (!requestInfo.Session.SessionID.IsEquals(data.Get<string>("ID")) || !requestInfo.Session.User.ID.IsEquals(data.Get<string>("UserID")))
					throw new InvalidSessionException();
				session.CopyFrom(data);
				await Session.UpdateAsync(session, cancellationToken);
			}

			return session.ToJson();
		}
		#endregion

		#region Sign a session in
		async Task<JObject> SignSessionInAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var body = requestInfo.GetBodyExpando();
			var email = body.Get<string>("Email").Decrypt();
			var password = body.Get<string>("Password").Decrypt();

			// find account & check
			var filter = Filters<Account>.And(
					Filters<Account>.Equals("AccountName", email),
					Filters<Account>.Equals("Type", AccountType.BuiltIn.ToString())
				);
			var account = await Account.GetAsync<Account>(filter, null, null, cancellationToken);
			if (account == null || !account.AccountKey.Equals(Account.HashPassword(account.ID, password)))
				throw new WrongAccountException();

			// response
			return account.GetJson();
		}
		#endregion

		#region Sign a session out
		async Task<JObject> SignSessionOutAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// remove session
			await Session.DeleteAsync<Session>(requestInfo.Session.SessionID, cancellationToken);

			// update account
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken);
			if (account != null)
			{
				if (account.Sessions == null)
					await account.GetSessionsAsync(cancellationToken);
				account.Sessions = account.Sessions.Where(s => !s.ID.Equals(requestInfo.Session.SessionID)).ToList();
				account.LastAccess = DateTime.Now;
				await Account.UpdateAsync(account, cancellationToken);
			}

			// response
			return new JObject()
			{
				{ "Status", "OK" }
			};
		}
		#endregion

		Task<JObject> ProcessAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			switch (requestInfo.Verb)
			{
				case "GET":
					return this.GetAccountAsync(requestInfo, cancellationToken);

				case "POST":
					if (requestInfo.Query.ContainsKey("x-convert"))
						return this.CreateAccountAsync(requestInfo, cancellationToken);
					return Task.FromException<JObject>(new MethodNotAllowedException(requestInfo.Verb));

				case "PUT":
					if ("reset".IsEquals(requestInfo.GetObjectIdentity()))
						return this.ResetPasswordAsync(requestInfo, cancellationToken);
					else if ("password".IsEquals(requestInfo.GetObjectIdentity()))
						return this.UpdatePasswordAsync(requestInfo, cancellationToken);
					else if ("email".IsEquals(requestInfo.GetObjectIdentity()))
						return this.UpdateEmailAsync(requestInfo, cancellationToken);
					return Task.FromException<JObject>(new InvalidRequestException());
			}

			return Task.FromException<JObject>(new MethodNotAllowedException(requestInfo.Verb));
		}

		#region Get an account
		async Task<JObject> GetAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (!this.IsAuthenticated(requestInfo))
				throw new AccessDeniedException();

			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken);
			if (account == null)
				throw new InformationNotFoundException();

			// response
			return account.GetJson();
		}
		#endregion

		#region Create an account
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

		#region Update an account
		#endregion

		#region Get the instructions when update an account
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
		#endregion

		#region Renew password of an account
		async Task<JObject> ResetPasswordAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account
			var email = requestInfo.Extra["Email"].Decrypt();
			var filter = Filters<Account>.And(
					Filters<Account>.Equals("AccountName", email),
					Filters<Account>.Equals("Type", AccountType.BuiltIn.ToString())
				);
			var account = await Account.GetAsync<Account>(filter, null, null, cancellationToken);
			if (account == null)
				return new JObject()
				{
					{ "Message", "Please check your email and follow the instruction to activate" }
				};

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
				{ "Email", account.AccountName },
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
				{ "Email", account.AccountName },
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
			await this.SendEmailAsync(instructions.Item4, account.Profile.Name + " <" + account.AccountName + ">", subject, body, smtp.Item1, smtp.Item2, smtp.Item3, smtp.Item4, smtp.Item5, cancellationToken);

			// response
			return new JObject()
			{
				{ "Message", "Please check your email and follow the instruction to activate" }
			};
		}
		#endregion

		#region Update password of an account
		async Task<JObject> UpdatePasswordAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account and check
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken);
			if (account == null)
				throw new InformationNotFoundException();

			var oldPassword = requestInfo.Extra["OldPassword"].Decrypt();
			if (!account.AccountKey.Equals(Account.HashPassword(account.ID, oldPassword)))
				throw new WrongAccountException();

			// prepare
			var password = requestInfo.Extra["Password"].Decrypt();
			var code = (new JObject()
			{
				{ "ID", account.ID },
				{ "Name", account.Profile.Name },
				{ "Email", account.AccountName },
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
			var instructions = await this.GetPasswordInstructionsAsync(requestInfo, cancellationToken, "password");
			var data = new Dictionary<string, string>()
			{
				{ "Host", requestInfo.Query.ContainsKey("host") ? requestInfo.Query["host"] : "unknown" },
				{ "Email", account.AccountName },
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
			await this.SendEmailAsync(instructions.Item4, account.Profile.Name + " <" + account.AccountName + ">", subject, body, smtp.Item1, smtp.Item2, smtp.Item3, smtp.Item4, smtp.Item5, cancellationToken);

			// response
			return new JObject()
			{
				{ "Message", "Please check your email and follow the instruction to activate" }
			};
		}
		#endregion

		#region Update email of an account
		async Task<JObject> UpdateEmailAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account and check
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken);
			if (account == null)
				throw new InformationNotFoundException();

			var oldPassword = requestInfo.Extra["OldPassword"].Decrypt();
			if (!account.AccountKey.Equals(Account.HashPassword(account.ID, oldPassword)))
				throw new WrongAccountException();

			// check existing
			var email = requestInfo.Extra["Email"].Decrypt();
			var filter = Filters<Account>.And(
					Filters<Account>.Equals("AccountName", email),
					Filters<Account>.Equals("Type", AccountType.BuiltIn.ToString())
				);
			var otherAccount = await Account.GetAsync<Account>(filter, null, null, cancellationToken);
			if (otherAccount != null)
				throw new InformationExistedException("The email '" + email + "' is used by other account");

			// update
			account.AccountName = email.Trim().ToLower();
			account.LastAccess = DateTime.Now;

			account.Profile.Email = email;
			account.Profile.LastUpdated = DateTime.Now;

			await Task.WhenAll(
					Account.UpdateAsync(account, cancellationToken),
					Profile.UpdateAsync(account.Profile, cancellationToken)
				);

			// response
			return account.Profile.ToJson();
		}
		#endregion

		Task<JObject> ProcessProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			switch (requestInfo.Verb)
			{
				case "GET":
					// search
					if ("search".IsEquals(requestInfo.GetObjectIdentity()))
						return this.SearchProfilesAsync(requestInfo, cancellationToken);

					// fetch
					else if ("fetch".IsEquals(requestInfo.GetObjectIdentity()))
						return this.FetchProfilesAsync(requestInfo, cancellationToken);

					// get details of a profile
					else
						return this.GetProfileAsync(requestInfo, cancellationToken);

				case "POST":
					// create profile
					if (requestInfo.Query.ContainsKey("x-convert"))
						return this.CreateProfileAsync(requestInfo, cancellationToken);

					// update profile
					else
						return this.UpdateProfileAsync(requestInfo, cancellationToken);
			}

			return Task.FromException<JObject>(new MethodNotAllowedException(requestInfo.Verb));
		}

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

			var filter = request.Has("FilterBy")
				? request.Get<ExpandoObject>("FilterBy").ToFilterBy<Profile>()
				: null;

			var sort = request.Has("SortBy")
				? request.Get<ExpandoObject>("SortBy").ToSortBy<Profile>()
				: null;
			if (sort == null && string.IsNullOrWhiteSpace(query))
				sort = Sorts<Profile>.Ascending("Name");

			var pagination = request.Has("Pagination")
				? request.Get<ExpandoObject>("Pagination").GetPagination()
				: new Tuple<long, int, int, int>(-1, 0, 20, 1);

			var pageNumber = pagination.Item4;

			// check cache
			var cacheKey = string.IsNullOrWhiteSpace(query) && (filter != null || sort != null)
				? (filter != null ? filter.GetMD5() + ":" : "") + (sort != null ? sort.GetMD5() + ":" : "") + pageNumber.ToString()
				: "";

			var json = !cacheKey.Equals("")
				? await Utility.DataCache.GetAsync<string>(cacheKey + "-json")
				: "";

			if (!string.IsNullOrWhiteSpace(json))
				return JObject.Parse(json);

			// prepare pagination
			var totalRecords = pagination.Item1 > -1
				? pagination.Item1
				: -1;

			if (totalRecords < 0)
				totalRecords = string.IsNullOrWhiteSpace(query)
					? await Profile.CountAsync(filter, cacheKey + "-total", cancellationToken)
					: await Profile.CountByQueryAsync(query, filter, cancellationToken);

			var pageSize = pagination.Item3;

			var totalPages = (new Tuple<long, int>(totalRecords, pageSize)).GetTotalPages();
			if (totalPages > 0 && pageNumber > totalPages)
				pageNumber = totalPages;

			// search
			var objects = totalRecords > 0
				? string.IsNullOrWhiteSpace(query)
					? await Profile.FindAsync(filter, sort, pageSize, pageNumber, cacheKey, cancellationToken)
					: await Profile.SearchAsync(query, filter, pageSize, pageNumber, cancellationToken)
				: new List<Profile>();

			// build result
			var profiles = objects.ToJsonArray();
			if (!requestInfo.Session.User.IsSystemAdministrator)
				foreach (JObject profile in profiles)
					this.NormalizeProfile(profile);

			pagination = new Tuple<long, int, int, int>(totalRecords, totalPages, pageSize, pageNumber);
			var result = new JObject()
			{
				{ "FilterBy", filter?.ToClientJson(query) },
				{ "SortBy", sort?.ToClientJson() },
				{ "Pagination", pagination?.GetPagination() },
				{ "Objects", profiles }
			};

			// update cache
			if (!cacheKey.Equals(""))
			{
#if DEBUG
				json = result.ToString(Formatting.Indented);
#else
				json = result.ToString(Formatting.None);
#endif
				Utility.DataCache.Set(cacheKey + "-json", json);
			}

			// return the result
			return result;
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

		async Task<JObject> ProcessActivationAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (!requestInfo.Verb.IsEquals("GET"))
				throw new MethodNotAllowedException(requestInfo.Verb);

			#region prepare
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

			ExpandoObject info = null;
			try
			{
				info = code.ToExpandoObject();
			}
			catch (Exception ex)
			{
				throw new InvalidActivateInformationException(ex);
			}

			// check time
			if (!info.Has("Time"))
				throw new InvalidActivateInformationException();

			var time = info.Get<DateTime>("Time");
			if (mode.IsEquals("account") && (DateTime.Now - time).TotalDays > 30)
				throw new ActivateInformationExpiredException();
			else if ((DateTime.Now - time).TotalHours > 24)
				throw new ActivateInformationExpiredException();
			#endregion

			// activate password
			if (mode.IsEquals("password"))
				return await this.ActivatePasswordAsync(requestInfo, info, cancellationToken);

			throw new InvalidRequestException();
		}

		#region Activate new password
		async Task<JObject> ActivatePasswordAsync(RequestInfo requestInfo, ExpandoObject  info, CancellationToken cancellationToken)
		{
			// prepare
			var id = info.Get<string>("ID");
			var password = info.Get<string>("Password");
			var sessionID = requestInfo.Session.SessionID;
			if (string.IsNullOrWhiteSpace(sessionID))
				sessionID = info.Get<string>("SessionID");
			var deviceID = requestInfo.GetDeviceID();
			if (string.IsNullOrWhiteSpace(deviceID))
				deviceID = info.Get<string>("DeviceID");
			var appName = requestInfo.GetAppName();
			if (string.IsNullOrWhiteSpace(appName))
				appName = info.Get<string>("AppName");
			var appPlatform = requestInfo.GetAppPlatform();
			if (string.IsNullOrWhiteSpace(appPlatform))
				appPlatform = info.Get<string>("AppPlatform");

			// load account
			var account = await Account.GetAsync<Account>(id, cancellationToken);
			if (account == null)
				throw new InvalidActivateInformationException();

			// update new password
			account.AccountKey = Account.HashPassword(account.ID, password);
			account.LastAccess = DateTime.Now;
			account.Sessions = null;
			await Account.UpdateAsync(account);

			// response
			return account.GetJson();
		}
		#endregion

		JObject RegisterSessionCaptcha(RequestInfo requestInfo)
		{
			if (!requestInfo.Verb.IsEquals("GET"))
				throw new MethodNotAllowedException(requestInfo.Verb);
			else if (!requestInfo.Query.ContainsKey("register"))
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

		#region Process inter-communicate messages
		protected override void ProcessInterCommunicateMessage(CommunicateMessage message)
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
			if (verb.IsEquals("Status") && !string.IsNullOrWhiteSpace(data.Get<string>("UserID")))
				try
				{
					var isOnline = data.Get<bool>("IsOnline");
					var session = Session.Get<Session>(data.Get<string>("SessionID"));
					if (session != null && session.Online != isOnline)
					{
						session.Online = isOnline;
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

	}
}