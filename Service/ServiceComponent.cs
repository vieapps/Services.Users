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

		#region Working with related services
		async Task<Tuple<string, string, string, string, Tuple<string, int, bool, string, string>>> GetInstructionsOfRelatedServiceAsync(RequestInfo requestInfo, string mode = "reset", CancellationToken cancellationToken = default(CancellationToken))
		{
			var request = new RequestInfo()
			{
				Session = requestInfo.Session,
				ServiceName = requestInfo.Query["related-service"],
				ObjectName = "instruction",
				Query = new Dictionary<string, string>(requestInfo.Query ?? new Dictionary<string, string>())
				{
					{ "object-identity", "account" }
				},
				Header = requestInfo.Header,
				Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>())
				{
					{ "mode", mode }
				},
				CorrelationID = requestInfo.CorrelationID
			};
			var data = (await this.CallServiceAsync(request, cancellationToken)).ToExpandoObject();

			var subject = data.Get<string>("Subject");
			var body = data.Get<string>("Body");
			var signature = data.Get<string>("Signature");
			var sender = data.Get<string>("Sender");
			var smtpServer = data.Get<string>("SmtpServer");
			var smtpServerPort = data.Has("SmtpServerPort")
				? data.Get<int>("SmtpServerPort")
				: 25;
			var smtpServerEnableSsl = data.Get<bool>("SmtpServerEnableSsl");
			var smtpUser = data.Get<string>("SmtpUser");
			var smtpUserPassword = data.Get<string>("SmtpUserPassword");

			return new Tuple<string, string, string, string, Tuple<string, int, bool, string, string>>(subject, body, signature, sender, new Tuple<string, int, bool, string, string>(smtpServer, smtpServerPort, smtpServerEnableSsl, smtpUser, smtpUserPassword));
		}

		async Task<Tuple<string, string, string, string, Tuple<string, int, bool, string, string>>> GetActivateInstructionsAsync(RequestInfo requestInfo, string mode = "reset", CancellationToken cancellationToken = default(CancellationToken))
		{
			string subject = "", body = "", signature = "", sender = "";
			string smtpServer = "", smtpUser = "", smtpUserPassword = "";
			var smtpServerPort = 25;
			var smtpServerEnableSsl = false;

			if (requestInfo.Query.ContainsKey("related-service"))
				try
				{
					var data = await this.GetInstructionsOfRelatedServiceAsync(requestInfo, mode, cancellationToken);

					subject = data.Item1;
					body = data.Item2;
					signature = data.Item3;
					sender = data.Item4;
					smtpServer = data.Item5.Item1;
					smtpServerPort = data.Item5.Item2;
					smtpServerEnableSsl = data.Item5.Item3;
					smtpUser = data.Item5.Item4;
					smtpUserPassword = data.Item5.Item5;
				}
				catch { }

			if (string.IsNullOrWhiteSpace(subject))
				switch (mode)
				{
					case "account":
						subject = "[{Host}] Kích hoạt tài khoản đăng nhập";
						break;

					case "invite":
						subject = "[{Host}] Lời mời tham gia hệ thống";
						break;

					case "reset":
						subject = "[{Host}] Kích hoạt mật khẩu đăng nhập mới";
						break;
				}

			if (string.IsNullOrWhiteSpace(body))
				switch (mode)
				{
					case "account":
						body = @"
						Xin chào <b>{Name}</b>
						<br/><br/>
						Chào mừng bạn đã tham gia vào hệ thống cùng chúng tôi.
						<br/><br/>
						Tài khoản thành viên của bạn đã được khởi tạo với các thông tin sau:
						<blockquote>
							Email đăng nhập: <b>{Email}</b>
							<br/>
							Mật khẩu đăng nhập: <b>{Password}</b>
						</blockquote>
						<br/>
						Để hoàn tất quá trình đăng ký, bạn vui lòng kích hoạt tài khoản đã đăng ký bằng cách mở liên kết dưới:
						<br/><br/>
						<span style='display:inline-block;padding:15px;border-radius:5px;background-color:#eee;font-weight:bold'>
						<a href='{Uri}' style='color:red'>Kích hoạt tài khoản</a>
						</span>
						<br/><br/>
						<br/>
						<i>Thông tin thêm:</i>
						<ul>
							<li>
								Hoạt động đăng ký tài khoản được thực hiện lúc <b>{Time}</b> với thiết bị có địa chỉ IP là <b>{IP}</b>
							</li>
							<li>
								Mã kích hoạt chỉ có giá trị trong vòng 01 tháng kể từ thời điểm nhận được email này.
								<br/>
								Sau thời gian đó, để gia nhập hệ thống bạn cần thực hiện  lại hoạt động đăng ký thành viên.
							</li>
							<li>
								Nếu không phải bạn thực hiện hoạt động này, bạn cũng không phải bận tâm 
								vì hệ thống sẽ tự động loại bỏ các thông tin không sử dụng sau thời gian đăng ký 01 tháng.
							</li>
						</ul>
						<br/><br/>
						{Signature}".Replace("\t", "");
						break;

					case "invite":
						body = @"
						Xin chào <b>{Name}</b>
						<br/><br/>
						Chào mừng bạn đến với hệ thống qua lời mời của <b>{Inviter}</b> ({InviterEmail}).
						<br/><br/>
						Tài khoản thành viên của bạn sẽ được khởi tạo với các thông tin sau:
						<blockquote>
							Email đăng nhập: <b>{Email}</b>
							<br/>
							Mật khẩu đăng nhập: <b>{Password}</b>
						</blockquote>
						<br/>
						Để hoàn tất quá trình và trở thành thành viên của hệ thống, bạn vui lòng khởi tạo & kích hoạt tài khoản bằng cách mở liên kết dưới:
						<br/><br/>
						<span style='display:inline-block;padding:15px;border-radius:5px;background-color:#eee;font-weight:bold'>
						<a href='{Uri}' style='color:red'>Khởi tạo &amp; Kích hoạt tài khoản</a>
						</span>
						<br/><br/>
						<br/>
						<i>Thông tin thêm:</i>
						<ul>
							<li>
								Lời mời tham gia hệ thống được thực hiện lúc <b>{Time}</b> với thiết bị có địa chỉ IP là <b>{IP}</b>
							</li>
							<li>
								Mã khởi tạo & kích hoạt chỉ có giá trị trong vòng 01 tháng kể từ thời điểm nhận được email này.
								<br/>
								Sau thời gian đó, để gia nhập hệ thống bạn cần thực hiện  hoạt động đăng ký thành viên.
							</li>
							<li>
								Nếu bạn không muốn tham gia vào hệ thống, bạn cũng không phải bận tâm  vì hệ thống sẽ chỉ khởi tạo tài khoản khi bạn thực hiện hoạt động này.
							</li>
						</ul>
						<br/><br/>
						{Signature}".Replace("\t", "");
						break;

					case "reset":
						body = @"
						Xin chào <b>{Name}</b>
						<br/><br/>
						Tài khoản đăng nhập của bạn đã được yêu cầu đặt lại thông tin đăng nhập như sau:
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
						{Signature}".Replace("\t", "");
						break;
				}

			return new Tuple<string, string, string, string, Tuple<string, int, bool, string, string>>(subject, body, signature, sender, new Tuple<string, int, bool, string, string>(smtpServer, smtpServerPort, smtpServerEnableSsl, smtpUser, smtpUserPassword));
		}

		async Task<Tuple<string, string, string, string, Tuple<string, int, bool, string, string>>> GetUpdateInstructionsAsync(RequestInfo requestInfo, string mode = "password", CancellationToken cancellationToken = default(CancellationToken))
		{
			string subject = "", body = "", signature = "", sender = "";
			string smtpServer = "", smtpUser = "", smtpUserPassword = "";
			var smtpServerPort = 25;
			var smtpServerEnableSsl = false;

			if (requestInfo.Query.ContainsKey("related-service"))
				try
				{
					var data = await this.GetInstructionsOfRelatedServiceAsync(requestInfo, mode, cancellationToken);

					subject = data.Item1;
					body = data.Item2;
					signature = data.Item3;
					sender = data.Item4;
					smtpServer = data.Item5.Item1;
					smtpServerPort = data.Item5.Item2;
					smtpServerEnableSsl = data.Item5.Item3;
					smtpUser = data.Item5.Item4;
					smtpUserPassword = data.Item5.Item5;
				}
				catch { }

			if (string.IsNullOrWhiteSpace(subject))
				switch (mode)
				{
					case "password":
						subject = "[{Host}] Thông báo thông tin đăng nhập tài khoản thay đổi (mật khẩu)";
						break;

					case "email":
						subject = "[{Host}] Thông báo thông tin đăng nhập tài khoản thay đổi (email)";
						break;
				}

			if (string.IsNullOrWhiteSpace(body))
				switch (mode)
				{
					case "password":
						body = @"
						Xin chào <b>{Name}</b>
						<br/><br/>
						Tài khoản đăng nhập của bạn đã được cật nhật thông tin đăng nhập như sau:
						<blockquote>
							Email đăng nhập: <b>{Email}</b>
							<br/>
							Mật khẩu đăng nhập (mới): <b>{Password}</b>
						</blockquote>
						<br/>
						<i>Thông tin thêm:</i>
						<ul>
							<li>
								Hoạt động này được thực hiện lúc <b>{Time}</b> với thiết bị <b>{AppPlatform}</b> có địa chỉ IP là <b>{IP}</b>
							</li>
							<li>
								Nếu không phải bạn thực hiện hoạt động này, bạn nên kiểm tra lại thông tin đăng nhập cũng như email liên quan
								vì có thể một điểm nào đó trong hệ thống thông tin bị rò rỉ (và có thể gây hại cho bạn).
							</li>
						</ul>
						<br/><br/>
						{Signature}".Replace("\t", "");
						break;

					case "email":
						body = @"
						Xin chào <b>{Name}</b>
						<br/><br/>
						Tài khoản đăng nhập của bạn đã được cật nhật thông tin đăng nhập như sau:
						<blockquote>
							Email đăng nhập (mới): <b>{Email}</b>
							<br/>
							Email đăng nhập (cũ): <b>{OldEmail}</b>
						</blockquote>
						<br/>
						<i>Thông tin thêm:</i>
						<ul>
							<li>
								Hoạt động này được thực hiện lúc <b>{Time}</b> với thiết bị <b>{AppPlatform}</b> có địa chỉ IP là <b>{IP}</b>
							</li>
							<li>
								Nếu không phải bạn thực hiện hoạt động này, bạn nên kiểm tra lại thông tin đăng nhập cũng như email liên quan
								vì có thể một điểm nào đó trong hệ thống thông tin bị rò rỉ (và có thể gây hại cho bạn).
							</li>
						</ul>
						<br/><br/>
						{Signature}".Replace("\t", "");
						break;
				}

			return new Tuple<string, string, string, string, Tuple<string, int, bool, string, string>>(subject, body, signature, sender, new Tuple<string, int, bool, string, string>(smtpServer, smtpServerPort, smtpServerEnableSsl, smtpUser, smtpUserPassword));
		}

		async Task<JObject> CallRelatedServiceAsync(RequestInfo requestInfo, string objectName, string verb = "GET", string objectIdentity = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			var request = new RequestInfo(requestInfo.Session, requestInfo.Query["related-service"], objectName, verb, requestInfo.Query, requestInfo.Header, requestInfo.Body, requestInfo.Extra, requestInfo.CorrelationID);
			if (!string.IsNullOrWhiteSpace(objectIdentity))
			{
				if (request.Query.ContainsKey("object-identity"))
					request.Query["object-identity"] = objectIdentity;
				else
					request.Query.Add("object-identity", objectIdentity);
			}
			return await this.CallServiceAsync(request, cancellationToken);
		}

		async Task<JObject> CallRelatedServiceAsync(RequestInfo requestInfo, User user, string objectName, string verb, CancellationToken cancellationToken = default(CancellationToken))
		{
			return await this.CallServiceAsync(new RequestInfo(
				new Services.Session(requestInfo.Session) { User = user }, 
				requestInfo.Query["related-service"], 
				objectName, 
				verb, 
				requestInfo.Query, 
				requestInfo.Header, 
				requestInfo.Body, 
				requestInfo.Extra, 
				requestInfo.CorrelationID
			), cancellationToken);
		}
		#endregion

		Task<JObject> ProcessSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			switch (requestInfo.Verb)
			{
				// get a session
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
			return !string.IsNullOrWhiteSpace(requestInfo.Session.SessionID)
				? (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.ID.Equals(User.SystemAccountID)
						? await Utility.Cache.FetchAsync<Session>(requestInfo.Session.SessionID)
						: await Session.GetAsync<Session>(requestInfo.Session.SessionID, cancellationToken)
					)?.ToJson()
				: null;
		}
		#endregion

		#region Register a session
		async Task<JObject> RegisterSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			if (string.IsNullOrWhiteSpace(requestInfo.Session.SessionID))
				throw new InvalidRequestException();

			var data = requestInfo.GetBodyExpando();
			if (data == null)
				throw new InformationRequiredException();

			// register a session of vistor/system account
			if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.ID.Equals(User.SystemAccountID))
			{
				// update cache of session
				var session = data.Copy<Session>();
				Utility.Cache.SetAbsolute(session, 180);

				// response
				return session.ToJson();
			}

			// register a session of authenticated account
			else
			{
				var session = await Session.GetAsync<Session>(requestInfo.Session.SessionID, cancellationToken);
				if (session == null)
				{
					session = data.Copy<Session>();
					await Session.CreateAsync(session, cancellationToken);
				}
				else
				{
					if (!requestInfo.Session.SessionID.IsEquals(data.Get<string>("ID")) || !requestInfo.Session.User.ID.IsEquals(data.Get<string>("UserID")))
						throw new InvalidSessionException();
					session.CopyFrom(data);
					await Session.UpdateAsync(session, cancellationToken);
				}

				// remove duplicated sessions
				await Session.DeleteManyAsync(Filters<Session>.And(
						Filters<Session>.Equals("DeviceID", session.DeviceID),
						Filters<Session>.NotEquals("ID", session.ID)
					), null, cancellationToken);

				// update account information
				var account = await Account.GetAsync<Account>(session.UserID, cancellationToken);
				account.LastAccess = DateTime.Now;
				await account.GetSessionsAsync(cancellationToken);
				await Account.UpdateAsync(account, cancellationToken);

				// response
				return session.ToJson();
			}
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
			var account = await Account.GetByEmailAsync(email, cancellationToken);
			if (account == null || !Account.HashPassword(account.ID, password).Equals(account.AccessKey))
				throw new WrongAccountException();

			// response
			return account.GetAccountJson();
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
				// get an account
				case "GET":
					return this.GetAccountAsync(requestInfo, cancellationToken);

				// create an account
				case "POST":
					return this.CreateAccountAsync(requestInfo, cancellationToken);

				// update an account
				case "PUT":
					if ("reset".IsEquals(requestInfo.GetObjectIdentity()))
						return this.ResetPasswordAsync(requestInfo, cancellationToken);
					else if ("password".IsEquals(requestInfo.GetObjectIdentity()))
						return this.UpdatePasswordAsync(requestInfo, cancellationToken);
					else if ("email".IsEquals(requestInfo.GetObjectIdentity()))
						return this.UpdateEmailAsync(requestInfo, cancellationToken);
					else
						return this.UpdateAccountAsync(requestInfo, cancellationToken);
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

			// prepare response
			var json = account.GetAccountJson();

			// related service
			if (requestInfo.Query.ContainsKey("related-service"))
				try
				{
					var result = await this.CallRelatedServiceAsync(requestInfo, "account", "GET", null, cancellationToken);
					foreach (var info in result)
						if (json[info.Key] != null)
							json[info.Key] = info.Value;
						else
							json.Add(info.Key, info.Value);
				}
				catch { }

			// return the result
			return json;
		}
		#endregion

		#region Create an account
		async Task<JObject> CreateAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// convert
			if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-convert"))
			{
				if (!requestInfo.Session.User.IsSystemAdministrator)
					throw new AccessDeniedException();

				var requestBody = requestInfo.GetBodyExpando();

				var account = requestBody.Copy<Account>();
				account.AccessKey = requestBody.Get<string>("AccessKey") ?? this.GenerateRandomPassword(account.AccessIdentity);

				await Account.CreateAsync(account, cancellationToken);
				return account.ToJson();
			}

			// register
			else
			{
				// prepare
				var requestBody = requestInfo.GetBodyExpando();

				var id = UtilityService.GetUUID();
				var json = new JObject()
				{
					{ "Message", "Please check email and follow the instructions" }
				};

				var name = requestBody.Get<string>("Name");
				var email = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Email")
					? requestInfo.Extra["Email"].Decrypt()
					: null;
				var password = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Password")
					? requestInfo.Extra["Password"].Decrypt()
					: null;
				if (string.IsNullOrWhiteSpace(password) && !string.IsNullOrWhiteSpace(email))
					password = this.GenerateRandomPassword(email);

				// create new account & profile
				if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-create"))
				{
					// create account
					var status = requestBody.Get<string>("Status");
					var account = new Account()
					{
						ID = id,
						Status = string.IsNullOrWhiteSpace(status) ? AccountStatus.Registered : status.ToEnum<AccountStatus>(),
						Type = (requestBody.Get<string>("Type") ?? "BuiltIn").ToEnum<AccountType>(),
						AccessIdentity = email,
						AccessKey = password,
					};

					await Account.CreateAsync(account, cancellationToken);

					json = account.GetAccountJson();
					if (requestInfo.Query.ContainsKey("related-service"))
						try
						{
							var result = await this.CallRelatedServiceAsync(requestInfo, json.FromJson<User>(), "account", "POST", cancellationToken);
							foreach (var info in result)
								if (json[info.Key] != null)
									json[info.Key] = info.Value;
								else
									json.Add(info.Key, info.Value);
						}
						catch { }

					// create profile
					var profile = new Profile() { ID = id };
					profile.CopyFrom(requestBody);
					profile.Name = name;
					profile.Email = email;

					await Profile.CreateAsync(profile, cancellationToken);
					if (requestInfo.Query.ContainsKey("related-service"))
						try
						{
							var result = await this.CallRelatedServiceAsync(requestInfo, json.FromJson<User>(), "profile", "POST", cancellationToken);
							foreach (var info in result)
								if (json[info.Key] != null)
									json[info.Key] = info.Value;
								else
									json.Add(info.Key, info.Value);
						}
						catch { }
				}

				// send activation email
				var mode = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-invite")
					? "invite"
					: "account";

				var code = (new JObject()
				{
					{ "ID", id },
					{ "Name", name },
					{ "Email", email },
					{ "Password", password },
					{ "Time", DateTime.Now },
					{ "Mode", requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-create") ? "Status" : "Create"  }
				}).ToString(Formatting.None).Encrypt(ServiceComponent.ActivationKey).ToBase64Url(true);

				var uri = requestInfo.Query.ContainsKey("uri")
					? requestInfo.Query["uri"].Url64Decode()
					: "http://localhost/#?prego=activate&mode={mode}&code={code}";
				uri = uri.Replace(StringComparison.OrdinalIgnoreCase, "{mode}", "account");
				uri = uri.Replace(StringComparison.OrdinalIgnoreCase, "{code}", code);

				// prepare activation email
				string inviter = "", inviterEmail = "";
				if (mode.Equals("invite"))
				{
					var profile = await Profile.GetAsync<Profile>(requestInfo.Session.User.ID, cancellationToken);
					inviter = profile.Name;
					inviterEmail = profile.Email;
				}

				var instructions = await this.GetActivateInstructionsAsync(requestInfo, mode, cancellationToken);
				var data = new Dictionary<string, string>()
				{
					{ "Host", requestInfo.GetQueryParameter("host") ?? "unknown" },
					{ "Email", email },
					{ "Password", password },
					{ "Name", name },
					{ "Time", DateTime.Now.ToString("hh:mm tt @ dd/MM/yyyy") },
					{ "AppPlatform", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
					{ "IP", requestInfo.Session.IP },
					{ "Uri", uri },
					{ "Code", code },
					{ "Inviter", inviter },
					{ "InviterEmail", inviterEmail },
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
				await this.SendEmailAsync(instructions.Item4, name + " <" + email + ">", subject, body, smtp.Item1, smtp.Item2, smtp.Item3, smtp.Item4, smtp.Item5, cancellationToken);

				// result
				return json;
			}
		}
		#endregion

		#region Update an account
		Task<JObject> UpdateAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			return Task.FromException<JObject>(new InvalidRequestException());
		}
		#endregion

		#region Renew password of an account
		string GenerateRandomPassword(string email)
		{
			var password = email.IndexOf("-") > 0
				? email.Substring(email.IndexOf("-"), 1)
				: email.IndexOf(".") > 0
					? email.Substring(email.IndexOf("."), 1)
					: email.IndexOf("_") > 0
						? email.Substring(email.IndexOf("_"), 1)
						: "#";

			return Captcha.GenerateRandomCode(true, true).ToUpper() + password
				+ Captcha.GenerateRandomCode(true, false).ToLower()
				+ UtilityService.GetUUID().GetHMACSHA1(email, false).Left(3).GetCapitalizedFirstLetter()
				+ UtilityService.GetUUID().Right(3).ToLower();
		}

		async Task<JObject> ResetPasswordAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account
			var email = requestInfo.Extra["Email"].Decrypt();
			var account = await Account.GetByEmailAsync(email, cancellationToken);
			if (account == null)
				return new JObject()
				{
					{ "Message", "Please check your email and follow the instruction to activate" }
				};

			// prepare
			var password = this.GenerateRandomPassword(email);
			var code = (new JObject()
			{
				{ "ID", account.ID },
				{ "Password", password },
				{ "Time", DateTime.Now }
			}).ToString(Formatting.None).Encrypt(ServiceComponent.ActivationKey).ToBase64Url(true);

			var uri = requestInfo.Query.ContainsKey("uri")
				? requestInfo.Query["uri"].Url64Decode()
				: "http://localhost/#?prego=activate&mode={mode}&code={code}";
			uri = uri.Replace(StringComparison.OrdinalIgnoreCase, "{mode}", "password");
			uri = uri.Replace(StringComparison.OrdinalIgnoreCase, "{code}", code);

			// prepare activation email
			var instructions = await this.GetActivateInstructionsAsync(requestInfo, "reset", cancellationToken);
			var data = new Dictionary<string, string>()
			{
				{ "Host", requestInfo.GetQueryParameter("host") ?? "unknown" },
				{ "Email", account.AccessIdentity },
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
			await this.SendEmailAsync(instructions.Item4, account.Profile.Name + " <" + account.AccessIdentity + ">", subject, body, smtp.Item1, smtp.Item2, smtp.Item3, smtp.Item4, smtp.Item5, cancellationToken);

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
			var oldPassword = requestInfo.Extra["OldPassword"].Decrypt();
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken);
			if (account == null || !Account.HashPassword(account.ID, oldPassword).Equals(account.AccessKey))
				throw new WrongAccountException();

			// update
			var password = requestInfo.Extra["Password"].Decrypt();
			account.AccessKey = Account.HashPassword(account.ID, password);
			account.LastAccess = DateTime.Now;
			await Account.UpdateAsync(account, cancellationToken);

			// send alert email
			var instructions = await this.GetUpdateInstructionsAsync(requestInfo, "password", cancellationToken);
			var data = new Dictionary<string, string>()
			{
				{ "Host", requestInfo.GetQueryParameter("host") ?? "unknown" },
				{ "Email", account.AccessIdentity },
				{ "Password", password },
				{ "Name", account.Profile.Name },
				{ "Time", DateTime.Now.ToString("hh:mm tt @ dd/MM/yyyy") },
				{ "AppPlatform", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
				{ "IP", requestInfo.Session.IP },
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
			await this.SendEmailAsync(instructions.Item4, account.Profile.Name + " <" + account.AccessIdentity + ">", subject, body, smtp.Item1, smtp.Item2, smtp.Item3, smtp.Item4, smtp.Item5, cancellationToken);

			// response
			return account.Profile.ToJson();
		}
		#endregion

		#region Update email of an account
		async Task<JObject> UpdateEmailAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account and check
			var oldPassword = requestInfo.Extra["OldPassword"].Decrypt();
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken);
			if (account == null || !Account.HashPassword(account.ID, oldPassword).Equals(account.AccessKey))
				throw new WrongAccountException();

			// check existing
			var email = requestInfo.Extra["Email"].Decrypt();
			var otherAccount = await Account.GetByEmailAsync(email, cancellationToken);
			if (otherAccount != null)
				throw new InformationExistedException("The email '" + email + "' is used by other account");

			// update
			var oldEmail = account.AccessIdentity;
			account.AccessIdentity = email.Trim().ToLower();
			account.LastAccess = DateTime.Now;

			account.Profile.Email = email;
			account.Profile.LastUpdated = DateTime.Now;

			await Task.WhenAll(
					Account.UpdateAsync(account, cancellationToken),
					Profile.UpdateAsync(account.Profile, cancellationToken)
				);

			// send alert email
			var instructions = await this.GetUpdateInstructionsAsync(requestInfo, "email", cancellationToken);
			var data = new Dictionary<string, string>()
			{
				{ "Host", requestInfo.GetQueryParameter("host") ?? "unknown" },
				{ "Email", account.AccessIdentity },
				{ "OldEmail", oldEmail },
				{ "Name", account.Profile.Name },
				{ "Time", DateTime.Now.ToString("hh:mm tt @ dd/MM/yyyy") },
				{ "AppPlatform", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
				{ "IP", requestInfo.Session.IP },
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
			await this.SendEmailAsync(instructions.Item4, account.Profile.Name + " <" + account.AccessIdentity + ">", subject, body, smtp.Item1, smtp.Item2, smtp.Item3, smtp.Item4, smtp.Item5, cancellationToken);

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

				// create a profile
				case "POST":
					return this.CreateProfileAsync(requestInfo, cancellationToken);

				// update a profile
				case "PUT":
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
			foreach (JObject profile in profiles)
			{
				if (requestInfo.Query.ContainsKey("related-service"))
					try
					{
						var data = await this.CallRelatedServiceAsync(requestInfo, "profile", "GET", (profile["ID"] as JValue).Value as string, cancellationToken);
						foreach (var info in data)
							if (profile[info.Key] != null)
								profile[info.Key] = info.Value;
							else
								profile.Add(info.Key, info.Value);
					}
					catch { }

				if (!requestInfo.Session.User.IsSystemAdministrator)
					this.NormalizeProfile(profile);
			}

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
			// prepare
			if (!this.IsAuthenticated(requestInfo))
				throw new AccessDeniedException();
			else if (!this.IsAuthorized(requestInfo, Components.Security.Action.View))
				throw new AccessDeniedException();

			var request = requestInfo.GetRequestExpando();
			var ids = request.Get<List<string>>("IDs");

			// fetch
			var filter = Filters<Profile>.Or(ids.Select(id => Filters<Profile>.Equals("ID", id)));
			var objects = await Profile.FindAsync(filter, null, 0, 1, null, cancellationToken);

			// build result
			var profiles = objects.ToJsonArray();
			foreach (JObject profile in profiles)
			{
				if (requestInfo.Query.ContainsKey("related-service"))
					try
					{
						var data = await this.CallRelatedServiceAsync(requestInfo, "profile", "GET", (profile["ID"] as JValue).Value as string, cancellationToken);
						foreach (var info in data)
							if (profile[info.Key] != null)
								profile[info.Key] = info.Value;
							else
								profile.Add(info.Key, info.Value);
					}
					catch { }

				if (!requestInfo.Session.User.IsSystemAdministrator)
					this.NormalizeProfile(profile);
			}

			// return
			return new JObject()
			{
				{ "Objects", profiles }
			};
		}
		#endregion

		#region Create a profile
		async Task<JObject> CreateProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-convert"))
			{
				if (!requestInfo.Session.User.IsSystemAdministrator)
					throw new AccessDeniedException();

				var profile = requestInfo.GetBodyJson().Copy<Profile>();
				await Profile.CreateAsync(profile, cancellationToken);
				return profile.ToJson();
			}

			throw new InvalidRequestException();
		}
		#endregion

		#region Get a profile
		async Task<JObject> GetProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// check permissions
			var id = requestInfo.GetObjectIdentity() ?? requestInfo.Session.User.ID;
			var gotRights = this.IsAuthenticated(requestInfo) && requestInfo.Session.User.ID.IsEquals(id);
			if (!gotRights)
				gotRights = this.IsAuthorized(requestInfo, Components.Security.Action.View);
			if (!gotRights)
				throw new AccessDeniedException();

			// get information
			var profile = await Profile.GetAsync<Profile>(id);
			if (profile == null)
				throw new InformationNotFoundException();

			// prepare response
			var json = profile.ToJson();

			// information of related service
			if (requestInfo.Query.ContainsKey("related-service"))
				try
				{
					var data = await this.CallRelatedServiceAsync(requestInfo, "profile", "GET", id, cancellationToken);
					foreach (var info in data)
						if (json[info.Key] != null)
							json[info.Key] = info.Value;
						else
							json.Add(info.Key, info.Value);
				}
				catch { }

			// normalize and return
			if (!requestInfo.Session.User.ID.Equals(profile.ID))
				this.NormalizeProfile(json);
			return json;
		}
		#endregion

		#region Update a profile
		async Task<JObject> UpdateProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// check permissions
			var id = requestInfo.GetObjectIdentity() ?? requestInfo.Session.User.ID;
			var gotRights = this.IsAuthenticated(requestInfo) && requestInfo.Session.User.ID.IsEquals(id);
			if (!gotRights)
				gotRights = this.IsAuthorized(requestInfo, Components.Security.Action.Update);
			if (!gotRights)
				throw new AccessDeniedException();

			// get information
			var profile = await Profile.GetAsync<Profile>(id);
			if (profile == null)
				throw new InformationNotFoundException();

			// update
			profile.CopyFrom(requestInfo.GetBodyJson());
			await Profile.UpdateAsync(profile, cancellationToken);

			// prepare response
			var json = profile.ToJson();

			// update information of related service
			if (requestInfo.Query.ContainsKey("related-service"))
				try
				{
					var data = await this.CallRelatedServiceAsync(requestInfo, "profile", "GET", id, cancellationToken);
					foreach (var info in data)
						if (json[info.Key] != null)
							json[info.Key] = info.Value;
						else
							json.Add(info.Key, info.Value);
				}
				catch { }

			// response
			if (!requestInfo.Session.User.ID.Equals(profile.ID))
				this.NormalizeProfile(json);
			return json;
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

			// activate account
			if (mode.IsEquals("account"))
				return await this.ActivateAccountAsync(requestInfo, info, cancellationToken);

			// activate password
			else if (mode.IsEquals("password"))
				return await this.ActivatePasswordAsync(requestInfo, info, cancellationToken);

			throw new InvalidRequestException();
		}

		#region Activate new account
		async Task<JObject> ActivateAccountAsync(RequestInfo requestInfo, ExpandoObject info, CancellationToken cancellationToken)
		{
			// prepare
			var id = info.Get<string>("ID");
			var mode = info.Get<string>("Mode");

			// activate
			if (mode.IsEquals("Status"))
			{
				// check
				var account = await Account.GetAsync<Account>(id, cancellationToken);
				if (account == null)
					throw new InformationNotFoundException();

				// update status
				if (account.Status.Equals(AccountStatus.Registered))
				{
					account.Status = AccountStatus.Activated;
					account.LastAccess = DateTime.Now;
					await Account.UpdateAsync(account, cancellationToken);
				}

				// response
				return account.GetAccountJson();
			}

			// create new account
			else
			{
				// prepare
				var name = info.Get<string>("Name");
				var email = info.Get<string>("Email");

				// create account
				var account = new Account()
				{
					ID = id,
					Status = AccountStatus.Activated,
					Type = (info.Get<string>("Type") ?? "BuiltIn").ToEnum<AccountType>(),
					Joined = info.Get<DateTime>("Time"),
					AccessIdentity = email,
					AccessKey = Account.HashPassword(id, info.Get<string>("Password"))
				};
				await Account.CreateAsync(account, cancellationToken);

				// prepare response
				var json = account.GetAccountJson();

				// update information of related service
				if (requestInfo.Query.ContainsKey("related-service"))
					try
					{
						var result = await this.CallRelatedServiceAsync(requestInfo, json.FromJson<User>(), "account", "POST", cancellationToken);
						foreach (var data in result)
							if (json[data.Key] != null)
								json[data.Key] = data.Value;
							else
								json.Add(data.Key, data.Value);
					}
					catch { }

				// create profile
				var profile = new Profile()
				{
					ID = id,
					Name = name,
					Email = email
				};
				await  Profile.CreateAsync(profile, cancellationToken);

				// update information of related service
				if (requestInfo.Query.ContainsKey("related-service"))
					try
					{
						await this.CallRelatedServiceAsync(requestInfo, json.FromJson<User>(), "profile", "POST", cancellationToken);
					}
					catch { }

				// return
				return json;
			}
		}
		#endregion 

		#region Activate new password
		async Task<JObject> ActivatePasswordAsync(RequestInfo requestInfo, ExpandoObject  info, CancellationToken cancellationToken)
		{
			// prepare
			var id = info.Get<string>("ID");
			var password = info.Get<string>("Password");

			// load account
			var account = await Account.GetAsync<Account>(id, cancellationToken);
			if (account == null)
				throw new InvalidActivateInformationException();

			// update new password
			account.AccessKey = Account.HashPassword(account.ID, password);
			account.LastAccess = DateTime.Now;
			account.Sessions = null;
			await Account.UpdateAsync(account);

			// response
			return account.GetAccountJson();
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
				+ (requestInfo.GetQueryParameter("register") ?? UtilityService.NewUID.Encrypt(CryptoService.DefaultEncryptionKey, true))
					.Substring(UtilityService.GetRandomNumber(13, 43), 13).Reverse() + ".jpg";

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