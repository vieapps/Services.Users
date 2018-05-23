#region Related components
using System;
using System.Linq;
using System.Dynamic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Numerics;
using System.IO.Compression;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	public class ServiceComponent : ServiceBase
	{
		public ServiceComponent() : base() { }

		ConcurrentDictionary<string, bool> VisitorSessions { get; } = new ConcurrentDictionary<string, bool>();

		public override string ServiceName => "Users";

		#region Encryption Keys
		internal string ActivationKey => this.GetKey("Activation", "VIEApps-56BA2999-NGX-A2E4-Services-4B54-Activation-83EB-Key-693C250DC95D");

		internal string AuthenticationKey => this.GetKey("Authentication", "VIEApps-65E47754-NGX-50C0-Services-4565-Authentication-BA55-Key-A8CC23879C5D");

		internal BigInteger ECCKey => this.GetKey("ECC", "tRZMCCemDIshR6SBnltv/kZvamQfMuMyx+2DG+2Yuw+13xN4A7Kk+nmEM81kx6ISlaxGgJjr/xK9kWznIC3OWlF2yrdMKeeCPM8eVFIfkiGqIPnGPDJaWRbtGswNjMmfQhbQvQ9qa5306RLt9F94vrOQp2M9eojE3cSuTqNg4OTL+9Dddabgzl94F3gOJoPRxzHqyKWRUhQdP+hOsWSS2KTska2ddm/Zh/fGKXwY9lnnrLHY1wjSJqCS3OO7PCRfQtEWSJcvzzgm7bvJ18fOLuJ5CZVThS+XLNwZgkbcICepRCiVbsk6fmh0482BJesG55pVeyv7ZyKNW+RyMXNEyLn5VY/1lPLxz7lLS88Lvqo=").Base64ToBytes().Decrypt().ToUnsignedBigInteger();

		internal string RSAKey => this.GetKey("RSA", "NihT0EJ2NLRhmGNbZ8A3jUdhZfO4jG4hfkwaHF1o00YoVx9S61TpmMiaZssOZB++UUyNsZZzxSfkh0i5O9Yr9us+/2zXhgR2zQVxOUrZnPpHpspyJzOegBpMMuTWF4WTl7st797BQ0AmUY1nEjfMTKVP+VSrrx0opTgi93MyvRGGa48vd7PosAM8uq+oMkhMZ/jTvasK6n3PKtb9XAm3hh4NFZBf7P2WuACXZ4Vbzd1MGtLHWfrYnWjGI9uhlo2QKueRLmHoqKM5pQFlB9M7/i2D/TXeWZSWNU+vW93xncUght3QtCwRJu7Kp8UGf8nnrFOshHgvMgsdDlvJt9ECN0/2uyUcWzB8cte5C9r6sP6ClUVSkKDvEOJVmuS2Isk72hbooPaAm7lS5NOzb2pHrxTKAZxaUyiZkFXH5rZxQ/5QjQ9PiAzm1AVdBE1tg1BzyGzY2z7RY/iQ5o22hhRSN3l49U4ftfXuL+LrGKnzxtVrQ15Vj9/pF7mz3lFy2ttTxJPccBiffi9LVtuUCo9BRgw7syn07gAqj1WXzuhPALwK6P6M1pPeFg6NEKLNWgRFE8GZ+dPhr2O0YCgDVuhJ+hDUxCDAEkZ0cQBiliHtjldJji1FnFMqg90QvFCuVCydq94Dnxdl9HSVMNC69i6H2GNfBuD9kTQ6gIOepc86YazDto8JljqEVOpkegusPENadLjpwOYCCslN1Y314B2g9vvZRwU3T+PcziBjym1ceagEEAObZ22Z/vhxBZ83Z2E1/RkbJqovIRKuHLCzU/4lBeTseJNlKPSACPuKAX08P4y5c+28WDrHv2+o7x9ISJe0SN1KmFMvv1xYtj/1NwOHQzfVjbpL46E0+Jr/IOOjh2CQhhUMm1GOEQAZ9n+b7a4diUPDG+BewAZvtd5gNX4zD0IKkJFwN+fBMWSHs0gs3jNz4RcYhH5IoHq27jrfM3cUlvBP9JpbZugNIh8ddZsUd4XQuCVZF+qlfRjY6lfEy4nXX48ianvdCqnBpkmRadG8qFLybkVS+s8RHcPwRkkzKQ4oGHdDeyiU8ZXnwvJ3IxDLoJV0xqKSRjhe9MxwdeN7VMSTNRAtQvqVvm6cL8KNbd2Hx1kPDEcqeUfVIeZ+zTIptO5GpjEMV+4gu338WG1RyEMAaiE536E+UR+0MqIe/Q==").Decrypt();
		#endregion

		#region Start
		public override void Start(string[] args = null, bool initializeRepository = true, Func<IService, Task> next = null)
		{
			base.Start(args, initializeRepository, async (service) =>
			{
				// register timers
				this.RegisterTimers(args);

				// last action
				if (next != null)
					try
					{
						await next(service).ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						await this.WriteLogsAsync(UtilityService.NewUUID, "Error occurred while invoking the next action", ex).ConfigureAwait(false);
					}
			});
		}
		#endregion

		public override async Task<JObject> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
		{
			var stopwatch = Stopwatch.StartNew();
			this.Logger.LogInformation($"Begin request ({requestInfo.Verb} {requestInfo.URI}) [{requestInfo.CorrelationID}]");
			try
			{
				JObject json = null;
				switch (requestInfo.ObjectName.ToLower())
				{
					case "session":
						json = await this.ProcessSessionAsync(requestInfo, cancellationToken).ConfigureAwait(false);
						break;

					case "otp":
						json = await this.ProcessOTPAsync(requestInfo, cancellationToken).ConfigureAwait(false);
						break;

					case "account":
						json = await this.ProcessAccountAsync(requestInfo, cancellationToken).ConfigureAwait(false);
						break;

					case "profile":
						json = await this.ProcessProfileAsync(requestInfo, cancellationToken).ConfigureAwait(false);
						break;

					case "activate":
						json = await this.ProcessActivationAsync(requestInfo, cancellationToken).ConfigureAwait(false);
						break;

					case "privileges":
						json = requestInfo.Verb.IsEquals("GET")
							? await this.GetPrivilegesAsync(requestInfo, cancellationToken).ConfigureAwait(false)
							: requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT")
								? await this.SetPrivilegesAsync(requestInfo, cancellationToken).ConfigureAwait(false)
								: throw new MethodNotAllowedException(requestInfo.Verb);
						break;

					case "status":
						json = await this.UpdateOnlineStatusAsync(requestInfo, cancellationToken).ConfigureAwait(false);
						break;

					case "captcha":
						json = this.RegisterSessionCaptcha(requestInfo);
						break;

					default:
						throw new InvalidRequestException($"The request is invalid ({requestInfo.Verb} {requestInfo.URI})");
				}
				stopwatch.Stop();
				this.Logger.LogInformation($"Success response - Execution times: {stopwatch.GetElapsedTimes()} [{requestInfo.CorrelationID}]");
				if (this.IsDebugResultsEnabled)
					this.Logger.LogInformation(
						$"- Request: {requestInfo.ToJson().ToString(this.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
						$"- Response: {json?.ToString(this.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
					);
				return json;
			}
			catch (Exception ex)
			{
				throw this.GetRuntimeException(requestInfo, ex, stopwatch);
			}
		}

		#region Working with related services
		async Task<Tuple<string, string, string, string, Tuple<string, int, bool, string, string>>> GetInstructionsOfRelatedServiceAsync(RequestInfo requestInfo, string mode = "reset", CancellationToken cancellationToken = default(CancellationToken))
		{
			var request = new RequestInfo()
			{
				Session = requestInfo.Session,
				ServiceName = requestInfo.Query["related-service"],
				ObjectName = "Instruction",
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
			var data = (await this.CallServiceAsync(request, cancellationToken).ConfigureAwait(false)).ToExpandoObject();

			var subject = data.Get<string>("Subject");
			var body = data.Get<string>("Body");
			var signature = data.Get<string>("Signature");
			var sender = data.Get<string>("Sender");
			var smtpServer = data.Get<string>("SmtpServer");
			var smtpServerPort = data.Get("SmtpServerPort", 25);
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
					var data = await this.GetInstructionsOfRelatedServiceAsync(requestInfo, mode, cancellationToken).ConfigureAwait(false);

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
					var data = await this.GetInstructionsOfRelatedServiceAsync(requestInfo, mode, cancellationToken).ConfigureAwait(false);

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

		async Task<JObject> CallRelatedServiceAsync(RequestInfo requestInfo, User user, string objectName, string verb, string objectIdentity, Dictionary<string, string> extra, CancellationToken cancellationToken = default(CancellationToken))
		{
			try
			{
				var request = new RequestInfo(
					new Services.Session(requestInfo.Session)
					{
						User = user ?? (requestInfo.Session.User ?? new User())
					},
					requestInfo.GetQueryParameter("related-service") ?? "",
					objectName ?? "",
					verb ?? "GET",
					new Dictionary<string, string>(requestInfo.Query ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
					new Dictionary<string, string>(requestInfo.Header ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
					requestInfo.Body ?? "",
					new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
					requestInfo.CorrelationID ?? UtilityService.NewUUID
				);

				if (!string.IsNullOrWhiteSpace(objectIdentity))
					request.Query["object-identity"] = objectIdentity;

				extra?.ForEach(kvp => request.Extra[kvp.Key] = kvp.Value);

				return await this.CallServiceAsync(request, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await this.WriteLogsAsync(requestInfo.CorrelationID, $"Error occurred while calling related service: {ex.Message}", ex).ConfigureAwait(false);
				return new JObject();
			}
		}

		Task<JObject> CallRelatedServiceAsync(RequestInfo requestInfo, string objectName, string verb = "GET", string objectIdentity = null, CancellationToken cancellationToken = default(CancellationToken))
			=> this.CallRelatedServiceAsync(requestInfo, requestInfo.Session.User, objectName, verb, objectIdentity, null, cancellationToken);
		#endregion

		Task<JObject> ProcessSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			switch (requestInfo.Verb)
			{
				// check exists
				case "EXIST":
					return this.CheckSessionExistsAsync(requestInfo, cancellationToken);

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

				// unknown
				default:
					throw new MethodNotAllowedException(requestInfo.Verb);
			}
		}

		#region Check exists of a session
		async Task<JObject> CheckSessionExistsAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// got cached
			var existed = await Utility.Cache.ExistsAsync<Session>(requestInfo.Session.SessionID, cancellationToken).ConfigureAwait(false);

			// no cached
			if (!existed && !requestInfo.Session.User.ID.Equals("") && !requestInfo.Session.User.IsSystemAccount)
				existed = await Session.GetAsync<Session>(requestInfo.Session.SessionID, cancellationToken).ConfigureAwait(false) != null;

			return new JObject()
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "Existed", existed }
			};
		}
		#endregion

		#region Get a session
		async Task<JObject> GetSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// verify
			if (requestInfo.Extra == null || !requestInfo.Extra.ContainsKey("Signature") || !requestInfo.Extra["Signature"].Equals(requestInfo.Header["x-app-token"].GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException("The signature is not found or invalid");

			// get information
			var session = requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount
				? await Utility.Cache.FetchAsync<Session>(requestInfo.Session.SessionID).ConfigureAwait(false)
				: await Session.GetAsync<Session>(requestInfo.Session.SessionID, cancellationToken).ConfigureAwait(false);

			return session?.ToJson();
		}
		#endregion

		#region Register a session
		async Task<JObject> RegisterSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			if (string.IsNullOrWhiteSpace(requestInfo.Session.SessionID))
				throw new InvalidRequestException();

			// verify
			if (requestInfo.Extra == null || !requestInfo.Extra.ContainsKey("Signature") || !requestInfo.Extra["Signature"].Equals(requestInfo.Body.GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException("The signature is not found or invalid");

			var request = requestInfo.GetBodyExpando();
			if (request == null)
				throw new InformationRequiredException();

			// register a session of vistor/system account
			if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount)
			{
				// update cache of session
				var session = request.Copy<Session>();
				await Utility.Cache.SetAsync(session, 180, cancellationToken).ConfigureAwait(false);
				this.VisitorSessions.TryAdd(session.ID, true);

				// response
				return session.ToJson();
			}

			// register a session of authenticated account
			else
			{
				var session = await Session.GetAsync<Session>(requestInfo.Session.SessionID, cancellationToken, false).ConfigureAwait(false);
				if (session == null)
				{
					session = request.Copy<Session>();
					await Session.CreateAsync(session, cancellationToken).ConfigureAwait(false);
				}
				else
				{
					if (!requestInfo.Session.SessionID.IsEquals(request.Get<string>("ID")) || !requestInfo.Session.User.ID.IsEquals(request.Get<string>("UserID")))
						throw new InvalidSessionException();

					session.CopyFrom(request);
					await Session.UpdateAsync(session, true, cancellationToken).ConfigureAwait(false);
				}

				// remove duplicated sessions
				await Session.DeleteManyAsync(Filters<Session>.And(
						Filters<Session>.Equals("DeviceID", session.DeviceID),
						Filters<Session>.NotEquals("ID", session.ID)
					), null, cancellationToken).ConfigureAwait(false);

				// update account information
				var account = await Account.GetAsync<Account>(session.UserID, cancellationToken).ConfigureAwait(false);
				account.LastAccess = DateTime.Now;
				await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);
				await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);

				// response
				return session.ToJson();
			}
		}
		#endregion

		#region Sign a session in
		async Task<JObject> SignSessionInAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// verify
			if (requestInfo.Extra == null || !requestInfo.Extra.ContainsKey("Signature") || !requestInfo.Extra["Signature"].Equals(requestInfo.Body.GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException("The signature is not found or invalid");

			// prepare
			var request = requestInfo.GetBodyExpando();
			var type = request.Get("Type", "BuiltIn").ToEnum<AccountType>();
			var email = request.Get<string>("Email").Decrypt(this.EncryptionKey).Trim().ToLower();
			var password = request.Get<string>("Password").Decrypt(this.EncryptionKey);
			Account account = null;

			// Windows account
			if (type.Equals(AccountType.Windows))
			{
				var username = email.Left(email.PositionOf("@"));
				username = username.PositionOf(@"\") > 0
					? username.Right(username.Length - username.PositionOf(@"\") - 1).Trim()
					: username.Trim();
				var domain = email.Right(email.Length - email.PositionOf("@") - 1).Trim();

				var body = new JObject
				{
					{ "Domain", domain.Encrypt(this.EncryptionKey) },
					{ "Username", username.Encrypt(this.EncryptionKey) },
					{ "Password", password.Encrypt(this.EncryptionKey) }
				}.ToString(Formatting.None);

				await this.CallServiceAsync(new RequestInfo(requestInfo.Session, "WindowsAD", "Account")
				{
					Verb = "POST",
					Header = requestInfo.Header,
					Body = body,
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", body.GetHMACSHA256(this.ValidationKey) }
					}
				}, cancellationToken).ConfigureAwait(false);

				// state to create information of account/profile
				var needToCreateAccount = true;
				if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-no-account"))
					needToCreateAccount = false;

				// create information of account/profile
				if (needToCreateAccount)
				{
					account = await Account.GetByIdentityAsync(email, AccountType.Windows, cancellationToken).ConfigureAwait(false);
					if (account == null)
					{
						account = new Account
						{
							ID = UtilityService.NewUUID,
							Type = AccountType.Windows,
							AccessIdentity = email
						};
						await Account.CreateAsync(account, cancellationToken).ConfigureAwait(false);

						var profile = new Profile
						{
							ID = account.ID,
							Name = request.Get("Name", username),
							Email = email
						};
						await Profile.CreateAsync(profile, cancellationToken).ConfigureAwait(false);
					}
				}

				// no need to create account, then response with success state
				else
					return new JObject();
			}

			// OAuth account
			else if (type.Equals(AccountType.OAuth))
			{

			}

			// BuiltIn account
			else
			{
				account = await Account.GetByIdentityAsync(email, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
				if (account == null || !Account.GeneratePassword(account.ID, password).Equals(account.AccessKey))
					throw new WrongAccountException();
			}

			// prepare results
			var results = account.GetAccountJson();

			// two-factors authentication is required
			if (account.TwoFactorsAuthentication.Required)
			{
				results["Require2FA"] = true;
				results["Providers"] = account.TwoFactorsAuthentication.GetProvidersJson(this.AuthenticationKey);
			}

			// clear cached of current session when 2FA is not required
			else
				await Utility.Cache.RemoveAsync<Session>(requestInfo.Session.SessionID).ConfigureAwait(false);

			// response
			return results;
		}
		#endregion

		#region Sign a session out
		async Task<JObject> SignSessionOutAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// verify
			if (requestInfo.Extra == null || !requestInfo.Extra.ContainsKey("Signature") || !requestInfo.Extra["Signature"].Equals(requestInfo.Header["x-app-token"].GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException("The signature is not found or invalid");

			// remove session
			await Session.DeleteAsync<Session>(requestInfo.Session.SessionID, requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);

			// update account
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
			if (account != null)
			{
				if (account.Sessions == null)
					await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);
				account.Sessions = account.Sessions.Where(s => !s.ID.Equals(requestInfo.Session.SessionID)).ToList();
				account.LastAccess = DateTime.Now;
				await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);
			}

			// response
			return new JObject();
		}
		#endregion

		Task<JObject> ProcessOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			switch (requestInfo.Verb)
			{
				// validate
				case "POST":
					return this.ValidateOTPAsync(requestInfo, cancellationToken);

				// provisioning
				case "GET":
					return this.GetProvisioningOTPAsync(requestInfo, cancellationToken);

				// update
				case "PUT":
					return this.UpdateOTPAsync(requestInfo, cancellationToken);

				// delete
				case "DELETE":
					return this.DeleteOTPAsync(requestInfo, cancellationToken);

				// unknown
				default:
					throw new MethodNotAllowedException(requestInfo.Verb);
			}
		}

		#region Validate an OTP
		async Task<JObject> ValidateOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var body = requestInfo.GetBodyExpando();

			var id = body.Get("ID", "");
			var otp = body.Get("OTP", "");
			var info = body.Get("Info", "");
			if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(otp) || string.IsNullOrWhiteSpace(info))
				throw new InformationRequiredException();

			try
			{
				id = id.Decrypt(this.EncryptionKey);
				otp = otp.Decrypt(this.EncryptionKey);
				info = info.Decrypt(this.EncryptionKey);
			}
			catch (Exception ex)
			{
				throw new InformationInvalidException(ex);
			}

			var account = await Account.GetAsync<Account>(id, cancellationToken);
			if (account == null)
				throw new InformationNotFoundException();

			var type = TwoFactorsAuthenticationType.App;
			var stamp = "";
			try
			{
				var data = info.Decrypt(this.AuthenticationKey, true).ToArray('|');
				type = data[0].ToEnum<TwoFactorsAuthenticationType>();
				var time = Convert.ToInt64(data[2]);
				if (account.TwoFactorsAuthentication.Settings.Where(s => s.Type.Equals(type) && s.Stamp.Equals(data[1]) && s.Time.Equals(time)).Count() > 0)
					stamp = data[1] + (!type.Equals(TwoFactorsAuthenticationType.Phone) ? $"|{time}" : "");
				else
					throw new InformationInvalidException();
			}
			catch (InformationInvalidException)
			{
				throw;
			}
			catch (Exception ex)
			{
				throw new InformationInvalidException(ex);
			}

			// validate
			await this.CallServiceAsync(new RequestInfo(requestInfo.Session, "AuthenticatorOTP", "Time-Based-OTP")
			{
				Verb = "GET",
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Type", type.ToString() },
					{ "ID", account.ID.Encrypt(this.EncryptionKey) },
					{ "Stamp", stamp.Encrypt(this.EncryptionKey) },
					{ "Password", otp.Encrypt(this.EncryptionKey) }
				}
			}, cancellationToken).ConfigureAwait(false);

			// update when success
			await Task.WhenAll(
				Utility.Cache.SetAsync(account),
				Utility.Cache.RemoveAsync<Session>(requestInfo.Session.SessionID)
			).ConfigureAwait(false);

			return account.GetAccountJson();
		}
		#endregion

		#region Get an OTP for provisioning
		async Task<JObject> GetProvisioningOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// check
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
			if (account == null)
				throw new InformationNotFoundException();

			var body = requestInfo.GetRequestExpando();
			if (!body.Get("Type", "").TryToEnum(out TwoFactorsAuthenticationType type))
				type = TwoFactorsAuthenticationType.App;

			var stamp = type.Equals(TwoFactorsAuthenticationType.App) ? UtilityService.NewUUID : body.Get("Number", "");
			if (string.IsNullOrWhiteSpace(stamp))
				throw new InformationRequiredException();

			// get provisioning info
			stamp += "|" + DateTime.Now.ToUnixTimestamp().ToString();
			var json = await this.CallServiceAsync(new RequestInfo(requestInfo.Session, "AuthenticatorOTP", "Time-Based-OTP")
			{
				Verb = "GET",
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Type", type.ToString() },
					{ "ID", account.ID.Encrypt(this.EncryptionKey) },
					{ "Stamp", stamp.Encrypt(this.EncryptionKey) },
					{ "Account", account.AccessIdentity.Encrypt(this.EncryptionKey) },
					{ "Issuer", body.Get("Issuer", "").Encrypt(this.EncryptionKey) },
					{ "Setup", "" }
				}
			}, cancellationToken).ConfigureAwait(false);

			// response
			json.Add(new JProperty("Provisioning", new JObject
			{
				{ "Type", type.ToString() },
				{ "Account", account.AccessIdentity },
				{ "ID", account.ID },
				{ "Stamp", stamp }
			}.ToString(Formatting.None).Encrypt(this.AuthenticationKey)));
			return json;
		}
		#endregion

		#region Update an OTP
		async Task<JObject> UpdateOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken);
			if (account == null)
				throw new InformationNotFoundException();

			var body = requestInfo.GetBodyExpando();
			var json = JObject.Parse(body.Get("Provisioning", "").Decrypt(this.AuthenticationKey));
			if (!account.ID.IsEquals((json["ID"] as JValue).Value.ToString()) || !account.AccessIdentity.IsEquals((json["Account"] as JValue).Value.ToString()))
				throw new InformationInvalidException();

			// validate with OTPs service
			if (!Enum.TryParse((json["Type"] as JValue).Value as string, out TwoFactorsAuthenticationType type))
				type = TwoFactorsAuthenticationType.App;
			var stamp = (json["Stamp"] as JValue).Value.ToString();
			json = await this.CallServiceAsync(new RequestInfo(requestInfo.Session, "AuthenticatorOTP", "Time-Based-OTP")
			{
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Type", type.ToString() },
					{ "ID", account.ID.Encrypt(this.EncryptionKey) },
					{ "Stamp", stamp.Encrypt(this.EncryptionKey) },
					{ "Password", body.Get("OTP", "").Encrypt(this.EncryptionKey) }
				}
			}, cancellationToken).ConfigureAwait(false);

			// update settings
			account.TwoFactorsAuthentication.Required = true;
			account.TwoFactorsAuthentication.Settings.Add(new TwoFactorsAuthenticationSetting
			{
				Type = type,
				Stamp = stamp.ToArray('|').First(),
				Time = Convert.ToInt64(stamp.ToArray('|').Last())
			});

			// get all sessions
			if (account.Sessions == null)
				await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);

			// revoke all sessions that are not verified with two-factors authentication
			var sessions = account.Sessions.Where(s => !s.ID.Equals(requestInfo.Session.SessionID) && !s.Verification).ToList();
			var messages = sessions.Select(s => new BaseMessage()
			{
				Type = "Session#Revoke",
				Data = new JObject
				{
					{ "Session", s.ID },
					{ "User", account.GetAccountJson() },
					{ "Device", s.DeviceID }
				}
			}).ToList();

			// update current session
			var session = account.Sessions.First(s => s.ID.Equals(requestInfo.Session.SessionID));
			var needUpdate = false;
			if (!session.Verification)
			{
				needUpdate = session.Verification = true;
				messages.Add(new BaseMessage()
				{
					Type = "Session#Update",
					Data = new JObject
					{
						{ "Session", session.ID },
						{ "User", account.GetAccountJson() },
						{ "Device", session.DeviceID },
						{ "Verification", session.Verification },
						{ "Token", session.AccessToken.Encrypt(this.EncryptionKey) }
					}
				});
			}

			// update account
			if (sessions.Count > 0)
				account.Sessions = account.Sessions.Except(sessions).ToList();
			json = account.GetAccountJson(true, this.AuthenticationKey);

			// run all tasks
			await Task.WhenAll(
				Account.UpdateAsync(account, true, cancellationToken),
				!needUpdate
					? Task.CompletedTask
					: Session.UpdateAsync(session, true, cancellationToken),
				sessions.Count < 1
					? Task.CompletedTask
					: Session.DeleteManyAsync(Filters<Session>.Or(sessions.Select(s => Filters<Session>.Equals("ID", s.ID))), null, cancellationToken),
				sessions.Count < 1
					? Task.CompletedTask
					: sessions.ForEachAsync((s, t) => Utility.Cache.RemoveAsync(s)),
				messages.Count < 1
					? Task.CompletedTask
					: this.SendInterCommunicateMessagesAsync("APIGateway", messages, cancellationToken),
				this.SendUpdateMessageAsync(new UpdateMessage
				{
					Type = "Users#Account",
					DeviceID = requestInfo.Session.DeviceID,
					Data = json
				}, cancellationToken)
			).ConfigureAwait(false);

			// response
			return json;
		}
		#endregion

		#region Delete an OTP
		async Task<JObject> DeleteOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken);
			if (account == null)
				throw new InformationNotFoundException();

			var info = (requestInfo.Query.ContainsKey("Info") ? requestInfo.Query["Info"].Decrypt(this.AuthenticationKey, true) : "").ToArray('|');
			var type = info[0].ToEnum<TwoFactorsAuthenticationType>();
			var stamp = info[1];
			var time = Convert.ToInt64(info[2]);

			// update settings
			account.TwoFactorsAuthentication.Settings = account.TwoFactorsAuthentication.Settings.Where(s => !s.Type.Equals(type) && !s.Stamp.Equals(stamp) && !s.Time.Equals(time)).ToList();
			account.TwoFactorsAuthentication.Required = account.TwoFactorsAuthentication.Settings.Count > 0;

			// prepare to update
			var json = account.GetAccountJson(true, this.AuthenticationKey);

			if (account.Sessions == null)
				await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);

			if (!account.TwoFactorsAuthentication.Required)
				account.Sessions.ForEach(s => s.Verification = false);

			var messages = account.Sessions
				.Where(s => s.Online)
				.Select(s => new UpdateMessage
				{
					Type = "Users#Account",
					DeviceID = s.DeviceID,
					Data = json
				})
				.ToList();

			// run all tasks
			await Task.WhenAll(
				Account.UpdateAsync(account, true, cancellationToken),
				account.TwoFactorsAuthentication.Required
					? Task.CompletedTask
					: account.Sessions.ForEachAsync((session, token) => Session.UpdateAsync(session, true, token), cancellationToken),
				account.TwoFactorsAuthentication.Required
					? Task.CompletedTask
					: this.SendInterCommunicateMessagesAsync("APIGateway", account.Sessions.Select(session => new BaseMessage()
					{
						Type = "Session#Refresh",
						Data = new JObject
						{
							{ "Session", session.ID }
						}
					}).ToList(), cancellationToken),
				this.SendUpdateMessagesAsync(messages, cancellationToken)
			).ConfigureAwait(false);

			// response
			return json;
		}
		#endregion

		Task<JObject> ProcessAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			switch (requestInfo.Verb)
			{
				// get an account
				case "GET":
					return this.GetAccountAsync(requestInfo, cancellationToken);

				// create or invite to register an account
				case "POST":
					return this.CreateAccountAsync(requestInfo, cancellationToken);

				// update an account
				case "PUT":
					var identity = requestInfo.GetObjectIdentity();
					if ("reset".IsEquals(identity))
						return this.ResetPasswordAsync(requestInfo, cancellationToken);
					else if ("password".IsEquals(identity))
						return this.UpdatePasswordAsync(requestInfo, cancellationToken);
					else if ("email".IsEquals(identity))
						return this.UpdateEmailAsync(requestInfo, cancellationToken);
					else
						return this.SetPrivilegesAsync(requestInfo, cancellationToken);

				// get sessions of an account
				case "HEAD":
					return this.GetAccountSessionsAsync(requestInfo, cancellationToken);

				// unknown
				default:
					throw new MethodNotAllowedException(requestInfo.Verb);
			}
		}

		#region Get an account
		async Task<JObject> GetAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// check to see the user in the request is system administrator or not
			if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("IsSystemAdministrator"))
				return new JObject()
				{
					{ "ID", requestInfo.Session.User.ID },
					{ "IsSystemAdministrator", requestInfo.Session.User.IsSystemAdministrator }
				};

			// check permission
			if (!this.IsAuthenticated(requestInfo))
				throw new AccessDeniedException();

			// get account information
			var account = await Account.GetAsync<Account>(requestInfo.GetObjectIdentity() ?? requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
			if (account == null)
				throw new InformationNotFoundException();

			// response
			return account.GetAccountJson(requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-status"), this.AuthenticationKey);
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
				account.AccessKey = requestBody.Get<string>("AccessKey") ?? Account.GeneratePassword(account.AccessIdentity);

				await Account.CreateAsync(account, cancellationToken).ConfigureAwait(false);
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
					? requestInfo.Extra["Email"].Decrypt(this.EncryptionKey).Trim().ToLower()
					: null;
				var password = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Password")
					? requestInfo.Extra["Password"].Decrypt(this.EncryptionKey)
					: null;
				if (string.IsNullOrWhiteSpace(password))
					password = Account.GeneratePassword(email);

				// check existing account
				if (await Account.GetByIdentityAsync(email, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false) != null)
					throw new InformationExistedException("The email address (" + email + ") has been used for another account");

				// related: privileges, service, extra info
				var relatedService = requestInfo.Query.ContainsKey("related-service")
					? requestInfo.Query["related-service"]
					: null;

				var privileges = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Privileges")
					? JArray.Parse(requestInfo.Extra["Privileges"].Decrypt(this.EncryptionKey)).ToList<Privilege>()
					: null;

				var relatedInfo = !string.IsNullOrWhiteSpace(relatedService) && requestInfo.Extra != null && requestInfo.Extra.ContainsKey("RelatedInfo")
					? requestInfo.Extra["RelatedInfo"].Decrypt(this.EncryptionKey).ToExpandoObject()
					: null;

				// permissions of privileges & related info
				if (privileges != null || relatedInfo != null)
				{
					var gotRights = await this.IsSystemAdministratorAsync(requestInfo).ConfigureAwait(false);
					if (!gotRights && !string.IsNullOrWhiteSpace(relatedService))
						gotRights = await this.IsServiceAdministratorAsync(requestInfo.Session.User, relatedService).ConfigureAwait(false);

					if (!gotRights)
					{
						privileges = null;
						relatedInfo = null;
					}
				}

				// create new account & profile
				var isCreateNew = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-create");
				if (isCreateNew)
				{
					// create account
					var account = new Account()
					{
						ID = id,
						Status = requestBody.Get("Status", "Registered").ToEnum<AccountStatus>(),
						Type = requestBody.Get("Type", "BuiltIn").ToEnum<AccountType>(),
						AccessIdentity = email,
						AccessKey = password,
						AccessPrivileges = privileges ?? new List<Privilege>()
					};

					await Account.CreateAsync(account, cancellationToken).ConfigureAwait(false);
					json = account.GetAccountJson();

					// create profile
					var profile = requestBody.Copy<Profile>();
					profile.ID = id;
					profile.Name = name;
					profile.Email = email;

					await Task.WhenAll(
						Profile.CreateAsync(profile, cancellationToken),
						requestInfo.Query.ContainsKey("related-service") ? this.CallRelatedServiceAsync(requestInfo, json.FromJson<User>(), "profile", "POST", null, relatedInfo?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value as string), cancellationToken) : Task.CompletedTask
					).ConfigureAwait(false);
				}

				// send activation email
				var mode = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-invite")
					? "invite"
					: "account";

				var codeData = new JObject()
				{
					{ "ID", id },
					{ "Name", name },
					{ "Email", email },
					{ "Password", password },
					{ "Time", DateTime.Now },
					{ "Mode", isCreateNew ? "Status" : "Create"  }
				};

				if (privileges != null)
					codeData.Add("Privileges", privileges.ToJsonArray());

				if (!string.IsNullOrWhiteSpace(relatedService) && relatedInfo != null)
				{
					codeData.Add("RelatedService", new JValue(relatedService));
					codeData.Add("RelatedUser", new JValue(requestInfo.Session.User.ID));
					codeData.Add("RelatedInfo", relatedInfo.ToJson());
				}

				var code = codeData.ToString(Formatting.None).Encrypt(this.ActivationKey).ToBase64Url(true);
				var uri = requestInfo.Query.ContainsKey("uri")
					? requestInfo.Query["uri"].Url64Decode()
					: "https://accounts.vieapps.net/#?prego=activate&mode={mode}&code={code}";
				uri = uri.Replace(StringComparison.OrdinalIgnoreCase, "{mode}", "account");
				uri = uri.Replace(StringComparison.OrdinalIgnoreCase, "{code}", code);

				// prepare activation email
				string inviter = "", inviterEmail = "";
				if (mode.Equals("invite"))
				{
					var profile = await Profile.GetAsync<Profile>(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
					inviter = profile.Name;
					inviterEmail = profile.Email;
				}

				var instructions = await this.GetActivateInstructionsAsync(requestInfo, mode, cancellationToken).ConfigureAwait(false);
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
				await this.SendEmailAsync(instructions.Item4, name + " <" + email + ">", subject, body, smtp.Item1, smtp.Item2, smtp.Item3, smtp.Item4, smtp.Item5, cancellationToken).ConfigureAwait(false);

				// result
				return json;
			}
		}
		#endregion

		#region Get the privilege objects of an account
		async Task<JObject> GetPrivilegesAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var serviceName = requestInfo.GetQueryParameter("related-service");
			var gotRights = requestInfo.Session.User.IsSystemAdministrator;
			if (!string.IsNullOrWhiteSpace(serviceName))
			{
				var systemID = requestInfo.GetQueryParameter("related-system");
				var objectIdentity = requestInfo.GetQueryParameter("related-object-identity");
				var service = await this.GetServiceAsync(serviceName).ConfigureAwait(false);
				if (!gotRights)
					gotRights = service != null
						? string.IsNullOrWhiteSpace(systemID)
							? await service.CanManageAsync(requestInfo.Session.User, requestInfo.GetQueryParameter("related-object"), objectIdentity).ConfigureAwait(false)
							: await service.CanManageAsync(requestInfo.Session.User, systemID, requestInfo.GetQueryParameter("related-definition"), objectIdentity).ConfigureAwait(false)
						: false;
				return gotRights
					? await this.CallServiceAsync(new RequestInfo(requestInfo.Session, serviceName, "Privileges", "GET")
					{
						Header = requestInfo.Header,
						Query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
						{
							{ "x-system", systemID },
							{ "x-object", requestInfo.GetQueryParameter("related-object") },
							{ "x-definition", requestInfo.GetQueryParameter("related-definition") },
							{ "x-object-identity", objectIdentity }
						},
						CorrelationID = requestInfo.CorrelationID
					}, cancellationToken).ConfigureAwait(false)
					: throw new AccessDeniedException();
			}

			return gotRights
				? new JObject()
				: throw new AccessDeniedException();
		}
		#endregion

		#region Update the privileges of an account
		async Task<JObject> SetPrivilegesAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var systemID = requestInfo.GetQueryParameter("related-system");
			var serviceName = requestInfo.GetQueryParameter("related-service");

			// system administrator can do
			var gotRights = requestInfo.Session.User.IsSystemAdministrator;

			// check with related service
			if (!gotRights && !string.IsNullOrWhiteSpace(serviceName))
			{
				var objectIdentity = requestInfo.GetQueryParameter("related-object-identity");
				var service = await this.GetServiceAsync(serviceName).ConfigureAwait(false);
				gotRights = service != null
					? string.IsNullOrWhiteSpace(systemID)
						? await service.CanManageAsync(requestInfo.Session.User, requestInfo.GetQueryParameter("related-object"), objectIdentity).ConfigureAwait(false)
						: await service.CanManageAsync(requestInfo.Session.User, systemID, requestInfo.GetQueryParameter("related-definition"), objectIdentity).ConfigureAwait(false)
					: false;
			}

			// stop if has no right to do
			if (!gotRights)
				throw new AccessDeniedException();

			// get account
			var account = await Account.GetAsync<Account>(requestInfo.GetObjectIdentity(), cancellationToken).ConfigureAwait(false);
			if (account == null)
				throw new InformationNotFoundException();

			// roles of a system
			if (!string.IsNullOrWhiteSpace(systemID) && requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Roles"))
				try
				{
					account.AccessRoles[systemID] = JArray.Parse(requestInfo.Extra["Roles"].Decrypt(this.EncryptionKey)).ToList<string>();
				}
				catch { }

			// privileges of a service
			if (!string.IsNullOrWhiteSpace(serviceName) && requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Privileges"))
				try
				{
					account.AccessPrivileges = account.AccessPrivileges.Where(p => !p.ServiceName.IsEquals(serviceName))
						.Concat(JArray.Parse(requestInfo.Extra["Privileges"].Decrypt(this.EncryptionKey)).ToList<Privilege>().Where(p => p.ServiceName.IsEquals(serviceName))).ToList();
				}
				catch { }

			// sessions
			var json = account.GetAccountJson(account.TwoFactorsAuthentication.Required, this.AuthenticationKey);
			var user = json.FromJson<User>();
			if (account.Sessions == null)
				await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);

			account.Sessions
				.Where(session => session.ExpiredAt > DateTime.Now)
				.ForEach(session =>
				{
					session.RenewedAt = DateTime.Now;
					session.ExpiredAt = DateTime.Now.AddDays(60);
					session.AccessToken = user.GetAccessToken(this.ECCKey);
				});

			// update database
			await Task.WhenAll(
				Account.UpdateAsync(account, requestInfo.Session.User.ID, cancellationToken),
				Task.WhenAll(account.Sessions.Select(session => Session.UpdateAsync(session, true, cancellationToken)))
			).ConfigureAwait(false);

			// send update messages
			await this.SendInterCommunicateMessagesAsync("APIGateway", account.Sessions.Select(session => new BaseMessage()
			{
				Type = "Session#Update",
				Data = new JObject()
				{
					{ "Session", session.ID },
					{ "User", json },
					{ "Device", session.DeviceID },
					{ "Verification", session.Verification },
					{ "Token", session.AccessToken.Encrypt(this.EncryptionKey) }
				}
			}).ToList(), cancellationToken).ConfigureAwait(false);

			// response
			return json;
		}
		#endregion

		#region Renew password of an account
		async Task<JObject> ResetPasswordAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account
			var email = requestInfo.Extra["Email"].Decrypt(this.EncryptionKey);
			var account = await Account.GetByIdentityAsync(email, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
			if (account == null)
				return new JObject()
				{
					{ "Message", "Please check your email and follow the instruction to activate" }
				};

			// prepare
			var password = Account.GeneratePassword(email);
			var code = new JObject()
			{
				{ "ID", account.ID },
				{ "Password", password },
				{ "Time", DateTime.Now }
			}.ToString(Formatting.None).Encrypt(this.ActivationKey).ToBase64Url(true);

			var uri = requestInfo.Query.ContainsKey("uri")
				? requestInfo.Query["uri"].Url64Decode()
				: "https://accounts.vieapps.net/#?prego=activate&mode={mode}&code={code}";
			uri = uri.Replace(StringComparison.OrdinalIgnoreCase, "{mode}", "password");
			uri = uri.Replace(StringComparison.OrdinalIgnoreCase, "{code}", code);

			// prepare activation email
			var instructions = await this.GetActivateInstructionsAsync(requestInfo, "reset", cancellationToken).ConfigureAwait(false);
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
			await this.SendEmailAsync(instructions.Item4, account.Profile.Name + " <" + account.AccessIdentity + ">", subject, body, smtp.Item1, smtp.Item2, smtp.Item3, smtp.Item4, smtp.Item5, cancellationToken).ConfigureAwait(false);

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
			var oldPassword = requestInfo.Extra["OldPassword"].Decrypt(this.EncryptionKey);
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
			if (account == null || !Account.GeneratePassword(account.ID, oldPassword).Equals(account.AccessKey))
				throw new WrongAccountException();

			// update
			var password = requestInfo.Extra["Password"].Decrypt(this.EncryptionKey);
			account.AccessKey = Account.GeneratePassword(account.ID, password);
			account.LastAccess = DateTime.Now;
			await Account.UpdateAsync(account, true, cancellationToken);

			// send alert email
			var instructions = await this.GetUpdateInstructionsAsync(requestInfo, "password", cancellationToken).ConfigureAwait(false);
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
			await this.SendEmailAsync(instructions.Item4, account.Profile.Name + " <" + account.AccessIdentity + ">", subject, body, smtp.Item1, smtp.Item2, smtp.Item3, smtp.Item4, smtp.Item5, cancellationToken).ConfigureAwait(false);

			// response
			return account.Profile.ToJson();
		}
		#endregion

		#region Update email of an account
		async Task<JObject> UpdateEmailAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account and check
			var oldPassword = requestInfo.Extra["OldPassword"].Decrypt(this.EncryptionKey);
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
			if (account == null || !Account.GeneratePassword(account.ID, oldPassword).Equals(account.AccessKey))
				throw new WrongAccountException();

			// check existing
			var email = requestInfo.Extra["Email"].Decrypt(this.EncryptionKey);
			var otherAccount = await Account.GetByIdentityAsync(email, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
			if (otherAccount != null)
				throw new InformationExistedException("The email '" + email + "' is used by other account");

			// update
			var oldEmail = account.AccessIdentity;
			account.AccessIdentity = email.Trim().ToLower();
			account.LastAccess = DateTime.Now;

			account.Profile.Email = email.Trim().ToLower();
			account.Profile.LastUpdated = DateTime.Now;

			await Task.WhenAll(
				Account.UpdateAsync(account, requestInfo.Session.User.ID, cancellationToken),
				Profile.UpdateAsync(account.Profile, requestInfo.Session.User.ID, cancellationToken)
			).ConfigureAwait(false);

			// send alert email
			var instructions = await this.GetUpdateInstructionsAsync(requestInfo, "email", cancellationToken).ConfigureAwait(false);
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
			await this.SendEmailAsync(instructions.Item4, account.Profile.Name + " <" + account.AccessIdentity + ">", subject, body, smtp.Item1, smtp.Item2, smtp.Item3, smtp.Item4, smtp.Item5, cancellationToken).ConfigureAwait(false);

			// response
			return account.Profile.ToJson();
		}
		#endregion

		#region Get the sessions of an account
		async Task<JObject> GetAccountSessionsAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var userID = requestInfo.GetObjectIdentity() ?? requestInfo.Session.User.ID;
			var account = !userID.Equals("") && !requestInfo.Session.User.IsSystemAccount
				? await Account.GetAsync<Account>(userID, cancellationToken).ConfigureAwait(false)
				: null;
			if (account != null && account.Sessions == null)
				await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);

			return new JObject()
			{
				{ "ID", userID },
				{
					"Sessions",
					account != null
						? account.Sessions.ToJArray(session => new JObject()
						{
							{ "SessionID", session.ID },
							{ "DeviceID", session.DeviceID },
							{ "AppInfo", session.AppInfo },
							{ "IsOnline", session.Online }
						})
						: new JArray()
				}
			};
		}
		#endregion

		Task<JObject> ProcessProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			switch (requestInfo.Verb)
			{
				case "GET":
					var identity = requestInfo.GetObjectIdentity();

					// search
					if ("search".IsEquals(identity))
						return this.SearchProfilesAsync(requestInfo, cancellationToken);

					// fetch
					else if ("fetch".IsEquals(identity))
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

				// unknown
				default:
					return Task.FromException<JObject>(new MethodNotAllowedException(requestInfo.Verb));
			}
		}

		#region Search profiles
		async Task<JObject> SearchProfilesAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// check permissions
			if (!this.IsAuthenticated(requestInfo))
				throw new AccessDeniedException();

			// prepare
			var request = requestInfo.GetRequestExpando();

			var query = request.Get<string>("FilterBy.Query");

			var filter = request.Get<ExpandoObject>("FilterBy", null)?.ToFilterBy<Profile>();

			var sort = request.Get<ExpandoObject>("SortBy", null)?.ToSortBy<Profile>();
			if (sort == null && string.IsNullOrWhiteSpace(query))
				sort = Sorts<Profile>.Ascending("Name");

			var pagination = request.Has("Pagination")
				? request.Get<ExpandoObject>("Pagination").GetPagination()
				: new Tuple<long, int, int, int>(-1, 0, 20, 1);

			var pageNumber = pagination.Item4;

			// check cache
			var cacheKey = string.IsNullOrWhiteSpace(query)
				? this.GetCacheKey<Profile>(filter, sort)
				: "";

			var json = !cacheKey.Equals("")
				? await Utility.Cache.GetAsync<string>($"{cacheKey }{pageNumber}:json").ConfigureAwait(false)
				: "";

			if (!string.IsNullOrWhiteSpace(json))
				return JObject.Parse(json);

			// prepare pagination
			var totalRecords = pagination.Item1 > -1
				? pagination.Item1
				: -1;

			if (totalRecords < 0)
				totalRecords = string.IsNullOrWhiteSpace(query)
					? await Profile.CountAsync(filter, $"{cacheKey}total", cancellationToken).ConfigureAwait(false)
					: await Profile.CountByQueryAsync(query, filter, cancellationToken).ConfigureAwait(false);

			var pageSize = pagination.Item3;

			var totalPages = (new Tuple<long, int>(totalRecords, pageSize)).GetTotalPages();
			if (totalPages > 0 && pageNumber > totalPages)
				pageNumber = totalPages;

			// search
			var objects = totalRecords > 0
				? string.IsNullOrWhiteSpace(query)
					? await Profile.FindAsync(filter, sort, pageSize, pageNumber, $"{cacheKey}{pageNumber}", cancellationToken).ConfigureAwait(false)
					: await Profile.SearchAsync(query, filter, pageSize, pageNumber, cancellationToken).ConfigureAwait(false)
				: new List<Profile>();

			// build result
			var profiles = new JArray();
			await objects.ForEachAsync(async (profile, token) =>
			{
				profiles.Add(profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, token).ConfigureAwait(false), !requestInfo.Session.User.IsSystemAdministrator));
			}, cancellationToken, true, false).ConfigureAwait(false);

			pagination = new Tuple<long, int, int, int>(totalRecords, totalPages, pageSize, pageNumber);
			var result = new JObject()
			{
				{ "FilterBy", (filter ?? new FilterBys<Profile>()).ToClientJson(query) },
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
				await Utility.Cache.SetAsync($"{cacheKey }{pageNumber}:json", json, Utility.Cache.ExpirationTime / 2).ConfigureAwait(false);
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
			else if (!await this.IsAuthorizedAsync(requestInfo, Components.Security.Action.View).ConfigureAwait(false))
				throw new AccessDeniedException();

			// fetch
			var request = requestInfo.GetRequestExpando();
			var filter = Filters<Profile>.Or(request.Get("IDs", new List<string>()).Select(id => Filters<Profile>.Equals("ID", id)));
			var objects = await Profile.FindAsync(filter, null, 0, 1, null, cancellationToken);

			// build result
			var profiles = new JArray();
			await objects.ForEachAsync(async (profile, token) =>
			{
				profiles.Add(profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, token).ConfigureAwait(false), !requestInfo.Session.User.IsSystemAdministrator));
			}, cancellationToken, true, false).ConfigureAwait(false);

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
				await Profile.CreateAsync(profile, cancellationToken).ConfigureAwait(false);

				return profile.GetProfileJson(null, false);
			}

			throw new InvalidRequestException();
		}
		#endregion

		#region Get a profile
		Task<JObject> GetProfileRelatedJsonAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
			=> this.CallRelatedServiceAsync(requestInfo, "profile", "GET", requestInfo.Session.User.ID, cancellationToken);

		async Task<JObject> GetProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get information
			var id = requestInfo.GetObjectIdentity() ?? requestInfo.Session.User.ID;
			var profile = await Profile.GetAsync<Profile>(id, cancellationToken).ConfigureAwait(false);
			if (profile == null)
				throw new InformationNotFoundException();

			// check permissions
			var doNormalize = false;
			var gotRights = this.IsAuthenticated(requestInfo) && requestInfo.Session.User.ID.IsEquals(id);
			if (!gotRights)
			{
				gotRights = requestInfo.Session.User.IsSystemAdministrator || await this.IsAuthorizedAsync(requestInfo, Components.Security.Action.View).ConfigureAwait(false);
				doNormalize = !requestInfo.Session.User.IsSystemAdministrator;
			}

			if (!gotRights && requestInfo.Query.ContainsKey("related-service"))
			{
				var systemID = requestInfo.GetQueryParameter("related-system");
				var serviceName = requestInfo.GetQueryParameter("related-service");
				var objectIdentity = requestInfo.GetQueryParameter("related-object-identity");
				var service = await this.GetServiceAsync(serviceName).ConfigureAwait(false);
				gotRights = service != null
					? string.IsNullOrWhiteSpace(systemID)
						? await service.CanManageAsync(requestInfo.Session.User, requestInfo.GetQueryParameter("related-object"), objectIdentity).ConfigureAwait(false)
						: await service.CanManageAsync(requestInfo.Session.User, systemID, requestInfo.GetQueryParameter("related-definition"), objectIdentity).ConfigureAwait(false)
					: false;
				doNormalize = false;
			}

			if (!gotRights)
				throw new AccessDeniedException();

			// response
			return profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, cancellationToken).ConfigureAwait(false), doNormalize);
		}
		#endregion

		#region Update a profile
		async Task<JObject> UpdateProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// check permissions
			var id = requestInfo.GetObjectIdentity() ?? requestInfo.Session.User.ID;
			var gotRights = requestInfo.Session.User.IsSystemAdministrator || (this.IsAuthenticated(requestInfo) && requestInfo.Session.User.ID.IsEquals(id));
			if (!gotRights)
				gotRights = await this.IsAuthorizedAsync(requestInfo, Components.Security.Action.Update).ConfigureAwait(false);
			if (!gotRights)
				throw new AccessDeniedException();

			// get information
			var profile = await Profile.GetAsync<Profile>(id, cancellationToken).ConfigureAwait(false);
			var account = await Account.GetAsync<Account>(id, cancellationToken).ConfigureAwait(false);
			if (profile == null || account == null)
				throw new InformationNotFoundException();

			// prepare
			profile.CopyFrom(requestInfo.GetBodyJson(), "ID,Title,LastUpdated".ToHashSet(), prf =>
			{
				profile.Title = null;
				profile.LastUpdated = DateTime.Now;
				profile.Avatar = string.IsNullOrWhiteSpace(profile.Avatar)
					? string.Empty
					: profile.Avatar.IsStartsWith(Utility.FilesHttpUri)
						? profile.Avatar.Right(profile.Avatar.Length - Utility.FilesHttpUri.Length)
						: profile.Avatar;

				if (account.Type.Equals(AccountType.BuiltIn) && !profile.Email.Equals(account.AccessIdentity))
					profile.Email = account.AccessIdentity;

				if (string.IsNullOrWhiteSpace(profile.Alias))
					profile.Alias = "";
			});

			// update
			await Task.WhenAll(
				Profile.UpdateAsync(profile, requestInfo.Session.User.ID, cancellationToken),
				requestInfo.Query.ContainsKey("related-service") ? this.CallRelatedServiceAsync(requestInfo, "profile", "PUT", profile.ID, cancellationToken) : Task.CompletedTask
			).ConfigureAwait(false);

			// send update message
			var json = profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, cancellationToken), false);
			await this.SendUpdateMessageAsync(new UpdateMessage
			{
				Type = "Users#Profile#Update",
				DeviceID = "*",
				ExcludedDeviceID = requestInfo.Session.DeviceID,
				Data = json
			}, cancellationToken).ConfigureAwait(false);

			// response
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
				code = code.ToBase64(false, true).Decrypt(this.ActivationKey);
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
				return await this.ActivateAccountAsync(requestInfo, info, cancellationToken).ConfigureAwait(false);

			// activate password
			else if (mode.IsEquals("password"))
				return await this.ActivatePasswordAsync(requestInfo, info, cancellationToken).ConfigureAwait(false);

			// unknown
			throw new InvalidRequestException();
		}

		#region Activate new account
		async Task<JObject> ActivateAccountAsync(RequestInfo requestInfo, ExpandoObject info, CancellationToken cancellationToken)
		{
			// prepare
			var mode = info.Get<string>("Mode");
			var id = info.Get<string>("ID");
			var name = info.Get<string>("Name");
			var email = info.Get<string>("Email");
			var privileges = info.Get<List<Privilege>>("Privileges");
			var relatedService = info.Get<string>("RelatedService");
			var relatedUser = info.Get<string>("RelatedUser");
			var relatedInfo = info.Get<ExpandoObject>("RelatedInfo");

			// activate
			if (mode.IsEquals("Status"))
			{
				// check
				var account = await Account.GetAsync<Account>(id, cancellationToken).ConfigureAwait(false);
				if (account == null && !string.IsNullOrWhiteSpace(email))
					account = await Account.GetByIdentityAsync(email, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
				if (account == null)
					throw new InformationNotFoundException();

				// update status
				if (account.Status.Equals(AccountStatus.Registered))
				{
					account.Status = AccountStatus.Activated;
					account.LastAccess = DateTime.Now;
					await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);
				}

				// update related information
				if (!string.IsNullOrWhiteSpace(relatedService) && !string.IsNullOrWhiteSpace(relatedUser))
					try
					{
						// prepare
						var relatedAccount = await Account.GetAsync<Account>(relatedUser, cancellationToken).ConfigureAwait(false);
						var relatedSession = new Services.Session(requestInfo.Session)
						{
							User = relatedAccount.GetAccountJson().FromJson<User>()
						};

						// update privileges
						try
						{
							account.AccessPrivileges = account.AccessPrivileges.Where(p => !p.ServiceName.IsEquals(relatedService))
								.Concat(JArray.Parse(requestInfo.Extra["Privileges"].Decrypt(this.EncryptionKey)).ToList<Privilege>().Where(p => p.ServiceName.IsEquals(relatedService))).ToList();
							await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);
						}
						catch { }

						// update related information
						if (relatedInfo != null)
						{
							var relatedRequest = new RequestInfo(relatedSession, relatedService, "activate", "GET")
							{
								Query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
							{
								{ "object-identity", account.ID }
							},
								CorrelationID = requestInfo.CorrelationID
							};
							relatedInfo.ForEach(kvp => relatedRequest.Extra[kvp.Key] = kvp.Value as string);
							await this.CallServiceAsync(relatedRequest, cancellationToken).ConfigureAwait(false);
						}
					}
					catch { }

				// response
				return account.GetAccountJson();
			}

			// create new account
			else
			{
				// create account
				var account = new Account()
				{
					ID = id,
					Status = AccountStatus.Activated,
					Type = info.Get("Type", "BuiltIn").ToEnum<AccountType>(),
					Joined = info.Get<DateTime>("Time"),
					AccessIdentity = email,
					AccessKey = Account.GeneratePassword(id, info.Get<string>("Password")),
					AccessPrivileges = privileges ?? new List<Privilege>()
				};
				await Account.CreateAsync(account, cancellationToken).ConfigureAwait(false);

				// prepare response
				var json = account.GetAccountJson();

				// create profile
				var profile = new Profile()
				{
					ID = id,
					Name = name,
					Email = email
				};
				await Profile.CreateAsync(profile, cancellationToken).ConfigureAwait(false);

				// update information of related service
				if (!string.IsNullOrWhiteSpace(relatedService) && !string.IsNullOrWhiteSpace(relatedUser) && relatedInfo != null)
					try
					{
						var relatedAccount = await Account.GetAsync<Account>(relatedUser, cancellationToken).ConfigureAwait(false);
						var relatedSession = new Services.Session(requestInfo.Session)
						{
							User = relatedAccount.GetAccountJson().FromJson<User>()
						};
						var relatedRequest = new RequestInfo(relatedSession, relatedService, "activate", "GET")
						{
							Query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
							{
								{ "object-identity", account.ID }
							},
							CorrelationID = requestInfo.CorrelationID
						};
						relatedInfo.ForEach(kvp => relatedRequest.Extra[kvp.Key] = kvp.Value as string);
						await this.CallServiceAsync(relatedRequest, cancellationToken).ConfigureAwait(false);
					}
					catch { }

				// return
				return json;
			}
		}
		#endregion

		#region Activate new password
		async Task<JObject> ActivatePasswordAsync(RequestInfo requestInfo, ExpandoObject info, CancellationToken cancellationToken)
		{
			// prepare
			var id = info.Get<string>("ID");
			var password = info.Get<string>("Password");

			// load account
			var account = await Account.GetAsync<Account>(id, cancellationToken).ConfigureAwait(false);
			if (account == null)
				throw new InvalidActivateInformationException();

			// update new password
			account.AccessKey = Account.GeneratePassword(account.ID, password);
			account.LastAccess = DateTime.Now;
			account.Sessions = null;
			await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);

			// response
			return account.GetAccountJson();
		}
		#endregion

		async Task<JObject> UpdateOnlineStatusAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// update the collection of online session
			try
			{
				this._onlineSessions[requestInfo.Session.SessionID] = requestInfo.Session.User.ID;
			}
			catch { }

			// update last access
			if (!requestInfo.Session.User.IsSystemAccount && !requestInfo.Session.User.ID.Equals(""))
			{
				var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
				if (account != null)
				{
					account.LastAccess = DateTime.Now;
					await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);
				}
			}

			// broadcast & return
			var info = new JObject
			{
				{ "UserID", requestInfo.Session.User.ID },
				{ "SessionID", requestInfo.Session.SessionID },
				{ "DeviceID", requestInfo.Session.DeviceID },
				{ "AppName", requestInfo.Session.AppName },
				{ "AppPlatform", requestInfo.Session.AppPlatform },
				{ "IP", requestInfo.Session.IP },
				{ "IsOnline", true }
			};

			await this.SendUpdateMessageAsync(new UpdateMessage
			{
				Type = "Users#Status",
				DeviceID = "*",
				ExcludedDeviceID = requestInfo.Session.DeviceID,
				Data = info
			}, cancellationToken).ConfigureAwait(false);

			return info;
		}

		#region Process inter-communicate messages
		Dictionary<string, string> _onlineSessions = new Dictionary<string, string>();

		protected override async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message, CancellationToken cancellationToken = default(CancellationToken))
		{
			if (this.IsDebugResultsEnabled)
				this.WriteLogs(UtilityService.NewUUID, $"Got an inter-communicate message {message.ToJson().ToString(this.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}");

			// prepare
			var data = message.Data?.ToExpandoObject();
			if (data == null)
				return;

			var correlationID = UtilityService.NewUUID;

			// online status
			if (message.Type.IsEquals("OnlineStatus"))
				try
				{
					// prepare
					var userID = data.Get<string>("UserID");
					var isOnline = data.Get("IsOnline", false);
					var sessionID = data.Get<string>("SessionID");
					var deviceID = data.Get("DeviceID", "");

					// update the collection of online session
					if (!isOnline)
						this._onlineSessions.Remove(sessionID);

					else
						try
						{
							this._onlineSessions[sessionID] = userID;
						}
						catch { }

					// update & broadcast
					if (!string.IsNullOrWhiteSpace(userID))
					{
						// update database
						var session = await Session.GetAsync<Session>(sessionID, cancellationToken);
						if (session != null && session.Online != isOnline)
						{
							session.Online = isOnline;
							await Session.UpdateAsync(session, true, cancellationToken).ConfigureAwait(false);
						}

						// boardcast messages to clients
						await this.SendUpdateMessageAsync(new UpdateMessage
						{
							Type = "Users#Status",
							DeviceID = "*",
							ExcludedDeviceID = deviceID,
							Data = message.Data
						}, cancellationToken).ConfigureAwait(false);
					}

					if (this.IsDebugResultsEnabled)
						this.WriteLogs(correlationID, $"Update online status successful {message.ToJson().ToString(this.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}");
				}
				catch (Exception ex)
				{
					await this.WriteLogsAsync(correlationID, "Error occurred while updating online status", ex);
				}

			// total of online users
			else if (message.Type.IsEquals("OnlineUsers"))
				await this.SendUpdateMessageAsync(new UpdateMessage
				{
					Type = "Users#Online",
					DeviceID = "*",
					Data = new JValue(this._onlineSessions.Count)
				}, cancellationToken).ConfigureAwait(false);

			// re-update sessions when got new access token
			else if (message.Type.IsEquals("Session"))
			{
				var userID = data.Get<string>("UserID");
				var accessToken = data.Get<string>("AccessToken");
				var account = await Account.GetAsync<Account>(userID, cancellationToken).ConfigureAwait(false);
				if (account != null)
				{
					if (account.Sessions == null)
						await account.GetSessionsAsync().ConfigureAwait(false);

					await account.Sessions.ForEachAsync(async (session, token) =>
					{
						if (session.Online)
						{
							session.AccessToken = accessToken.Decrypt(this.EncryptionKey);
							await Session.UpdateAsync(session, true, token).ConfigureAwait(false);

							await this.SendInterCommunicateMessageAsync("APIGateway", new BaseMessage()
							{
								Type = "Session#Update",
								Data = new JObject()
								{
									{ "Session", session.ID },
									{ "User", account.GetAccountJson() },
									{ "Device", session.DeviceID },
									{ "Verification", session.Verification },
									{ "Token", accessToken }
								}
							}, token).ConfigureAwait(false);
						}
						else
							await Session.DeleteAsync<Session>(session.ID, UtilityService.GetAppSetting("Users:SystemAccountID", "VIEAppsNGX-MMXVII-System-Account"), token).ConfigureAwait(false);
					}, cancellationToken).ConfigureAwait(false);
				}
			}
		}
		#endregion

		JObject RegisterSessionCaptcha(RequestInfo requestInfo)
		{
			if (!requestInfo.Verb.IsEquals("GET"))
				throw new MethodNotAllowedException(requestInfo.Verb);

			var code = CaptchaService.GenerateCode();
			var uri = this.GetHttpURI("Files", "https://afs.vieapps.net")
				+ "/captchas/" + code.Url64Encode() + "/"
				+ (requestInfo.GetQueryParameter("register") ?? UtilityService.NewUUID.Encrypt(this.EncryptionKey, true)).Substring(UtilityService.GetRandomNumber(13, 43), 13).Reverse() + ".jpg";

			return new JObject
			{
				{ "Code", code },
				{ "Uri", uri }
			};
		}

		#region Timers for working with background workers & schedulers
		void RegisterTimers(string[] args = null)
		{
			// timer to request client update state (5 minutes)
			this.StartTimer(async () =>
			{
				await this.SendUpdateMessageAsync(new UpdateMessage()
				{
					Type = "OnlineStatus",
					DeviceID = "*",
				}, this.CancellationTokenSource.Token).ConfigureAwait(false);
#if DEBUG
				await this.WriteLogsAsync(UtilityService.NewUUID, "Send message to request update online status successful").ConfigureAwait(false);
#endif
			}, 5 * 60);

			// timer to clean expired sessions (13 hours)
			this.StartTimer(async () =>
			{
				var userID = UtilityService.GetAppSetting("Users:SystemAccountID", "VIEAppsNGX-MMXVII-System-Account");
				var sessions = await Session.FindAsync(Filters<Session>.LessThan("ExpiredAt", DateTime.Now), null, 0, 1, null, this.CancellationTokenSource.Token).ConfigureAwait(false);
				await sessions.ForEachAsync((session, token) => Session.DeleteAsync<Session>(session.ID, userID, token), this.CancellationTokenSource.Token, true, false).ConfigureAwait(false);
			}, 13 * 60 * 60);

			// timer to refresh visitor sessions (1 hour)
			this.StartTimer(async () =>
			{
				await this.VisitorSessions.Keys.ToList().ForEachAsync(async (id, token) =>
				{
					var key = $"Session#{id}";
					var session = await Utility.Cache.GetAsync(key, token).ConfigureAwait(false);
					if (session != null)
						await Utility.Cache.SetAsync(key, session, 180, token).ConfigureAwait(false);
					else
						this.VisitorSessions.TryRemove(id, out bool state);
				}, this.CancellationTokenSource.Token).ConfigureAwait(false);
			}, 60 * 60);
		}
		#endregion

	}
}