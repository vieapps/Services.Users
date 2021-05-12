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
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Utility;
using net.vieapps.Services;
#endregion

namespace net.vieapps.Services.Users
{
	public class ServiceComponent : ServiceBase
	{

		#region Properties
		ConcurrentDictionary<string, Tuple<DateTime, string>> Sessions { get; } = new ConcurrentDictionary<string, Tuple<DateTime, string>>();

		string ActivationKey => this.GetKey("Activation", "VIEApps-56BA2999-NGX-A2E4-Services-4B54-Activation-83EB-Key-693C250DC95D");

		string AuthenticationKey => this.GetKey("Authentication", "VIEApps-65E47754-NGX-50C0-Services-4565-Authentication-BA55-Key-A8CC23879C5D");

		RSA _rsa = null;

		RSA RSA
		{
			get
			{
				if (this._rsa == null)
				{
					this._rsa = CryptoService.CreateRSA(this.RSAKey);
					if (this._rsa.KeySize != 2048)
					{
						this._rsa = RSA.Create();
						this._rsa.KeySize = 2048;
					}
				}
				return this._rsa;
			}
		}

		HashSet<string> WindowsAD { get; set; }
		#endregion

		public override string ServiceName => "Users";

		public override void Start(string[] args = null, bool initializeRepository = true, Action<IService> next = null)
			=> base.Start(args, initializeRepository, _ =>
			{
				// initialize static properties
				Utility.Cache = new Cache($"VIEApps-Services-{this.ServiceName}", Components.Utility.Logger.GetLoggerFactory());
				Utility.ActivateHttpURI = this.GetHttpURI("Portals", "https://portals.vieapps.net");
				while (Utility.ActivateHttpURI.EndsWith("/"))
					Utility.ActivateHttpURI = Utility.ActivateHttpURI.Left(Utility.FilesHttpURI.Length - 1);
				Utility.ActivateHttpURI += "/home?prego=activate&mode={{mode}}&code={{code}}";
				Utility.FilesHttpURI = this.GetHttpURI("Files", "https://fs.vieapps.net");
				while (Utility.FilesHttpURI.EndsWith("/"))
					Utility.FilesHttpURI = Utility.FilesHttpURI.Left(Utility.FilesHttpURI.Length - 1);

				// register timers
				this.RegisterTimers(args);

				// last action
				next?.Invoke(this);
			});

		public override async Task<JToken> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default)
		{
			var stopwatch = Stopwatch.StartNew();
			await this.WriteLogsAsync(requestInfo, $"Begin request ({requestInfo.Verb} {requestInfo.GetURI()})").ConfigureAwait(false);
			using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, this.CancellationToken))
				try
				{
					JToken json = null;
					switch (requestInfo.ObjectName.ToLower())
					{
						case "session":
							json = await this.ProcessSessionAsync(requestInfo, cts.Token).ConfigureAwait(false);
							break;

						case "otp":
							json = await this.ProcessOTPAsync(requestInfo, cts.Token).ConfigureAwait(false);
							break;

						case "account":
							json = await this.ProcessAccountAsync(requestInfo, cts.Token).ConfigureAwait(false);
							break;

						case "profile":
							json = await this.ProcessProfileAsync(requestInfo, cts.Token).ConfigureAwait(false);
							break;

						case "activate":
							json = await this.ProcessActivationAsync(requestInfo, cts.Token).ConfigureAwait(false);
							break;

						case "privileges":
							json = requestInfo.Verb.IsEquals("GET")
								? await this.GetPrivilegesAsync(requestInfo, cts.Token).ConfigureAwait(false)
								: requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT")
									? await this.SetPrivilegesAsync(requestInfo, cts.Token).ConfigureAwait(false)
									: throw new MethodNotAllowedException(requestInfo.Verb);
							break;

						case "captcha":
							if (!requestInfo.Verb.IsEquals("GET"))
								throw new MethodNotAllowedException(requestInfo.Verb);
							var captcha = CaptchaService.GenerateCode();
							json = new JObject
							{
								{ "Code", captcha },
								{ "Uri", $"{Utility.CaptchaURI}{captcha.Url64Encode()}/{(requestInfo.GetQueryParameter("register") ?? UtilityService.NewUUID.Encrypt(this.EncryptionKey, true)).Substring(UtilityService.GetRandomNumber(13, 43), 13).Reverse()}.jpg" }
							};
							break;

						default:
							throw new InvalidRequestException($"The request is invalid ({requestInfo.Verb} {requestInfo.GetURI()})");
					}
					stopwatch.Stop();
					await this.WriteLogsAsync(requestInfo, $"Success response - Execution times: {stopwatch.GetElapsedTimes()}").ConfigureAwait(false);
					if (this.IsDebugResultsEnabled)
						await this.WriteLogsAsync(requestInfo, $"- Request: {requestInfo.ToString(this.JsonFormat)}" + "\r\n" + $"- Response: {json?.ToString(this.JsonFormat)}").ConfigureAwait(false);
					return json;
				}
				catch (Exception ex)
				{
					throw this.GetRuntimeException(requestInfo, ex, stopwatch);
				}
		}

		#region Call related services
		IService GetRelatedService(RequestInfo requestInfo)
		{
			try
			{
				return Router.GetService(requestInfo?.GetQueryParameter("related-service"));
			}
			catch
			{
				return null;
			}
		}

		async Task<JToken> CallRelatedServiceAsync(RequestInfo requestInfo, User user, string objectName, string verb = "GET", string objectIdentity = null, Dictionary<string, string> extra = null, CancellationToken cancellationToken = default)
		{
			var correlationID = requestInfo.CorrelationID ?? UtilityService.NewUUID;

			var serviceName = requestInfo.GetQueryParameter("related-service") ?? "";
			if (string.IsNullOrWhiteSpace(serviceName))
				return new JObject();

			try
			{
				var request = new RequestInfo(
					new Services.Session(requestInfo.Session)
					{
						User = user ?? requestInfo.Session.User ?? User.GetDefault(requestInfo.Session.SessionID)
					},
					serviceName,
					objectName ?? "",
					verb ?? "GET",
					new Dictionary<string, string>(requestInfo.Query ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
					new Dictionary<string, string>(requestInfo.Header ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
					requestInfo.Body ?? "",
					new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
					correlationID
				);

				if (!string.IsNullOrWhiteSpace(objectIdentity))
					request.Query["object-identity"] = objectIdentity;

				extra?.ForEach(kvp => request.Extra[kvp.Key] = kvp.Value);

				return await this.CallServiceAsync(request, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				if (this.IsDebugLogEnabled)
					await this.WriteLogsAsync(correlationID, $"Error occurred while calling the related service [{serviceName}] => {ex.Message}", ex).ConfigureAwait(false);
				return new JObject();
			}
		}

		Task<JToken> CallRelatedServiceAsync(RequestInfo requestInfo, string objectName, string verb = "GET", string objectIdentity = null, Dictionary<string, string> extra = null, CancellationToken cancellationToken = default)
			=> this.CallRelatedServiceAsync(requestInfo, null, objectName, verb, objectIdentity, extra, cancellationToken);

		Task<JToken> CallRelatedServiceAsync(RequestInfo requestInfo, string objectName, Dictionary<string, string> extra = null, CancellationToken cancellationToken = default)
			=> this.CallRelatedServiceAsync(requestInfo, objectName, null, null, extra, cancellationToken);
		#endregion

		#region Get instructions
		async Task<Tuple<Tuple<string, string>, Tuple<string, string>, Tuple<string, int, bool, string, string>>> GetInstructionsOfRelatedServiceAsync(RequestInfo requestInfo, string mode = "reset", CancellationToken cancellationToken = default)
		{
			var data = await this.CallRelatedServiceAsync(requestInfo, "Instructions", new Dictionary<string, string> { ["mode"] = mode }, cancellationToken).ConfigureAwait(false);

			var message = data.Get("Message", new JObject());
			var subject = message.Get<string>("Subject");
			var body = message.Get<string>("Body");

			var email = data.Get("Email", new JObject());
			var emailSender = email.Get<string>("Sender");
			var emailSignature = email.Get<string>("Signature");

			var smtp = email.Get<JObject>("Smtp", new JObject());
			var smtpServerHost = smtp.Get<string>("Host");
			var smtpServerPort = smtp.Get<int>("Port", 25);
			var smtpServerEnableSsl = smtp.Get<bool>("EnableSsl", false);
			var smtpUser = smtp.Get<string>("User");
			var smtpUserPassword = smtp.Get<string>("UserPassword");

			return new Tuple<Tuple<string, string>, Tuple<string, string>, Tuple<string, int, bool, string, string>>
			(
				new Tuple<string, string>(subject, body),
				new Tuple<string, string>(emailSender, emailSignature),
				new Tuple<string, int, bool, string, string>(smtpServerHost, smtpServerPort, smtpServerEnableSsl, smtpUser, smtpUserPassword)
			);
		}

		async Task<Tuple<Tuple<string, string>, Tuple<string, string>, Tuple<string, int, bool, string, string>>> GetInstructionsAsync(RequestInfo requestInfo, string mode = "reset", CancellationToken cancellationToken = default)
		{
			string subject = "", body = "", emailSender = "", emailSignature = "";
			string smtpServerHost = "", smtpUser = "", smtpUserPassword = "";
			var smtpServerPort = 25;
			var smtpServerEnableSsl = false;

			if (requestInfo.Query.ContainsKey("related-service"))
				try
				{
					var data = await this.GetInstructionsOfRelatedServiceAsync(requestInfo, mode, cancellationToken).ConfigureAwait(false);

					subject = data.Item1.Item1;
					body = data.Item1.Item2;
					emailSender = data.Item2.Item1;
					emailSignature = data.Item2.Item2;
					smtpServerHost = data.Item3.Item1;
					smtpServerPort = data.Item3.Item2;
					smtpServerEnableSsl = data.Item3.Item3;
					smtpUser = data.Item3.Item4;
					smtpUserPassword = data.Item3.Item5;
				}
				catch { }

			if (string.IsNullOrWhiteSpace(subject) || string.IsNullOrWhiteSpace(body))
				try
				{
					var apisURI = this.GetHttpURI("APIs", "https://apis.vieapps.net");
					var json = await UtilityService.FetchWebResourceAsync($"{apisURI}/statics/instructions/users/{requestInfo.GetQueryParameter("language") ?? "vi-VN"}.json", cancellationToken).ConfigureAwait(false);
					var instruction = JObject.Parse(json).Get<JObject>(mode);
					subject = string.IsNullOrWhiteSpace(subject) ? instruction?.Get<string>("subject") : subject;
					body = string.IsNullOrWhiteSpace(body) ? instruction?.Get<string>("body") : body;
				}
				catch (Exception ex)
				{
					await this.WriteLogsAsync(requestInfo, $"Error occurred while fetching instructions => {ex.Message}", ex).ConfigureAwait(false);
				}

			return new Tuple<Tuple<string, string>, Tuple<string, string>, Tuple<string, int, bool, string, string>>
			(
				new Tuple<string, string>(subject, body.NormalizeHTMLBreaks()),
				new Tuple<string, string>(emailSender, emailSignature),
				new Tuple<string, int, bool, string, string>(smtpServerHost, smtpServerPort, smtpServerEnableSsl, smtpUser, smtpUserPassword)
			);
		}
		#endregion

		protected override Privileges Privileges => new Privileges();

		Task<JToken> ProcessSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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

				// log a session in
				case "PUT":
					return this.LogSessionInAsync(requestInfo, cancellationToken);

				// log a session out
				case "DELETE":
					return this.LogSessionOutAsync(requestInfo, cancellationToken);

				// unknown
				default:
					return Task.FromException<JToken>(new MethodNotAllowedException(requestInfo.Verb));
			}
		}

		#region Check exists of a session
		async Task<JToken> CheckSessionExistsAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(requestInfo.Session?.SessionID))
				return new JObject
				{
					{ "ID", requestInfo.Session?.SessionID },
					{ "Existed", false }
				};
			else if (this.Sessions.ContainsKey(requestInfo.Session.SessionID))
				return new JObject
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "Existed", true }
				};

			var session = await Utility.Cache.GetAsync<Session>($"Session#{requestInfo.Session.SessionID}", cancellationToken).ConfigureAwait(false);
			if (session == null && !requestInfo.Session.User.ID.Equals("") && !requestInfo.Session.User.IsSystemAccount)
				session = await Session.GetAsync<Session>(requestInfo.Session.SessionID, cancellationToken).ConfigureAwait(false);

			return new JObject
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "Existed", session != null }
			};
		}
		#endregion

		#region Get a session
		async Task<JToken> GetSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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
		async Task<JToken> RegisterSessionAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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
				var session = Session.CreateInstance(request);
				await Utility.Cache.SetAsync(session, cancellationToken).ConfigureAwait(false);

				// response
				return session.ToJson();
			}

			// register a session of authenticated account
			else
			{
				var session = await Session.GetAsync<Session>(requestInfo.Session.SessionID, cancellationToken, false).ConfigureAwait(false);
				if (session == null)
				{
					session = Session.CreateInstance(request);
					await Session.CreateAsync(session, cancellationToken).ConfigureAwait(false);
				}
				else
				{
					if (!requestInfo.Session.SessionID.IsEquals(request.Get<string>("ID")) || !requestInfo.Session.User.ID.IsEquals(request.Get<string>("UserID")))
						throw new InvalidSessionException();

					await Session.UpdateAsync(session.Fill(request), true, cancellationToken).ConfigureAwait(false);
				}

				// make sure the cache has updated && remove duplicated sessions
				await Task.WhenAll(
					Utility.Cache.SetAsync(session, cancellationToken),
					Session.DeleteManyAsync(Filters<Session>.And(Filters<Session>.Equals("DeviceID", session.DeviceID), Filters<Session>.NotEquals("ID", session.ID)), null, cancellationToken)
				).ConfigureAwait(false);

				// update account information
				var account = await Account.GetAsync<Account>(session.UserID, cancellationToken).ConfigureAwait(false);
				if (account != null)
				{
					account.LastAccess = DateTime.Now;
					await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);
					await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);
				}

				// response
				return session.ToJson();
			}
		}
		#endregion

		#region Log a session in
		async Task<JToken> LogSessionInAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// verify
			if (requestInfo.Extra == null || !requestInfo.Extra.ContainsKey("Signature") || !requestInfo.Extra["Signature"].Equals(requestInfo.Body.GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException("The signature is not found or invalid");

			// prepare
			var request = requestInfo.GetBodyExpando();
			var email = request.Get("Email", "").Decrypt(this.EncryptionKey).Trim().ToLower();
			var password = request.Get("Password", "").Decrypt(this.EncryptionKey);

			if (this.WindowsAD == null)
				this.WindowsAD = UtilityService.GetAppSetting("Users:WindowsAD", "vieapps.net|vieapps.com").ToLower().ToHashSet("|", true);
			var domain = email.Right(email.Length - email.PositionOf("@") - 1).Trim();
			var type = this.WindowsAD.Contains(domain)
				? AccountType.Windows
				: request.Get("Type", "BuiltIn").TryToEnum(out AccountType acctype) ? acctype : AccountType.BuiltIn;

			Account account = null;

			// Windows account
			if (type.Equals(AccountType.Windows))
			{
				var username = email.Left(email.PositionOf("@"));
				username = username.PositionOf(@"\") > 0
					? username.Right(username.Length - username.PositionOf(@"\") - 1).Trim()
					: username.Trim();

				var body = new JObject
				{
					{ "Domain", domain.Encrypt(this.EncryptionKey) },
					{ "Username", username.Encrypt(this.EncryptionKey) },
					{ "Password", password.Encrypt(this.EncryptionKey) }
				}.ToString(Formatting.None);

				await this.CallServiceAsync(new RequestInfo(requestInfo.Session, "WindowsAD", "Account", "POST")
				{
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
							ID = email.GenerateUUID(),
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
				await Utility.Cache.RemoveAsync<Session>(requestInfo.Session.SessionID, cancellationToken).ConfigureAwait(false);

			// response
			return results;
		}
		#endregion

		#region Log a session out
		async Task<JToken> LogSessionOutAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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

		Task<JToken> ProcessOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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
					return Task.FromException<JToken>(new MethodNotAllowedException(requestInfo.Verb));
			}
		}

		#region Validate an OTP
		async Task<JToken> ValidateOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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
			await this.CallServiceAsync(new RequestInfo(requestInfo.Session, "AuthenticatorOTP", "Time-Based-OTP", "GET")
			{
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
				Utility.Cache.SetAsync(account, cancellationToken),
				Utility.Cache.RemoveAsync<Session>(requestInfo.Session.SessionID, cancellationToken)
			).ConfigureAwait(false);

			return account.GetAccountJson();
		}
		#endregion

		#region Get an OTP for provisioning
		async Task<JToken> GetProvisioningOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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
			var json = await this.CallServiceAsync(new RequestInfo(requestInfo.Session, "AuthenticatorOTP", "Time-Based-OTP", "GET")
			{
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
			json["Provisioning"] = new JObject
			{
				{ "Type", type.ToString() },
				{ "Account", account.AccessIdentity },
				{ "ID", account.ID },
				{ "Stamp", stamp }
			}.ToString(Formatting.None).Encrypt(this.AuthenticationKey);
			return json;
		}
		#endregion

		#region Update an OTP
		async Task<JToken> UpdateOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken);
			if (account == null)
				throw new InformationNotFoundException();

			try
			{
				var password = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-password")
					? requestInfo.Extra["x-password"].Decrypt(this.EncryptionKey)
					: null;
				if (string.IsNullOrWhiteSpace(password) || !Account.GeneratePassword(account.ID, password).Equals(account.AccessKey))
					throw new WrongAccountException();
			}
			catch (WrongAccountException)
			{
				throw;
			}
			catch (Exception ex)
			{
				throw new WrongAccountException(ex);
			}

			var body = requestInfo.GetBodyExpando();
			var json = JObject.Parse(body.Get("Provisioning", "").Decrypt(this.AuthenticationKey));
			if (!account.ID.IsEquals(json.Get<string>("ID")) || !account.AccessIdentity.IsEquals(json.Get<string>("Account")))
				throw new InformationInvalidException();

			// validate with OTPs service
			if (!Enum.TryParse(json.Get<string>("Type"), out TwoFactorsAuthenticationType type))
				type = TwoFactorsAuthenticationType.App;
			var stamp = json.Get<string>("Stamp");
			json = await this.CallServiceAsync(new RequestInfo(requestInfo.Session, "AuthenticatorOTP", "Time-Based-OTP", "GET")
			{
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Type", type.ToString() },
					{ "ID", account.ID.Encrypt(this.EncryptionKey) },
					{ "Stamp", stamp.Encrypt(this.EncryptionKey) },
					{ "Password", body.Get("OTP", "").Encrypt(this.EncryptionKey) }
				}
			}, cancellationToken).ConfigureAwait(false) as JObject;

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
			var sessions = account.Sessions.Where(s => !s.ID.Equals(requestInfo.Session.SessionID) && !s.Verified).ToList();
			var messages = sessions.Select(s => new BaseMessage
			{
				Type = "Session#Revoke",
				Data = new JObject
				{
					{ "SessionID", s.ID }
				}
			}).ToList();

			// update current session
			var session = account.Sessions.First(s => s.ID.Equals(requestInfo.Session.SessionID));
			var needUpdate = false;
			if (!session.Verified)
			{
				needUpdate = session.Verified = true;
				messages.Add(new BaseMessage
				{
					Type = "Session#Update",
					Data = new JObject
					{
						{ "SessionID", session.ID },
						{ "User", account.GetAccountJson() },
						{ "Verified", session.Verified }
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
				needUpdate ? Session.UpdateAsync(session, true, cancellationToken) : Task.CompletedTask,
				sessions.Count > 0 ? Session.DeleteManyAsync(Filters<Session>.Or(sessions.Select(s => Filters<Session>.Equals("ID", s.ID))), null, cancellationToken) : Task.CompletedTask,
				sessions.Count > 0 ? sessions.ForEachAsync((s, token) => Utility.Cache.RemoveAsync(s, token), cancellationToken) : Task.CompletedTask,
				messages.Count > 0 ? this.SendInterCommunicateMessagesAsync("APIGateway", messages, cancellationToken) : Task.CompletedTask
			).ConfigureAwait(false);

			// response
			return json;
		}
		#endregion

		#region Delete an OTP
		async Task<JToken> DeleteOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var account = await Account.GetAsync<Account>(requestInfo.Session.User.ID, cancellationToken);
			if (account == null)
				throw new InformationNotFoundException();

			try
			{
				var password = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-password")
					? requestInfo.Extra["x-password"].Decrypt(this.EncryptionKey)
					: null;
				if (string.IsNullOrWhiteSpace(password) || !Account.GeneratePassword(account.ID, password).Equals(account.AccessKey))
					throw new WrongAccountException();
			}
			catch (WrongAccountException)
			{
				throw;
			}
			catch (Exception ex)
			{
				throw new WrongAccountException(ex);
			}

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
				account.Sessions.ForEach(s => s.Verified = false);

			// run all tasks
			await Task.WhenAll(
				Account.UpdateAsync(account, true, cancellationToken),
				account.TwoFactorsAuthentication.Required ? Task.CompletedTask : account.Sessions.ForEachAsync((session, token) => Session.UpdateAsync(session, true, token), cancellationToken),
				account.TwoFactorsAuthentication.Required ? Task.CompletedTask : this.SendInterCommunicateMessagesAsync("APIGateway", account.Sessions.Select(session => new BaseMessage
				{
					Type = "Session#Update",
					Data = new JObject
					{
						{ "SessionID", session.ID },
						{ "Verification", false }
					}
				}).ToList(), cancellationToken)
			).ConfigureAwait(false);

			// response
			return json;
		}
		#endregion

		Task<JToken> ProcessAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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
					return Task.FromException<JToken>(new MethodNotAllowedException(requestInfo.Verb));
			}
		}

		#region Get an account
		async Task<JToken> GetAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// check to see the user in the request is system administrator or not
			if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("IsSystemAdministrator"))
				return new JObject
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
			return account.GetAccountJson(requestInfo.Query.ContainsKey("x-status"), this.AuthenticationKey);
		}
		#endregion

		#region Create/Register an account
		async Task<JToken> CreateAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var requestBody = requestInfo.GetBodyExpando();

			var id = UtilityService.GetUUID();
			var json = new JObject
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
				throw new InformationExistedException($"The email address ({email}) has been used for another account");

			// related: privileges, service, extra info
			var privileges = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Privileges")
				? JArray.Parse(requestInfo.Extra["Privileges"].Decrypt(this.EncryptionKey)).ToList<Privilege>()
				: null;

			var relatedService = requestInfo.GetQueryParameter("related-service");
			var relatedInfo = !string.IsNullOrWhiteSpace(relatedService) && requestInfo.Extra != null && requestInfo.Extra.ContainsKey("RelatedInfo")
				? requestInfo.Extra["RelatedInfo"].Decrypt(this.EncryptionKey).ToExpandoObject()
				: null;

			// permissions of privileges & related info
			if (privileges != null || relatedInfo != null)
			{
				var gotRights = await this.IsSystemAdministratorAsync(requestInfo).ConfigureAwait(false);
				if (!gotRights && !string.IsNullOrWhiteSpace(relatedService))
				{
					var relatedSvc = this.GetRelatedService(requestInfo);
					gotRights = relatedSvc != null && await relatedSvc.CanManageAsync(requestInfo.Session.User, requestInfo.ObjectName, null, null, null, cancellationToken).ConfigureAwait(false);
				}
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
				var account = new Account
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

				await Profile.CreateAsync(profile, cancellationToken).ConfigureAwait(false);
				if (!string.IsNullOrWhiteSpace(relatedService))
					await this.CallRelatedServiceAsync(requestInfo, json.Copy<User>(), "profile", "POST", null, relatedInfo?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value as string), cancellationToken).ConfigureAwait(false);
			}

			// send activation email
			var mode = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-invite")
				? "invite"
				: "account";

			var codeData = new JObject
			{
				{ "ID", id },
				{ "Name", name },
				{ "Email", email },
				{ "Password", password },
				{ "Time", DateTime.Now },
				{ "Mode", isCreateNew ? "Status" : "Create"  }
			};

			if (privileges != null)
				codeData["Privileges"] = privileges.ToJsonArray();

			if (!string.IsNullOrWhiteSpace(relatedService) && relatedInfo != null)
			{
				codeData["RelatedService"] = relatedService;
				codeData["RelatedUser"] = requestInfo.Session.User.ID;
				codeData["RelatedInfo"] = relatedInfo.ToJson();
			}

			var code = codeData.ToString(Formatting.None).Encrypt(this.ActivationKey).ToBase64Url(true);
			var uri = (requestInfo.GetQueryParameter("uri")?.Url64Decode() ?? Utility.ActivateHttpURI).Format(new Dictionary<string, object>
			{
				["mode"] = "account",
				["code"] = code
			});

			// prepare activation email
			var instructions = await this.GetInstructionsAsync(requestInfo, mode, cancellationToken).ConfigureAwait(false);

			var from = instructions.Item2.Item1;
			var to = $"{name} <{email}>";

			var subject = instructions.Item1.Item1;
			if (string.IsNullOrWhiteSpace(subject))
				subject = @"[{{@request.Session(AppName)}}] Activate your account";

			var body = instructions.Item1.Item2;
			if (string.IsNullOrWhiteSpace(body))
				body = @"Hi <b>{{@params(Name)}}</b>
				<br/>
				These are your account information:
				<blockquote>
					Email: <b>{{@params(Email)}}</b>
					Password: <b>{{@params(Password)}}</b>
				</blockquote>
				Please click the link below to activate your account and complete the registration step:
				<br/>
				<span style='display:inline-block;padding:15px;border-radius:5px;background-color:#eee;font-weight:bold'>
					<a href='{{@params(Uri)}}' style='color:red'>Activate your account</a>
				</span>";

			var smtpServerHost = instructions.Item3.Item1;
			var smtpServerPort = instructions.Item3.Item2;
			var smtpServerEnableSsl = instructions.Item3.Item3;
			var smtpServerUsername = instructions.Item3.Item4;
			var smtpServerPassword = instructions.Item3.Item5;

			var requestExpando = requestInfo.ToExpandoObject(requestInfoAsExpandoObject =>
			{
				requestInfoAsExpandoObject.Set("Body", requestInfo.BodyAsExpandoObject);
				requestInfoAsExpandoObject.Get<ExpandoObject>("Header").Remove("x-app-token");
			});

			var inviter = mode.Equals("invite") ? await Profile.GetAsync<Profile>(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false) : null;
			var paramsExpando = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
			{
				{ "Email", email },
				{ "Password", password },
				{ "Name", name },
				{ "Uri", uri },
				{ "Code", code },
				{ "Inviter", new JObject
					{
						{ "Name", inviter?.Name },
						{ "Email", inviter?.Email }
					}
				},
				{ "Time", DateTime.Now },
				{ "Location", await requestInfo.GetLocationAsync().ConfigureAwait(false) },
				{ "EmailSignature", instructions.Item2.Item2 }
			}.ToExpandoObject();

			var parameters = $"{subject}\r\n{body}"
				.GetDoubleBracesTokens()
				.Select(token => token.Item2)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToDictionary(token => token, token =>
				{
					return token.StartsWith("@[") && token.EndsWith("]")
						? Extensions.JsEvaluate(token.GetJsExpression(requestExpando, null, paramsExpando))
						: token.StartsWith("@")
							? token.Evaluate(new Tuple<ExpandoObject, ExpandoObject, ExpandoObject>(requestExpando, null, paramsExpando))
							: token;
				});

			// send an email
			await this.SendEmailAsync(from, to, subject.Format(parameters), body.Format(parameters), smtpServerHost, smtpServerPort, smtpServerEnableSsl, smtpServerUsername, smtpServerPassword, cancellationToken).ConfigureAwait(false);

			// result
			return json;
		}
		#endregion

		#region Get the privilege objects of an account
		async Task<JToken> GetPrivilegesAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var gotRights = requestInfo.Session.User.IsSystemAdministrator;
			var relatedService = gotRights ? null : this.GetRelatedService(requestInfo);
			if (!gotRights && relatedService != null)
			{
				var serviceName = requestInfo.GetQueryParameter("related-service");
				var objectName = requestInfo.GetQueryParameter("related-object");
				var systemID = requestInfo.GetQueryParameter("related-system");
				var definitionID = requestInfo.GetQueryParameter("related-definition");
				var objectID = requestInfo.GetQueryParameter("related-object-identity");
				if (await relatedService.CanManageAsync(requestInfo.Session.User, objectName, systemID, definitionID, objectID, cancellationToken).ConfigureAwait(false))
					return await this.CallServiceAsync(new RequestInfo(requestInfo.Session, serviceName, "Privileges", "GET")
					{
						Header = requestInfo.Header,
						Query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
						{
							{ "x-object-name", objectName },
							{ "x-system-id", systemID },
							{ "x-definition-id", definitionID },
							{ "x-object-id", objectID }
						},
						CorrelationID = requestInfo.CorrelationID
					}, cancellationToken).ConfigureAwait(false);
			}

			return gotRights
				? new JObject()
				: throw new AccessDeniedException();
		}
		#endregion

		#region Update the privileges of an account
		async Task<JToken> SetPrivilegesAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var serviceName = requestInfo.GetQueryParameter("related-service");
			var objectName = requestInfo.GetQueryParameter("related-object");
			var systemID = requestInfo.GetQueryParameter("related-system");
			var entityInfo = requestInfo.GetQueryParameter("related-entity");
			var objectID = requestInfo.GetQueryParameter("related-object-identity");

			// check permission => only system administrator or manager of the specified service can do
			var isSystemAdministrator = requestInfo.Session.User.IsSystemAdministrator;
			var gotRights = isSystemAdministrator;
			var relatedService = gotRights ? null : this.GetRelatedService(requestInfo);
			if (!gotRights && relatedService != null)
				gotRights = await relatedService.CanManageAsync(requestInfo.Session.User, objectName, systemID, entityInfo, objectID, cancellationToken).ConfigureAwait(false);
			if (!gotRights)
				throw new AccessDeniedException();

			// get account
			var account = await Account.GetAsync<Account>(requestInfo.GetObjectIdentity(), cancellationToken).ConfigureAwait(false);
			if (account == null)
				throw new InformationNotFoundException();

			// roles of a system
			if (!string.IsNullOrWhiteSpace(systemID) && requestInfo.Extra != null && (requestInfo.Extra.ContainsKey("Roles") || requestInfo.Extra.ContainsKey("AddedRoles") || requestInfo.Extra.ContainsKey("RemovedRoles")))
				try
				{
					if (!account.AccessRoles.TryGetValue(systemID, out var roles))
						roles = new List<string>();
					if (requestInfo.Extra.ContainsKey("Roles"))
						account.AccessRoles[systemID] = roles.Concat(JArray.Parse(requestInfo.Extra["Roles"].Decrypt(this.EncryptionKey)).ToList<string>()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
					else if (requestInfo.Extra.ContainsKey("AddedRoles"))
						account.AccessRoles[systemID] = roles.Concat(JArray.Parse(requestInfo.Extra["AddedRoles"].Decrypt(this.EncryptionKey)).ToList<string>()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
					else if (requestInfo.Extra.ContainsKey("RemovedRoles"))
						account.AccessRoles[systemID] = roles.Except(JArray.Parse(requestInfo.Extra["RemovedRoles"].Decrypt(this.EncryptionKey)).ToList<string>()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
				}
				catch (Exception ex)
				{
					await this.WriteLogsAsync(requestInfo, $"Error while processing roles of an user account [{account.ID}] => {ex.Message}", ex, LogLevel.Error).ConfigureAwait(false);
				}

			// privileges of a service
			if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Privileges"))
				try
				{
					var allPrivileges = requestInfo.Extra["Privileges"].Decrypt(this.EncryptionKey).ToJson().ToExpandoObject();
					if (isSystemAdministrator)
					{
						(allPrivileges as IDictionary<string, object>).Keys.ForEach(svcName =>
						{
							var svcPrivileges = allPrivileges.Get<List<Privilege>>(svcName).Where(p => p.ServiceName.IsEquals(svcName)).ToList();
							if (svcPrivileges.Count == 1 && svcPrivileges[0].ObjectName.Equals("") && svcPrivileges[0].Role.Equals(PrivilegeRole.Viewer.ToString()))
								svcPrivileges = new List<Privilege>();
							account.AccessPrivileges = account.AccessPrivileges.Where(p => !p.ServiceName.IsEquals(svcName)).Concat(svcPrivileges).ToList();
						});
					}
					else if (!string.IsNullOrWhiteSpace(serviceName))
					{
						var svcPrivileges = allPrivileges.Get<List<Privilege>>(serviceName).Where(p => p.ServiceName.IsEquals(serviceName)).ToList();
						if (svcPrivileges.Count == 1 && svcPrivileges[0].ObjectName.Equals("") && svcPrivileges[0].Role.Equals(PrivilegeRole.Viewer.ToString()))
							svcPrivileges = new List<Privilege>();
						account.AccessPrivileges = account.AccessPrivileges.Where(p => !p.ServiceName.IsEquals(serviceName)).Concat(svcPrivileges).ToList();
					}
					account.AccessPrivileges = account.AccessPrivileges.OrderBy(p => p.ServiceName).ThenBy(p => p.ObjectName).ToList();
				}
				catch (Exception ex)
				{
					await this.WriteLogsAsync(requestInfo, $"Error while processing privileges of an user account [{account.ID}] => {ex.Message}", ex, LogLevel.Error).ConfigureAwait(false);
				}

			// update sessions
			var json = account.GetAccountJson(account.TwoFactorsAuthentication.Required, this.AuthenticationKey);
			var user = json.FromJson<User>();
			if (account.Sessions == null)
				await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);
			account.Sessions.Where(session => session.ExpiredAt > DateTime.Now).ForEach(session =>
			{
				try
				{
					user.SessionID = session.ID;
					session.RenewedAt = DateTime.Now;
					session.ExpiredAt = DateTime.Now.AddDays(60);
					session.AccessToken = user.GetAccessToken(this.ECCKey);
				}
				catch (Exception ex)
				{
					this.WriteLogs(requestInfo, $"Error while preparing session of an user account [{session.ID} @ {user.ID}] => {ex.Message}", ex, LogLevel.Error);
				}
			});

			// update into repository
			await Task.WhenAll(
				Account.UpdateAsync(account, requestInfo.Session.User.ID, cancellationToken),
				Task.WhenAll(account.Sessions.Select(session => Session.UpdateAsync(session, true, cancellationToken)))
			).ConfigureAwait(false);

			// send update messages to API Gateway to update with clients
			await this.SendInterCommunicateMessagesAsync("APIGateway", account.Sessions.Select(session => new BaseMessage
			{
				Type = "Session#Update",
				Data = new JObject
				{
					{ "SessionID", session.ID },
					{ "User", json },
					{ "Verified", session.Verified }
				}
			}).ToList(), cancellationToken).ConfigureAwait(false);
			if (this.IsDebugLogEnabled)
				await this.WriteLogsAsync(requestInfo, $"Successfully send {account.Sessions.Count} message(s) to API Gateway to update new access token of an user account [{account.ID}]").ConfigureAwait(false);

			// response
			return json;
		}
		#endregion

		#region Renew password of an account
		async Task<JToken> ResetPasswordAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account
			var email = requestInfo.Extra["Email"].Decrypt(this.EncryptionKey);
			var account = await Account.GetByIdentityAsync(email, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
			if (account == null)
				return new JObject
				{
					{ "Message", "Please check your email and follow the instruction to activate" }
				};

			// prepare
			var password = Account.GeneratePassword(email);
			var code = new JObject
			{
				{ "ID", account.ID },
				{ "Password", password },
				{ "Time", DateTime.Now }
			}.ToString(Formatting.None).Encrypt(this.ActivationKey).ToBase64Url(true);

			var uri = (requestInfo.Query.ContainsKey("uri") ? requestInfo.Query["uri"].Url64Decode() : Utility.ActivateHttpURI).Format(new Dictionary<string, object>
			{
				["mode"] = "password",
				["code"] = code
			});

			// prepare activation email
			var instructions = await this.GetInstructionsAsync(requestInfo, "reset", cancellationToken).ConfigureAwait(false);

			var from = instructions.Item2.Item1;
			var to = $"{account.Profile.Name} <{account.AccessIdentity}>";

			var subject = instructions.Item1.Item1;
			if (string.IsNullOrWhiteSpace(subject))
				subject = @"[{{@request.Session(AppName)}}] Activate your new password";

			var body = instructions.Item1.Item2;
			if (string.IsNullOrWhiteSpace(body))
				body = @"Hi <b>{{@params(Name)}}</b>
				<br/>
				These are your account information:
				<blockquote>
					Email: <b>{{@params(Email)}}</b>
					Password (new): <b>{{@params(Password)}}</b>
				</blockquote>
				Please click the link below to activate your new password:
				<br/>
				<span style='display:inline-block;padding:15px;border-radius:5px;background-color:#eee;font-weight:bold'>
					<a href='{{@params(Uri)}}' style='color:red'>Activate your new password</a>
				</span>";

			var smtpServerHost = instructions.Item3.Item1;
			var smtpServerPort = instructions.Item3.Item2;
			var smtpServerEnableSsl = instructions.Item3.Item3;
			var smtpServerUsername = instructions.Item3.Item4;
			var smtpServerPassword = instructions.Item3.Item5;

			var requestExpando = requestInfo.ToExpandoObject(requestInfoAsExpandoObject =>
			{
				requestInfoAsExpandoObject.Set("Body", requestInfo.BodyAsExpandoObject);
				requestInfoAsExpandoObject.Get<ExpandoObject>("Header").Remove("x-app-token");
			});

			var paramsExpando = new Dictionary<string, object>
			{
				{ "Email", account.AccessIdentity },
				{ "Password", password },
				{ "Name", account.Profile.Name },
				{ "Uri", uri },
				{ "Code", code },
				{ "Time", DateTime.Now },
				{ "Location", await requestInfo.GetLocationAsync().ConfigureAwait(false) },
				{ "EmailSignature", instructions.Item2.Item2 }
			}.ToExpandoObject();

			var parameters = $"{subject}\r\n{body}"
				.GetDoubleBracesTokens()
				.Select(token => token.Item2)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToDictionary(token => token, token =>
				{
					return token.StartsWith("@[") && token.EndsWith("]")
						? Extensions.JsEvaluate(token.GetJsExpression(requestExpando, null, paramsExpando))
						: token.StartsWith("@")
							? token.Evaluate(new Tuple<ExpandoObject, ExpandoObject, ExpandoObject>(requestExpando, null, paramsExpando))
							: token;
				});

			// send an email
			await this.SendEmailAsync(from, to, subject.Format(parameters), body.Format(parameters), smtpServerHost, smtpServerPort, smtpServerEnableSsl, smtpServerUsername, smtpServerPassword, cancellationToken).ConfigureAwait(false);

			// response
			return new JObject
			{
				{ "Message", "Please check your email and follow the instruction to activate" }
			};
		}
		#endregion

		#region Update password of an account
		async Task<JToken> UpdatePasswordAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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

			// prepare activation email
			var instructions = await this.GetInstructionsAsync(requestInfo, "password", cancellationToken).ConfigureAwait(false);

			var from = instructions.Item2.Item1;
			var to = $"{account.Profile.Name} <{account.AccessIdentity}>";

			var subject = instructions.Item1.Item1;
			if (string.IsNullOrWhiteSpace(subject))
				subject = @"[{{@request.Session(AppName)}}] Your account has been updated";

			var body = instructions.Item1.Item2;
			if (string.IsNullOrWhiteSpace(body))
				body = @"Hi <b>{{@params(Name)}}</b>
				<br/>
				These are your account information:
				<blockquote>
					Email: <b>{{@params(Email)}}</b>
					Password (new): <b>{{@params(Password)}}</b>
				</blockquote>";

			var smtpServerHost = instructions.Item3.Item1;
			var smtpServerPort = instructions.Item3.Item2;
			var smtpServerEnableSsl = instructions.Item3.Item3;
			var smtpServerUsername = instructions.Item3.Item4;
			var smtpServerPassword = instructions.Item3.Item5;

			var requestExpando = requestInfo.ToExpandoObject(requestInfoAsExpandoObject =>
			{
				requestInfoAsExpandoObject.Set("Body", requestInfo.BodyAsExpandoObject);
				requestInfoAsExpandoObject.Get<ExpandoObject>("Header").Remove("x-app-token");
			});

			var paramsExpando = new Dictionary<string, object>
			{
				{ "Email", account.AccessIdentity },
				{ "Password", password },
				{ "Name", account.Profile.Name },
				{ "Time", DateTime.Now },
				{ "Location", await requestInfo.GetLocationAsync().ConfigureAwait(false) },
				{ "EmailSignature", instructions.Item2.Item2 }
			}.ToExpandoObject();

			var parameters = $"{subject}\r\n{body}"
				.GetDoubleBracesTokens()
				.Select(token => token.Item2)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToDictionary(token => token, token =>
				{
					return token.StartsWith("@[") && token.EndsWith("]")
						? Extensions.JsEvaluate(token.GetJsExpression(requestExpando, null, paramsExpando))
						: token.StartsWith("@")
							? token.Evaluate(new Tuple<ExpandoObject, ExpandoObject, ExpandoObject>(requestExpando, null, paramsExpando))
							: token;
				});

			// send an email
			await this.SendEmailAsync(from, to, subject.Format(parameters), body.Format(parameters), smtpServerHost, smtpServerPort, smtpServerEnableSsl, smtpServerUsername, smtpServerPassword, cancellationToken).ConfigureAwait(false);

			// response
			return account.Profile.ToJson();
		}
		#endregion

		#region Update email of an account
		async Task<JToken> UpdateEmailAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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

			// prepare activation email
			var instructions = await this.GetInstructionsAsync(requestInfo, "email", cancellationToken).ConfigureAwait(false);

			var from = instructions.Item2.Item1;
			var to = $"{account.Profile.Name} <{account.AccessIdentity}>";

			var subject = instructions.Item1.Item1;
			if (string.IsNullOrWhiteSpace(subject))
				subject = @"[{{@request.Session(AppName)}}] Your account has been updated";

			var body = instructions.Item1.Item2;
			if (string.IsNullOrWhiteSpace(body))
				body = @"Hi <b>{{@params(Name)}}</b>
				<br/>
				These are your account information:
				<blockquote>
					Your new login  email: <b>{{@params(Email)}}</b>
					Old login email: <b>{{@params(OldEmail)}}</b>
				</blockquote>";

			var smtpServerHost = instructions.Item3.Item1;
			var smtpServerPort = instructions.Item3.Item2;
			var smtpServerEnableSsl = instructions.Item3.Item3;
			var smtpServerUsername = instructions.Item3.Item4;
			var smtpServerPassword = instructions.Item3.Item5;

			var requestExpando = requestInfo.ToExpandoObject(requestInfoAsExpandoObject =>
			{
				requestInfoAsExpandoObject.Set("Body", requestInfo.BodyAsExpandoObject);
				requestInfoAsExpandoObject.Get<ExpandoObject>("Header").Remove("x-app-token");
			});

			var paramsExpando = new Dictionary<string, object>
			{
				{ "Host", requestInfo.GetQueryParameter("host") ?? "unknown" },
				{ "Email", account.AccessIdentity },
				{ "OldEmail", oldEmail },
				{ "Name", account.Profile.Name },
				{ "Time", DateTime.Now },
				{ "Location", await requestInfo.GetLocationAsync().ConfigureAwait(false) },
				{ "EmailSignature", instructions.Item2.Item2 }
			}.ToExpandoObject();

			var parameters = $"{subject}\r\n{body}"
				.GetDoubleBracesTokens()
				.Select(token => token.Item2)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToDictionary(token => token, token =>
				{
					return token.StartsWith("@[") && token.EndsWith("]")
						? Extensions.JsEvaluate(token.GetJsExpression(requestExpando, null, paramsExpando))
						: token.StartsWith("@")
							? token.Evaluate(new Tuple<ExpandoObject, ExpandoObject, ExpandoObject>(requestExpando, null, paramsExpando))
							: token;
				});

			// send an email
			await this.SendEmailAsync(from, to, subject.Format(parameters), body.Format(parameters), smtpServerHost, smtpServerPort, smtpServerEnableSsl, smtpServerUsername, smtpServerPassword, cancellationToken).ConfigureAwait(false);

			// response
			return account.Profile.ToJson();
		}
		#endregion

		#region Get the sessions of an account
		async Task<JToken> GetAccountSessionsAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var userID = requestInfo.GetObjectIdentity() ?? requestInfo.Session.User.ID;
			var account = !userID.Equals("") && !requestInfo.Session.User.IsSystemAccount
				? await Account.GetAsync<Account>(userID, cancellationToken).ConfigureAwait(false)
				: null;

			if (account != null && account.Sessions == null)
				await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);

			return new JObject
			{
				{ "ID", userID },
				{
					"Sessions",
					account != null
						? account.Sessions.ToJArray(session => new JObject
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

		Task<JToken> ProcessProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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
						return this.FetchProfilesAsync(requestInfo, cancellationToken, requestInfo.Extra.TryGetValue("x-notifications-key", out var notificationsKey) && notificationsKey != null ? notificationsKey.IsEquals(this.GetKey("Notifications", null)) : false);

					// get details of a profile
					else
						return this.GetProfileAsync(requestInfo, cancellationToken);

				// update a profile
				case "PUT":
					return this.UpdateProfileAsync(requestInfo, cancellationToken);

				// unknown
				default:
					return Task.FromException<JToken>(new MethodNotAllowedException(requestInfo.Verb));
			}
		}

		#region Search profiles
		async Task<JToken> SearchProfilesAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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
				? this.GetCacheKey(filter, sort)
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
					: await Profile.CountAsync(query, filter, cancellationToken).ConfigureAwait(false);

			var pageSize = pagination.Item3;

			var totalPages = (new Tuple<long, int>(totalRecords, pageSize)).GetTotalPages();
			if (totalPages > 0 && pageNumber > totalPages)
				pageNumber = totalPages;

			// search
			var objects = totalRecords > 0
				? string.IsNullOrWhiteSpace(query)
					? await Profile.FindAsync(filter, sort, pageSize, pageNumber, $"{cacheKey}{pageNumber}", cancellationToken).ConfigureAwait(false)
					: await Profile.SearchAsync(query, filter, null, pageSize, pageNumber, cancellationToken).ConfigureAwait(false)
				: new List<Profile>();

			// build result
			var profiles = new JArray();
			await objects.ForEachAsync(async (profile, token) =>
			{
				profiles.Add(profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, token).ConfigureAwait(false) as JObject, !requestInfo.Session.User.IsSystemAdministrator));
			}, cancellationToken, true, false).ConfigureAwait(false);

			pagination = new Tuple<long, int, int, int>(totalRecords, totalPages, pageSize, pageNumber);
			var result = new JObject
			{
				{ "FilterBy", (filter ?? new FilterBys<Profile>()).ToClientJson(query) },
				{ "SortBy", sort?.ToClientJson() },
				{ "Pagination", pagination?.GetPagination() },
				{ "Objects", profiles }
			};

			// update cache
			if (!cacheKey.Equals(""))
			{
				json = result.ToString(this.JsonFormat);
				await Utility.Cache.SetAsync($"{cacheKey }{pageNumber}:json", json, Utility.Cache.ExpirationTime / 2).ConfigureAwait(false);
			}

			// return the result
			return result;
		}
		#endregion

		#region Fetch profiles
		async Task<JToken> FetchProfilesAsync(RequestInfo requestInfo, CancellationToken cancellationToken, bool isContactRequest = false)
		{
			// check permissions
			if (!isContactRequest)
			{
				if (!this.IsAuthenticated(requestInfo))
					throw new AccessDeniedException();
				else if (!await this.IsAuthorizedAsync(requestInfo, "profile", Components.Security.Action.View, cancellationToken).ConfigureAwait(false))
					throw new AccessDeniedException();
			}

			// fetch
			var filter = Filters<Profile>.Or(requestInfo.GetRequestExpando().Get("IDs", new List<string>()).Select(id => Filters<Profile>.Equals("ID", id)));
			var objects = await Profile.FindAsync(filter, null, 0, 1, null, cancellationToken).ConfigureAwait(false);

			// return as contacts
			if (isContactRequest)
			{
				var sessions = new Dictionary<string, JArray>(StringComparer.OrdinalIgnoreCase);
				await objects.ForEachAsync(async (profile, token) =>
				{
					var account = await Account.GetAsync<Account>(profile.ID, cancellationToken).ConfigureAwait(false);
					if (account != null)
					{
						if (account.Sessions == null)
							await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);
						sessions[account.ID] = account.Sessions.ToJArray(session => new JObject
						{
							{ "SessionID", session.ID },
							{ "DeviceID", session.DeviceID },
							{ "AppInfo", session.AppInfo },
							{ "IsOnline", session.Online }
						});
					}
				}, cancellationToken).ConfigureAwait(false);
				return objects.Select(profile => new JObject
				{
					{ "ID", profile.ID },
					{ "Name", profile.Name },
					{ "Email", profile.Email },
					{ "Sessions", sessions.TryGetValue(profile.ID,  out var session) ? session : null }
				}).ToJArray();
			}

			// return the normalized profiles
			var profiles = new JArray();
			await objects.ForEachAsync(async (profile, token) =>
			{
				profiles.Add(profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, token).ConfigureAwait(false) as JObject, !requestInfo.Session.User.IsSystemAdministrator));
			}, cancellationToken, true, false).ConfigureAwait(false);
			return new JObject
			{
				{ "Objects", profiles }
			};
		}
		#endregion

		#region Get a profile
		Task<JToken> GetProfileRelatedJsonAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
			=> this.CallRelatedServiceAsync(requestInfo, null, "Profile", "GET", requestInfo.Session.User.ID, null, cancellationToken);

		async Task<JToken> GetProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get information
			var id = requestInfo.GetObjectIdentity() ?? requestInfo.Session.User.ID;
			var profile = await Profile.GetAsync<Profile>(id, cancellationToken).ConfigureAwait(false);
			if (profile == null)
				throw new InformationNotFoundException();

			// prepare
			var objectName = requestInfo.GetQueryParameter("related-object");
			var systemID = requestInfo.GetQueryParameter("related-system");
			var definitionID = requestInfo.GetQueryParameter("related-definition");
			var objectID = requestInfo.GetQueryParameter("related-object-identity");

			// check permissions
			var doNormalize = false;
			var gotRights = this.IsAuthenticated(requestInfo) && requestInfo.Session.User.ID.IsEquals(id);
			if (!gotRights)
			{
				gotRights = requestInfo.Session.User.IsSystemAdministrator || await this.IsAuthorizedAsync(requestInfo, "profile", Components.Security.Action.View, cancellationToken).ConfigureAwait(false);
				doNormalize = !requestInfo.Session.User.IsSystemAdministrator;
			}
			var relatedService = gotRights ? null : this.GetRelatedService(requestInfo);
			if (!gotRights && relatedService != null)
			{
				gotRights = await relatedService.CanManageAsync(requestInfo.Session.User, objectName, systemID, definitionID, objectID, cancellationToken).ConfigureAwait(false);
				doNormalize = false;
			}
			if (!gotRights && requestInfo.GetHeaderParameter("x-app") == null)
				throw new AccessDeniedException();

			// response
			var response = profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, cancellationToken).ConfigureAwait(false) as JObject, doNormalize);
			if (requestInfo.GetHeaderParameter("x-app") != null)
				await this.SendUpdateMessageAsync(new UpdateMessage
				{
					Type = $"{this.ServiceName}#Profile",
					Data = response,
					DeviceID = requestInfo.Session.DeviceID
				}, cancellationToken).ConfigureAwait(false);
			return response;
		}
		#endregion

		#region Update a profile
		async Task<JToken> UpdateProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// check permissions
			var id = requestInfo.GetObjectIdentity() ?? requestInfo.Session.User.ID;
			var gotRights = requestInfo.Session.User.IsSystemAdministrator || (this.IsAuthenticated(requestInfo) && requestInfo.Session.User.ID.IsEquals(id));
			if (!gotRights)
				gotRights = await this.IsAuthorizedAsync(requestInfo, "profile", Components.Security.Action.Update, cancellationToken).ConfigureAwait(false);
			if (!gotRights)
				throw new AccessDeniedException();

			// get information
			var profile = await Profile.GetAsync<Profile>(id, cancellationToken).ConfigureAwait(false);
			var account = await Account.GetAsync<Account>(id, cancellationToken).ConfigureAwait(false);
			if (profile == null || account == null)
				throw new InformationNotFoundException();

			// prepare
			var bodyJson = requestInfo.BodyAsJson;
			profile.CopyFrom(bodyJson, "ID,Title,LastUpdated,Options".ToHashSet(), accountprofile =>
			{
				profile.Title = null;
				profile.Options = bodyJson.Get<JObject>("Options")?.ToString(Formatting.None);
				profile.LastUpdated = DateTime.Now;
				profile.Avatar = string.IsNullOrWhiteSpace(profile.Avatar)
					? string.Empty
					: profile.Avatar.IsStartsWith(Utility.AvatarURI)
						? profile.Avatar.Replace(Utility.FilesHttpURI, "~~")
						: profile.Avatar;

				if (account.Type.Equals(AccountType.BuiltIn) && !profile.Email.Equals(account.AccessIdentity))
					profile.Email = account.AccessIdentity;

				if (string.IsNullOrWhiteSpace(profile.Alias))
					profile.Alias = "";
			});

			// update
			await Task.WhenAll(
				Profile.UpdateAsync(profile, requestInfo.Session.User.ID, cancellationToken),
				requestInfo.Query.ContainsKey("related-service")
					? this.CallRelatedServiceAsync(requestInfo, null, "Profile", "PUT", profile.ID, null, cancellationToken)
					: Task.CompletedTask
			).ConfigureAwait(false);

			// send update message
			var json = profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, cancellationToken).ConfigureAwait(false) as JObject, false);
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

		async Task<JToken> ProcessActivationAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
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

			ExpandoObject info;
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
		async Task<JToken> ActivateAccountAsync(RequestInfo requestInfo, ExpandoObject info, CancellationToken cancellationToken)
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
							User = relatedAccount.GetAccountJson().Copy<User>()
						};

						// update privileges
						try
						{
							account.AccessPrivileges = account.AccessPrivileges.Where(p => !p.ServiceName.IsEquals(relatedService))
								.Concat(JArray.Parse(requestInfo.Extra["Privileges"].Decrypt(this.EncryptionKey)).ToList<Privilege>().Where(p => p.ServiceName.IsEquals(relatedService)))
								.ToList();
							await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);
						}
						catch { }

						// update related information
						if (relatedInfo != null)
							await this.CallServiceAsync(new RequestInfo(relatedSession, relatedService, "activate", "GET")
							{
								Query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
								{
									{ "object-identity", account.ID }
								},
								Extra = relatedInfo.ToDictionary(kvp => kvp.Key, kvp => kvp.Value as string),
								CorrelationID = requestInfo.CorrelationID
							}, cancellationToken).ConfigureAwait(false);
					}
					catch { }

				// response
				return account.GetAccountJson();
			}

			// create new account
			else
			{
				// create account
				var account = new Account
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
				var profile = new Profile
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
							User = relatedAccount.GetAccountJson().Copy<User>()
						};
						await this.CallServiceAsync(new RequestInfo(relatedSession, relatedService, "activate", "GET")
						{
							Query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
							{
								{ "object-identity", account.ID }
							},
							Extra = relatedInfo.ToDictionary(kvp => kvp.Key, kvp => kvp.Value as string),
							CorrelationID = requestInfo.CorrelationID
						}, cancellationToken).ConfigureAwait(false);
					}
					catch { }

				// return
				return json;
			}
		}
		#endregion

		#region Activate new password
		async Task<JToken> ActivatePasswordAsync(RequestInfo requestInfo, ExpandoObject info, CancellationToken cancellationToken)
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

		#region Sync
		public override async Task<JToken> SyncAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default)
		{
			var stopwatch = Stopwatch.StartNew();
			this.WriteLogs(requestInfo, $"Start sync ({requestInfo.Verb} {requestInfo.GetURI()})");
			using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, this.CancellationTokenSource.Token))
				try
				{
					// validate
					var json = await base.SyncAsync(requestInfo, cancellationToken).ConfigureAwait(false);

					// sync
					switch (requestInfo.ObjectName.ToLower())
					{
						case "account":
							json = await this.SyncAccountAsync(requestInfo, cts.Token).ConfigureAwait(false);
							break;

						case "profile":
							json = await this.SyncProfileAsync(requestInfo, cts.Token).ConfigureAwait(false);
							break;

						default:
							throw new InvalidRequestException($"The request for synchronizing is invalid ({requestInfo.Verb} {requestInfo.GetURI()})");
					}

					stopwatch.Stop();
					this.WriteLogs(requestInfo, $"Sync success - Execution times: {stopwatch.GetElapsedTimes()}");
					if (this.IsDebugResultsEnabled)
						this.WriteLogs(requestInfo,
							$"- Request: {requestInfo.ToString(this.JsonFormat)}" + "\r\n" +
							$"- Response: {json?.ToString(this.JsonFormat)}"
						);
					return json;
				}
				catch (Exception ex)
				{
					throw this.GetRuntimeException(requestInfo, ex, stopwatch);
				}
		}

		async Task<JToken> SyncAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var data = requestInfo.GetBodyExpando();
			var account = await Account.GetAsync<Account>(data.Get<string>("ID"), cancellationToken).ConfigureAwait(false);
			if (account == null)
			{
				account = Account.CreateInstance(data, null, acc => acc.AccessKey = acc.AccessKey ?? Account.GeneratePassword(acc.ID, Account.GeneratePassword(acc.AccessIdentity)));
				await Account.CreateAsync(account, cancellationToken).ConfigureAwait(false);
			}
			else
			{
				account.Fill(data, null, acc => acc.AccessKey = acc.AccessKey ?? Account.GeneratePassword(acc.ID, Account.GeneratePassword(acc.AccessIdentity)));
				await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);
			}
			return new JObject
			{
				{ "Sync", "Success" },
				{ "ID", account.ID },
				{ "Type", account.GetTypeName(true) }
			};
		}

		async Task<JToken> SyncProfileAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var data = requestInfo.GetBodyExpando();
			var profile = await Profile.GetAsync<Profile>(data.Get<string>("ID"), cancellationToken).ConfigureAwait(false);
			if (profile == null)
			{
				profile = Profile.CreateInstance(data);
				await Profile.CreateAsync(profile, cancellationToken).ConfigureAwait(false);
			}
			else
			{
				profile.Fill(data);
				await Profile.UpdateAsync(profile, true, cancellationToken).ConfigureAwait(false);
			}
			return new JObject
			{
				{ "Sync", "Success" },
				{ "ID", profile.ID },
				{ "Type", profile.GetTypeName(true) }
			};
		}

		protected override Task SendSyncRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default)
		{
			return base.SendSyncRequestAsync(requestInfo, cancellationToken);
		}
		#endregion

		protected override async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message, CancellationToken cancellationToken = default)
		{
			// prepare
			var correlationID = UtilityService.NewUUID;
			var request = message.Data?.ToExpandoObject();
			if (request == null)
				return;

			// state of a session
			if (message.Type.IsEquals("Session#State"))
				try
				{
					var sessionID = request.Get<string>("SessionID");
					var userID = request.Get<string>("UserID");
					var key = $"Session#{sessionID}";
					if (request.Get<bool>("IsOnline"))
					{
						var session = string.IsNullOrWhiteSpace(userID)
							? await Utility.Cache.GetAsync<Session>(key, cancellationToken).ConfigureAwait(false)
							: await Session.GetAsync<Session>(sessionID, cancellationToken).ConfigureAwait(false);
						if (session != null)
						{
							if (this.Sessions.TryGetValue(sessionID, out Tuple<DateTime, string> info))
								this.Sessions.TryUpdate(sessionID, new Tuple<DateTime, string>(DateTime.Now, userID), info);
							else
								this.Sessions.TryAdd(sessionID, new Tuple<DateTime, string>(DateTime.Now, userID));
							if (string.IsNullOrWhiteSpace(userID))
								await Utility.Cache.SetAsync(key, session, 0, cancellationToken).ConfigureAwait(false);
							else if (info == null || (DateTime.Now - info.Item1).TotalMinutes > 14)
							{
								var account = await Account.GetAsync<Account>(userID, cancellationToken).ConfigureAwait(false);
								if (account != null)
								{
									account.LastAccess = DateTime.Now;
									await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);
								}
							}
						}
					}
					else if (this.Sessions.TryRemove(sessionID, out Tuple<DateTime, string> info))
					{
						if (string.IsNullOrWhiteSpace(info.Item2))
							await Utility.Cache.RemoveAsync(key, cancellationToken).ConfigureAwait(false);
						else
						{
							var session = await Session.GetAsync<Session>(sessionID, cancellationToken).ConfigureAwait(false);
							if (session != null)
							{
								session.Online = false;
								await Session.UpdateAsync(session, true, cancellationToken).ConfigureAwait(false);
							}
							var account = string.IsNullOrWhiteSpace(info.Item2) ? null : await Account.GetAsync<Account>(info.Item2, cancellationToken).ConfigureAwait(false);
							if (account != null)
							{
								account.LastAccess = DateTime.Now;
								await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);
							}
						}
					}

					if (this.IsDebugResultsEnabled)
						await this.WriteLogsAsync(correlationID, $"Update online state of a session successful - Online sessions: {this.Sessions.Count:#,##0}", null, this.ServiceName, "Communicates").ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await this.WriteLogsAsync(correlationID, $"Error occurred while updating session state => {ex.Message}", ex, this.ServiceName, "Communicates", LogLevel.Error).ConfigureAwait(false); ;
				}

			// status of sessions
			else if (message.Type.IsEquals("Session#Status"))
			{
				var numberOfVisitorSessions = this.Sessions.Count(kvp => string.IsNullOrWhiteSpace(kvp.Value.Item2));
				new UpdateMessage
				{
					Type = "Users#Session#Status",
					DeviceID = "*",
					Data = new JObject
					{
						{ "TotalSessions", this.Sessions.Count },
						{ "VisitorSessions", numberOfVisitorSessions },
						{ "UserSessions", this.Sessions.Count - numberOfVisitorSessions }
					}
				}.Send();
			}

			// unknown
			else if (this.IsDebugResultsEnabled)
				await this.WriteLogsAsync(correlationID, $"Got an inter-communicate message => {message.ToJson().ToString(this.JsonFormat)})", null, this.ServiceName, "Communicates", LogLevel.Warning).ConfigureAwait(false);
		}

		#region Timers for working with background workers & schedulers
		void RegisterTimers(string[] args = null)
		{
			// clean expired sessions (13 hours)
			this.StartTimer(async () =>
			{
				var userID = UtilityService.GetAppSetting("Users:SystemAccountID", "VIEAppsNGX-MMXVII-System-Account");
				var sessions = await Session.FindAsync(Filters<Session>.LessThan("ExpiredAt", DateTime.Now), null, 0, 1, null, this.CancellationTokenSource.Token).ConfigureAwait(false);
				await sessions.ForEachAsync((session, token) => Session.DeleteAsync<Session>(session.ID, userID, token), this.CancellationTokenSource.Token, true, false).ConfigureAwait(false);
			}, 13 * 60 * 60);

			// refresh sessions (10 minutes)
			this.StartTimer(async () =>
			{
				var userTimepoint = DateTime.Now.AddMinutes(-15);
				var visitorTimepoint = DateTime.Now.AddMinutes(-10);
				await this.Sessions.Select(kvp => new { SessionID = kvp.Key, LastActivity = kvp.Value.Item1, UserID = kvp.Value.Item2 })
					.ToList()
					.ForEachAsync(async (info, token) =>
					{
						// remove offline session
						if (info.LastActivity < (string.IsNullOrWhiteSpace(info.UserID) ? visitorTimepoint : userTimepoint))
							await this.SendInterCommunicateMessageAsync(new CommunicateMessage("Users")
							{
								Type = "Session#State",
								Data = new JObject
								{
									{ "SessionID", info.SessionID },
									{ "UserID", info.UserID },
									{ "IsOnline", false }
								}
							}, token).ConfigureAwait(false);

						// refresh anonymous session
						else if (string.IsNullOrWhiteSpace(info.UserID))
						{
							var key = $"Session#{info.SessionID}";
							var session = await Utility.Cache.GetAsync<Session>(key, token).ConfigureAwait(false);
							if (session != null)
								await Utility.Cache.SetAsync(key, session, 0, token).ConfigureAwait(false);
							else
								this.Sessions.TryRemove(info.SessionID, out Tuple<DateTime, string> sessioninfo);
						}
					}, this.CancellationTokenSource.Token)
					.ConfigureAwait(false);
			}, 10 * 60);
		}
		#endregion

	}
}