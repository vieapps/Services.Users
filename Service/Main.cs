#region Related components
using System;
using System.Linq;
using System.Dynamic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Utility;
using net.vieapps.Services;
using System.Data;
using System.IO;
using WampSharp.V2.Core.Contracts;

#endregion

namespace net.vieapps.Services.Users
{
	public class ServiceComponent : ServiceBase
	{

		#region Properties
		ConcurrentDictionary<string, Tuple<DateTime, string>> Sessions { get; } = new ConcurrentDictionary<string, Tuple<DateTime, string>>();

		string ActivationKey => this.GetKey("Activation", "VIEApps-56BA2999-NGX-A2E4-Services-4B54-Activation-83EB-Key-693C250DC95D");

		string AuthenticationKey => this.GetKey("Authentication", "VIEApps-65E47754-NGX-50C0-Services-4565-Authentication-BA55-Key-A8CC23879C5D");

		HashSet<string> WindowsAD { get; set; } = UtilityService.GetAppSetting("Users:WindowsAD", "vieapps.net|vieapps.com").ToLower().ToHashSet("|", true);

		string PhoneCountryCode { get; } = UtilityService.GetAppSetting("Users:Phone:CountryCode", "84");
		#endregion

		public override string ServiceName => "Users";

		public override void Start(string[] args = null, bool initializeRepository = true, Action<IService> next = null)
			=> base.Start(args, initializeRepository, _ =>
			{
				// initialize static properties
				Utility.Cache = new Cache($"VIEApps-Services-{this.ServiceName}", Components.Utility.Logger.GetLoggerFactory());
				Utility.OAuths = UtilityService.GetAppSetting("Users:OAuths", "").ToList();
				if ("false".IsEquals(UtilityService.GetAppSetting("Users:AllowRegister", "true")))
					Utility.AllowRegister = false;

				Utility.ActivateHttpURI = this.GetHttpURI("Portals", "https://portals.vieapps.net");
				while (Utility.ActivateHttpURI.EndsWith("/"))
					Utility.ActivateHttpURI = Utility.ActivateHttpURI.Left(Utility.FilesHttpURI.Length - 1);
				Utility.ActivateHttpURI += "/home?prego=activate&mode={{mode}}&code={{code}}";
				Utility.FilesHttpURI = this.GetHttpURI("Files", "https://fs.vieapps.net");
				while (Utility.FilesHttpURI.EndsWith("/"))
					Utility.FilesHttpURI = Utility.FilesHttpURI.Left(Utility.FilesHttpURI.Length - 1);
				Utility.CaptchaHttpURI = this.GetHttpURI("Captchas", Utility.FilesHttpURI);
				while (Utility.CaptchaHttpURI.EndsWith("/"))
					Utility.CaptchaHttpURI = Utility.CaptchaHttpURI.Left(Utility.CaptchaHttpURI.Length - 1);
				Utility.CaptchaHttpURI += "/captchas/";
				Utility.AvatarHttpURI = this.GetHttpURI("Avatars", Utility.FilesHttpURI);
				while (Utility.AvatarHttpURI.EndsWith("/"))
					Utility.AvatarHttpURI = Utility.AvatarHttpURI.Left(Utility.AvatarHttpURI.Length - 1);
				Utility.AvatarHttpURI += "/avatars/";

				this.Logger?.LogInformation($"System Administrators: {User.SystemAdministrators.Join(",")}");

				// register timers
				this.RegisterTimers();

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
							json = await this.ProcessOtpAsync(requestInfo, cts.Token).ConfigureAwait(false);
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
								{ "Uri", $"{Utility.CaptchaHttpURI}{captcha.Url64Encode()}/{(requestInfo.GetQueryParameter("register") ?? UtilityService.NewUUID.Encrypt(this.EncryptionKey, true)).Substring(UtilityService.GetRandomNumber(13, 43), 13).Reverse()}.jpg" }
							};
							break;

						case "definitions":
							switch (requestInfo.GetObjectIdentity()?.ToLower())
							{
								case "oauth":
								case "oauths":
									json = Utility.OAuths.ToJArray();
									break;

								case "account":
								case "accounts":
									json = this.GenerateFormControls<Account>();
									break;

								case "profile":
								case "profiles":
									json = this.GenerateFormControls<Profile>();
									break;

								default:
									throw new InvalidRequestException($"The request is invalid [({requestInfo.Verb}): {requestInfo.GetURI()}]");
							}
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
				var request = new RequestInfo
				(
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
				extra?.ForEach(kvp => request.Extra[kvp.Key] = kvp.Value);
				if (!string.IsNullOrWhiteSpace(objectIdentity))
					request.Query["object-identity"] = objectIdentity;

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
			var response = await this.CallRelatedServiceAsync(requestInfo, "Instructions", new Dictionary<string, string> { ["mode"] = mode }, cancellationToken).ConfigureAwait(false);

			var message = response.Get("Message", new JObject());
			var subject = message.Get<string>("Subject");
			var body = message.Get<string>("Body");

			var email = response.Get("Email", new JObject());
			var emailSender = email.Get<string>("Sender");
			var emailSignature = email.Get<string>("Signature");

			var smtp = email.Get("Smtp", new JObject());
			var smtpServerHost = smtp.Get<string>("Host");
			var smtpServerPort = smtp.Get("Port", 25);
			var smtpServerEnableSsl = smtp.Get("EnableSsl", false);
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
					var response = await UtilityService.FetchHttpAsync($"{apisURI}/statics/instructions/users/{requestInfo.GetParameter("language") ?? "vi-VN"}.json", cancellationToken).ConfigureAwait(false);
					var instruction = response.ToJson().Get<JObject>(mode);
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
				? await Utility.Cache.FetchAsync<Session>(requestInfo.Session.SessionID, cancellationToken).ConfigureAwait(false)
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

			var requestBody = requestInfo.GetBodyExpando();
			if (requestBody == null)
				throw new InformationRequiredException();

			// register a session of vistor/system account
			if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount)
			{
				// update cache of session
				var session = Session.CreateInstance(requestBody);
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
					session = Session.CreateInstance(requestBody);
					await Session.CreateAsync(session, cancellationToken).ConfigureAwait(false);
				}
				else
				{
					if (!requestInfo.Session.SessionID.IsEquals(requestBody.Get<string>("ID")) || !requestInfo.Session.User.ID.IsEquals(requestBody.Get<string>("UserID")))
						throw new InvalidSessionException();

					await Session.UpdateAsync(session.Fill(requestBody), true, cancellationToken).ConfigureAwait(false);
				}

				// make sure the cache has updated && remove duplicated sessions
				await Task.WhenAll
				(
					Utility.Cache.SetAsync(session, cancellationToken),
					Session.DeleteManyAsync(Filters<Session>.And(Filters<Session>.Equals("DeviceID", session.DeviceID), Filters<Session>.NotEquals("ID", session.ID)), null, cancellationToken)
				).ConfigureAwait(false);

				// update account information
				var account = await Account.GetByIDAsync(session.UserID, cancellationToken).ConfigureAwait(false);
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
			var requestBody = requestInfo.GetBodyExpando();

			var identity = requestBody.Get("Account", "").Decrypt(this.EncryptionKey).Trim().ToLower();
			if (string.IsNullOrWhiteSpace(identity))
				identity = requestBody.Get("Email", "").Decrypt(this.EncryptionKey).Trim().ToLower();

			var password = requestBody.Get("Password", "").Decrypt(this.EncryptionKey);

			var domain = identity.Right(identity.Length - identity.PositionOf("@") - 1).Trim();
			var type = this.WindowsAD.Contains(domain)
				? AccountType.Windows
				: requestBody.Get("Type", "BuiltIn").TryToEnum(out AccountType acctype) ? acctype : AccountType.BuiltIn;

			Account account = null;

			// Windows AD account
			if (type.Equals(AccountType.Windows))
			{
				var username = identity.Left(identity.PositionOf("@"));
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
					Header = new Dictionary<string, string>(requestInfo.Header ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
					Query = new Dictionary<string, string>(requestInfo.Query ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
					{
						["language"] = requestInfo.GetParameter("language") ?? "en-US"
					},
					Body = body,
					Extra = new Dictionary<string, string>(requestInfo.Query ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
					{
						["Signature"] = body.GetHMACSHA256(this.ValidationKey)
					}
				}, cancellationToken).ConfigureAwait(false);

				// state to create information of account/profile
				var needToCreateAccount = true;
				if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-no-account"))
					needToCreateAccount = false;

				// create information of account/profile
				if (needToCreateAccount)
				{
					account = await Account.GetByAccessIdentityAsync(identity, AccountType.Windows, cancellationToken).ConfigureAwait(false);
					if (account == null)
					{
						account = new Account
						{
							ID = identity.GenerateUUID(),
							Type = AccountType.Windows,
							AccessIdentity = identity
						};
						await Account.CreateAsync(account, cancellationToken).ConfigureAwait(false);

						var profile = new Profile
						{
							ID = account.ID,
							Name = requestBody.Get("Name", username),
							Email = identity
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

			// Built-In account
			else
			{
				account = await Account.GetByAccessIdentityAsync(this.ValidatePhone(identity, out var phone) ? phone : identity, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
				if (account == null || !Account.GeneratePassword(account.ID, password).Equals(account.AccessKey))
					throw new WrongAccountException();
			}

			// prepare response
			var response = account.GetAccountJson();

			// two-factors authentication is required
			if (account.TwoFactorsAuthentication != null && account.TwoFactorsAuthentication.Required)
			{
				response["Require2FA"] = true;
				response["Providers"] = account.TwoFactorsAuthentication.GetProvidersJson(this.AuthenticationKey);
				var provider = account.TwoFactorsAuthentication.Providers.FirstOrDefault();
				if (provider != null && provider.Type.Equals(TwoFactorsAuthenticationType.SMS))
					await this.SendOtpSmsAsync(requestInfo, account, provider.Stamp, true, cancellationToken).ConfigureAwait(false);
			}

			// clear cached of current session when 2FA is not required
			else
				await Utility.Cache.RemoveAsync<Session>(requestInfo.Session.SessionID, cancellationToken).ConfigureAwait(false);

			// response
			return response;
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
			var account = await Account.GetByIDAsync(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
			if (account != null)
			{
				if (account.Sessions == null)
					await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);
				account.Sessions = account.Sessions.Where(session => !session.ID.Equals(requestInfo.Session.SessionID)).ToList();
				account.LastAccess = DateTime.Now;
				await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);
			}

			// response
			return new JObject();
		}
		#endregion

		Task<JToken> ProcessOtpAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			switch (requestInfo.Verb)
			{
				// provision
				case "GET":
					return this.ProvisionOtpAsync(requestInfo, cancellationToken);

				// validate
				case "POST":
					return this.ValidateOtpAsync(requestInfo, cancellationToken);

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

		#region Provision OTP
		async Task<JToken> ProvisionOtpAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var identity = requestInfo.GetParameter("x-sms-otp") ?? requestInfo.Session.User.ID;
			var account = !string.IsNullOrWhiteSpace(identity) && identity.IsValidUUID()
				? await Account.GetByIDAsync(identity, cancellationToken).ConfigureAwait(false)
				: await Account.GetByAccessIdentityAsync(this.ValidatePhone(identity, out var number) ? number : identity, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
			if (account == null)
				throw new InformationNotFoundException();

			var type = TwoFactorsAuthenticationType.App;
			if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("OtpType"))
				try
				{
					type = requestInfo.Extra["OtpType"].Decrypt(this.EncryptionKey).ToEnum<TwoFactorsAuthenticationType>();
				}
				catch { }

			var phone = string.Empty;
			if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("OtpPhone"))
				try
				{
					phone = requestInfo.Extra["OtpPhone"].Decrypt(this.EncryptionKey);
				}
				catch { }

			// send OTP code to a phone number
			if (type.Equals(TwoFactorsAuthenticationType.SMS) && !string.IsNullOrWhiteSpace(phone) && !string.IsNullOrWhiteSpace(requestInfo.GetParameter("x-sms-otp")))
				try
				{
					if (identity.IsEquals(requestInfo.GetParameter("x-sms-account")?.Url64Decode()) && this.ValidatePhone(identity, out phone))
					{
						phone = phone.Encrypt(this.AuthenticationKey, true);
						if (account.TwoFactorsAuthentication.Settings.FirstOrDefault(provider => provider.Type.Equals(type) && provider.Stamp.Equals(phone)) == null)
							throw new InformationInvalidException();
					}
					else
					{
						var data = phone.Decrypt(this.AuthenticationKey, true).ToArray("|");
						if (data.Length != 2 || !data.First().IsEquals($"{type}"))
							throw new InformationInvalidException();
						phone = data.Last();
					}
					return await this.SendOtpSmsAsync(requestInfo, account, phone, true, cancellationToken).ConfigureAwait(false);
				}
				catch (InformationInvalidException)
				{
					throw;
				}
				catch (Exception ex)
				{
					throw new InformationInvalidException(ex);
				}

			// provision
			if (type.Equals(TwoFactorsAuthenticationType.SMS) && !this.ValidatePhone(phone, out phone))
				throw new InformationInvalidException($"The phone number is invalid");

			var stamp = type.Equals(TwoFactorsAuthenticationType.App)
				? $"{UtilityService.NewUUID}#{DateTime.Now.ToIsoString(true)}".GetHMACSHA256(account.ID)
				: phone.Encrypt(this.AuthenticationKey, true);

			var issuer = string.Empty;
			if (requestInfo.Extra != null && requestInfo.Extra.ContainsKey("OtpIssuer"))
				try
				{
					issuer = requestInfo.Extra["OtpIssuer"].Decrypt(this.EncryptionKey);
				}
				catch { }

			var response = type.Equals(TwoFactorsAuthenticationType.SMS)
				? await this.SendOtpSmsAsync(requestInfo, account, phone, false, cancellationToken).ConfigureAwait(false)
				: await this.CallOtpServiceAsync(requestInfo, type, account.ID, stamp, null, cancellationToken, new Dictionary<string, string>
					{
						{ "Account", account.AccessIdentity.Encrypt(this.EncryptionKey) },
						{ "Issuer", issuer.Encrypt(this.EncryptionKey) },
						{ "Setup", type.ToString() }
					}).ConfigureAwait(false);

			// response
			response["Provisioning"] = new JObject
			{
				{ "Type", $"{type}" },
				{ "Account", account.AccessIdentity },
				{ "ID", account.ID },
				{ "Stamp", stamp }
			}.ToString(Formatting.None).Encrypt(this.AuthenticationKey);
			return response;
		}
		#endregion

		#region Validate an OTP
		async Task<JToken> ValidateOtpAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var requestBody = requestInfo.GetBodyExpando();

			var id = requestBody.Get<string>("ID");
			var otp = requestBody.Get<string>("OTP");
			var info = requestBody.Get<string>("Info");
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

			var account = await Account.GetByIDAsync(id, cancellationToken).ConfigureAwait(false);
			if (account == null)
				throw new InformationNotFoundException();

			TwoFactorsAuthenticationType type;
			string stamp;
			try
			{
				var data = info.Decrypt(this.AuthenticationKey, true).ToArray("|");
				if (data.Length != 2)
					throw new InformationInvalidException();
				if (!data.First().TryToEnum(out type))
					type = TwoFactorsAuthenticationType.App;
				stamp = data.Last();
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
			await this.CallOtpServiceAsync(requestInfo, type, account.ID, stamp, otp, cancellationToken).ConfigureAwait(false);

			// response
			await Task.WhenAll
			(
				Utility.Cache.SetAsync(account, cancellationToken),
				Utility.Cache.RemoveAsync<Session>(requestInfo.Session.SessionID, cancellationToken)
			).ConfigureAwait(false);
			return account.GetAccountJson();
		}
		#endregion

		#region Update an OTP
		async Task<JToken> UpdateOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var account = await Account.GetByIDAsync(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
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

			var requestBody = requestInfo.GetBodyExpando();
			var otp = requestBody.Get<string>("OTP");

			try
			{
				requestBody = requestBody.Get<string>("Provisioning").Decrypt(this.AuthenticationKey).ToExpandoObject();
				if (!account.ID.IsEquals(requestBody.Get<string>("ID")) || !account.AccessIdentity.IsEquals(requestBody.Get<string>("Account")))
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

			var stamp = requestBody.Get<string>("Stamp");
			if (!requestBody.Get("Type", "App").TryToEnum(out TwoFactorsAuthenticationType type))
				type = TwoFactorsAuthenticationType.App;

			if (string.IsNullOrWhiteSpace(stamp) || string.IsNullOrWhiteSpace(otp))
				throw new InformationInvalidException();

			// validate
			await this.CallOtpServiceAsync(requestInfo, type, account.ID, stamp, otp, cancellationToken).ConfigureAwait(false);

			// prepare mapping account
			if (type.Equals(TwoFactorsAuthenticationType.SMS))
			{
				var phone = stamp.Decrypt(this.AuthenticationKey, true);
				var mappingAccount = await Account.GetByAccessIdentityAsync(phone, AccountType.BuiltIn, cancellationToken, false).ConfigureAwait(false);
				if (mappingAccount == null)
					await Account.CreateAsync(new Account
					{
						ID = UtilityService.NewUUID,
						Type = AccountType.BuiltIn,
						Status = AccountStatus.Activated,
						AccessIdentity = phone,
						AccessKey = null,
						AccessMapIdentity = account.ID
					}, cancellationToken).ConfigureAwait(false);
				else if (!account.ID.IsEquals(mappingAccount.AccessMapIdentity))
					throw new InformationExistedException($"The phone number ({phone}) has been used for another account");
			}

			// update settings
			var existed = account.TwoFactorsAuthentication.Settings.FirstOrDefault(setting => setting.Type.Equals(type) && setting.Stamp.Equals(stamp));
			if (existed != null)
			{
				existed.Stamp = stamp;
				existed.Time = DateTime.Now.ToUnixTimestamp();
			}
			else
				account.TwoFactorsAuthentication.Settings.Add(new TwoFactorsAuthenticationSetting
				{
					Type = type,
					Stamp = stamp,
					Time = DateTime.Now.ToUnixTimestamp()
				});

			account.TwoFactorsAuthentication.Required = true;
			account.TwoFactorsAuthentication.Settings = account.TwoFactorsAuthentication.Providers;

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

			// response
			await Task.WhenAll
			(
				Account.UpdateAsync(account, true, cancellationToken),
				needUpdate ? Session.UpdateAsync(session, true, cancellationToken) : Task.CompletedTask,
				sessions.Count > 0 ? Session.DeleteManyAsync(Filters<Session>.Or(sessions.Select(s => Filters<Session>.Equals("ID", s.ID))), null, cancellationToken) : Task.CompletedTask,
				sessions.Count > 0 ? sessions.ForEachAsync(s => Utility.Cache.RemoveAsync(s, cancellationToken)) : Task.CompletedTask,
				messages.Count > 0 ? this.SendInterCommunicateMessagesAsync("APIGateway", messages, cancellationToken) : Task.CompletedTask
			).ConfigureAwait(false);
			return account.GetAccountJson(true, this.AuthenticationKey);
		}
		#endregion

		#region Delete an OTP
		async Task<JToken> DeleteOTPAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var account = await Account.GetByIDAsync(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
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

			if (!requestInfo.Query.ContainsKey("Info"))
				throw new InformationInvalidException();

			var info = requestInfo.Query["Info"].Decrypt(this.AuthenticationKey, true).ToArray("|");
			if (info.Length != 2)
				throw new InformationInvalidException();

			var type = info.First().ToEnum<TwoFactorsAuthenticationType>();
			var stamp = info.Last();

			// delete mapping account
			if (type.Equals(TwoFactorsAuthenticationType.SMS))
			{
				var phone = stamp.Decrypt(this.AuthenticationKey, true);
				var mappingAccount = await Account.GetByAccessIdentityAsync(phone, AccountType.BuiltIn, cancellationToken, false).ConfigureAwait(false);
				if (mappingAccount != null && account.ID.IsEquals(mappingAccount.AccessMapIdentity))
					await Account.DeleteAsync<Account>(mappingAccount.ID, account.ID, cancellationToken).ConfigureAwait(false);
			}

			// update settings
			account.TwoFactorsAuthentication.Settings = account.TwoFactorsAuthentication.Providers.Except(account.TwoFactorsAuthentication.Providers.Where(provider => provider.Type.Equals(type) && provider.Stamp.Equals(stamp))).ToList();
			account.TwoFactorsAuthentication.Required = account.TwoFactorsAuthentication.Settings.Any();

			var response = account.GetAccountJson(true, this.AuthenticationKey);
			if (account.Sessions == null)
				await account.GetSessionsAsync(cancellationToken).ConfigureAwait(false);
			if (!account.TwoFactorsAuthentication.Required)
				account.Sessions.ForEach(session => session.Verified = false);

			// response
			await Task.WhenAll
			(
				Account.UpdateAsync(account, true, cancellationToken),
				account.TwoFactorsAuthentication.Required ? Task.CompletedTask : account.Sessions.ForEachAsync(session => Session.UpdateAsync(session, true, cancellationToken)),
				account.TwoFactorsAuthentication.Required ? Task.CompletedTask : this.SendInterCommunicateMessagesAsync("APIGateway", account.Sessions.Select(session => new BaseMessage
				{
					Type = "Session#Update",
					Data = new JObject
					{
						{ "SessionID", session.ID },
						{ "User", response },
						{ "Verified", session.Verified }
					}
				}).ToList(), cancellationToken)
			).ConfigureAwait(false);
			return response;
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
					else if ("renew".IsEquals(identity))
						return this.RenewPasswordAsync(requestInfo, cancellationToken);
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
				throw new AccessDeniedException("Not authenticated");

			// get account information
			var identity = requestInfo.GetObjectIdentity() ?? requestInfo.Session.User.ID;
			var account = !string.IsNullOrWhiteSpace(identity) && identity.IsValidUUID()
				? await Account.GetByIDAsync(identity, cancellationToken).ConfigureAwait(false)
				: await Account.GetByAccessIdentityAsync(this.ValidatePhone(identity, out var phone) ? phone : identity, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
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
			var response = new JObject
			{
				{ "Message", "Please check email and follow the instructions" }
			};

			var name = requestBody.Get<string>("Name");
			var identity = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Account") ? requestInfo.Extra["Account"].Decrypt(this.EncryptionKey).Trim().ToLower() : null;
			if (string.IsNullOrWhiteSpace(identity))
				identity = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Email") ? requestInfo.Extra["Email"].Decrypt(this.EncryptionKey).Trim().ToLower() : null;
			var password = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Password") ? requestInfo.Extra["Password"].Decrypt(this.EncryptionKey) : null;
			if (string.IsNullOrWhiteSpace(password))
				password = Account.GeneratePassword(identity);

			// check existing account
			if (await Account.GetByAccessIdentityAsync(identity, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false) != null)
				throw new InformationExistedException($"The identity ({identity}) has been used for another account");

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
				var gotRights = await this.IsSystemAdministratorAsync(requestInfo, cancellationToken).ConfigureAwait(false);
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
				// not allow
				if (!Utility.AllowRegister)
					return response;

				// create account
				var account = new Account
				{
					ID = id,
					Status = requestBody.Get("Status", "Registered").ToEnum<AccountStatus>(),
					Type = requestBody.Get("Type", "BuiltIn").ToEnum<AccountType>(),
					AccessIdentity = identity,
					AccessKey = password,
					AccessPrivileges = privileges ?? new List<Privilege>()
				};

				await Account.CreateAsync(account, cancellationToken).ConfigureAwait(false);
				response = account.GetAccountJson();

				// create profile
				var profile = requestBody.Copy<Profile>();
				profile.ID = id;
				profile.Name = name;
				profile.Email = identity;

				await Profile.CreateAsync(profile, cancellationToken).ConfigureAwait(false);
				if (!string.IsNullOrWhiteSpace(relatedService))
					await this.CallRelatedServiceAsync(requestInfo, response.Copy<User>(), "Profile", "POST", null, relatedInfo?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value as string), cancellationToken).ConfigureAwait(false);
			}

			// send activation email
			var mode = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("x-invite")
				? "invite"
				: "account";

			var codeData = new JObject
			{
				{ "ID", id },
				{ "Name", name },
				{ "Email", identity },
				{ "Account", identity },
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
			var to = $"{name} <{identity}>";

			var subject = instructions.Item1.Item1;
			if (string.IsNullOrWhiteSpace(subject))
				subject = @"[{{@request.Session(AppName)}}] Activate your account";

			var body = instructions.Item1.Item2;
			if (string.IsNullOrWhiteSpace(body))
				body = @"Hi <b>{{@params(Name)}}</b>
				<br/>
				These are your account information:
				<blockquote>
					Account: <b>{{@params(Account)}}</b>
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

			var inviter = mode.Equals("invite") ? await Profile.GetAsync<Profile>(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false) : null;
			var @params = new JObject
			{
				{ "Account", identity },
				{ "Password", password },
				{ "Email", identity },
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
				{ "Location", await requestInfo.GetLocationAsync(cancellationToken).ConfigureAwait(false) },
				{ "EmailSignature", instructions.Item2.Item2 }
			}.ToExpandoObject();
			var parameters = $"{subject}\r\n{body}".PrepareDoubleBracesParameters(null, requestInfo.AsExpandoObject, @params);

			// send an email
			await this.SendEmailAsync(from, to, subject.Format(parameters), body.Format(parameters), smtpServerHost, smtpServerPort, smtpServerEnableSsl, smtpServerUsername, smtpServerPassword, cancellationToken).ConfigureAwait(false);

			// response
			return response;
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
			var account = await Account.GetByIDAsync(requestInfo.GetObjectIdentity(), cancellationToken).ConfigureAwait(false);
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
			var response = account.GetAccountJson(account.TwoFactorsAuthentication.Required, this.AuthenticationKey);
			var user = response.FromJson<User>();
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
			await Task.WhenAll
			(
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
					{ "User", response },
					{ "Verified", session.Verified }
				}
			}).ToList(), cancellationToken).ConfigureAwait(false);
			if (this.IsDebugLogEnabled)
				await this.WriteLogsAsync(requestInfo, $"Successfully send {account.Sessions.Count} message(s) to API Gateway to update new access token of an user account [{account.ID}]").ConfigureAwait(false);

			// response
			return response;
		}
		#endregion

		#region Reset password of an account
		async Task<JToken> ResetPasswordAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account
			var identity = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Account") ? requestInfo.Extra["Account"].Decrypt(this.EncryptionKey) : null;
			if (string.IsNullOrWhiteSpace(identity))
				identity = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Email") ? requestInfo.Extra["Email"].Decrypt(this.EncryptionKey) : null;

			var account = await Account.GetByAccessIdentityAsync(identity, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
			if (account == null)
				return new JObject
				{
					{ "Message", "Please check your email and follow the instruction to activate" }
				};

			// prepare
			var password = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Password") ? requestInfo.Extra["Password"].Decrypt(this.EncryptionKey) : null;
			if (string.IsNullOrWhiteSpace(password))
				password = Account.GeneratePassword(identity);

			var code = new JObject
			{
				{ "ID", account.ID },
				{ "Password", password },
				{ "Time", DateTime.Now }
			}.ToString(Formatting.None).Encrypt(this.ActivationKey).ToBase64Url(true);

			var uri = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Uri") ? requestInfo.Extra["Uri"].Decrypt(this.EncryptionKey) : null;
			if (string.IsNullOrWhiteSpace(uri))
				uri = requestInfo.Query.ContainsKey("uri") ? requestInfo.Query["uri"].Url64Decode() : Utility.ActivateHttpURI;

			uri = uri.Format(new Dictionary<string, object>
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
				<br/><br/>
				These are your account information:
				<blockquote>
					Account: <b>{{@params(Account)}}</b>
					<br/>
					Password (new): <b>{{@params(Password)}}</b>
				</blockquote>
				Please click the link below to activate your new password:
				<br/><br/>
				<span style='display:inline-block;padding:15px;border-radius:5px;background-color:#eee;font-weight:bold'>
					<a href='{{@params(Uri)}}' style='color:red'>Activate your new password</a>
				</span>";

			var smtpServerHost = instructions.Item3.Item1;
			var smtpServerPort = instructions.Item3.Item2;
			var smtpServerEnableSsl = instructions.Item3.Item3;
			var smtpServerUsername = instructions.Item3.Item4;
			var smtpServerPassword = instructions.Item3.Item5;

			var @params = new JObject
			{
				{ "Account", account.AccessIdentity },
				{ "Password", password },
				{ "Email", account.AccessIdentity },
				{ "Name", account.Profile.Name },
				{ "Uri", uri },
				{ "Code", code },
				{ "Time", DateTime.Now },
				{ "Location", await requestInfo.GetLocationAsync(cancellationToken).ConfigureAwait(false) },
				{ "EmailSignature", instructions.Item2.Item2 }
			}.ToExpandoObject();
			var parameters = $"{subject}\r\n{body}".PrepareDoubleBracesParameters(null, requestInfo.AsExpandoObject, @params);

			// send an email
			await this.SendEmailAsync(from, to, subject.Format(parameters), body.Format(parameters), smtpServerHost, smtpServerPort, smtpServerEnableSsl, smtpServerUsername, smtpServerPassword, cancellationToken).ConfigureAwait(false);

			// response
			return new JObject
			{
				{ "Message", "Please check your email and follow the instruction to activate" }
			};
		}
		#endregion

		#region Renew password of an account (SMS)
		async Task<JToken> RenewPasswordAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (this.ValidatePhone(requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Account") ? requestInfo.Extra["Account"].Decrypt(this.EncryptionKey) : null, out var phone))
			{
				// prepare
				var account = await Account.GetByAccessIdentityAsync(phone, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
				if (account == null)
					throw new InformationNotFoundException();

				var otp = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("OtpCode") ? requestInfo.Extra["OtpCode"].Decrypt(this.EncryptionKey) : null;
				if (string.IsNullOrWhiteSpace(otp))
					throw new InformationInvalidException();

				var stamp = phone.Encrypt(this.AuthenticationKey, true);
				if (account.TwoFactorsAuthentication.Settings.FirstOrDefault(provider => provider.Type.Equals(TwoFactorsAuthenticationType.SMS) && provider.Stamp.Equals(stamp)) == null)
					throw new InformationInvalidException();

				// validate
				await this.CallOtpServiceAsync(requestInfo, TwoFactorsAuthenticationType.SMS, account.ID, stamp, otp, cancellationToken).ConfigureAwait(false);

				// update
				var password = requestInfo.Extra != null && requestInfo.Extra.ContainsKey("Password") ? requestInfo.Extra["Password"].Decrypt(this.EncryptionKey) : null;
				if (string.IsNullOrWhiteSpace(password))
					password = Account.GeneratePassword(phone);

				account.AccessKey = Account.GeneratePassword(account.ID, password);
				account.LastAccess = DateTime.Now;
				account.Sessions = null;
				await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);

				// send SMS
				var message = requestInfo.GetParameter("x-sms-renew-password-template") ?? UtilityService.GetAppSetting("Users:SMS:RenewPassword");
				if (string.IsNullOrWhiteSpace(message))
					message = "vi-VN".IsEquals(requestInfo.GetParameter("language") ?? "en-US")
						? "Sử dụng mật khẩu {{Password}} để đăng nhập trên app {{AppName}}"
						: "Use the password {{Password}} to login on {{AppName}} app";

				await this.SendSmsAsync(requestInfo, phone, message, new Dictionary<string, string>
				{
					["Password"] = password,
					["Code"] = password,
					["Phone"] = phone,
					["PhoneNumber"] = phone,
					["Name"] = account.Profile?.Name,
					["Email"] = account.Profile?.Email,
					["Account"] = account.AccessIdentity,
					["AccountID"] = account.ID
				}, cancellationToken).ConfigureAwait(false);

				// send email
				await this.SendUpdatePasswordEmailAsync(requestInfo, account, password, cancellationToken).ConfigureAwait(false);
			}

			return new JObject
			{
				{ "Status", "Sent" }
			};
		}
		#endregion

		#region Update password of an account
		async Task<JToken> UpdatePasswordAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account and check
			var oldPassword = requestInfo.Extra["OldPassword"].Decrypt(this.EncryptionKey);
			var account = await Account.GetByIDAsync(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
			if (account == null || !Account.GeneratePassword(account.ID, oldPassword).Equals(account.AccessKey))
				throw new WrongAccountException();

			// update
			var password = requestInfo.Extra["Password"].Decrypt(this.EncryptionKey);
			account.AccessKey = Account.GeneratePassword(account.ID, password);
			account.LastAccess = DateTime.Now;
			await Account.UpdateAsync(account, true, cancellationToken);

			// send an email
			await this.SendUpdatePasswordEmailAsync(requestInfo, account, password, cancellationToken).ConfigureAwait(false);

			// response
			return account.Profile?.ToJson() ?? new JObject();
		}

		async Task SendUpdatePasswordEmailAsync(RequestInfo requestInfo, Account account, string password, CancellationToken cancellationToken)
		{
			if (!this.ValidateEmail(account.AccessIdentity, out var email))
			{
				if (!this.ValidateEmail(account.Profile?.Email, out email))
					return;
			}

			var instructions = await this.GetInstructionsAsync(requestInfo, "password", cancellationToken).ConfigureAwait(false);

			var from = instructions.Item2.Item1;
			var to = $"{account.Profile?.Name ?? email} <{email}>";

			var subject = instructions.Item1.Item1;
			if (string.IsNullOrWhiteSpace(subject))
				subject = @"[{{@request.Session(AppName)}}] Your account has been updated";

			var body = instructions.Item1.Item2;
			if (string.IsNullOrWhiteSpace(body))
				body = @"Hi <b>{{@params(Name)}}</b>
				<br/>
				These are your account information:
				<blockquote>
					Account: <b>{{@params(Account)}}</b>
					Password (new): <b>{{@params(Password)}}</b>
				</blockquote>";

			var smtpServerHost = instructions.Item3.Item1;
			var smtpServerPort = instructions.Item3.Item2;
			var smtpServerEnableSsl = instructions.Item3.Item3;
			var smtpServerUsername = instructions.Item3.Item4;
			var smtpServerPassword = instructions.Item3.Item5;

			var @params = new JObject
			{
				{ "Account", account.AccessIdentity },
				{ "Password", password },
				{ "Email", email },
				{ "Name", account.Profile?.Name },
				{ "Time", DateTime.Now },
				{ "Location", await requestInfo.GetLocationAsync(cancellationToken).ConfigureAwait(false) },
				{ "EmailSignature", instructions.Item2.Item2 }
			}.ToExpandoObject();
			var parameters = $"{subject}\r\n{body}".PrepareDoubleBracesParameters(null, requestInfo.AsExpandoObject, @params);

			await this.SendEmailAsync(from, to, subject.Format(parameters), body.Format(parameters), smtpServerHost, smtpServerPort, smtpServerEnableSsl, smtpServerUsername, smtpServerPassword, cancellationToken).ConfigureAwait(false);
		}
		#endregion

		#region Update email of an account
		async Task<JToken> UpdateEmailAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// get account and check
			var oldPassword = requestInfo.Extra["OldPassword"].Decrypt(this.EncryptionKey);
			var account = await Account.GetByIDAsync(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);
			if (account == null || !Account.GeneratePassword(account.ID, oldPassword).Equals(account.AccessKey))
				throw new WrongAccountException();

			// check existing
			var email = requestInfo.Extra["Email"].Decrypt(this.EncryptionKey);
			if (!this.ValidateEmail(email, out email))
				throw new InformationInvalidException("The email address is invalid");

			var otherAccount = await Account.GetByAccessIdentityAsync(email, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
			if (otherAccount != null && !otherAccount.ID.Equals(account.ID))
				throw new InformationExistedException($"The email '{email}' is used by other account");

			// update
			var oldEmail = account.AccessIdentity;
			account.AccessIdentity = email;
			account.LastAccess = DateTime.Now;

			account.Profile.Email = email;
			account.Profile.LastUpdated = DateTime.Now;

			await Task.WhenAll
			(
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

			var @params = new JObject
			{
				{ "Host", requestInfo.GetQueryParameter("host") ?? "unknown" },
				{ "Email", account.AccessIdentity },
				{ "OldEmail", oldEmail },
				{ "Name", account.Profile.Name },
				{ "Time", DateTime.Now },
				{ "Location", await requestInfo.GetLocationAsync(cancellationToken).ConfigureAwait(false) },
				{ "EmailSignature", instructions.Item2.Item2 }
			}.ToExpandoObject();
			var parameters = $"{subject}\r\n{body}".PrepareDoubleBracesParameters(null, requestInfo.AsExpandoObject, @params);

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
				? await Account.GetByIDAsync(userID, cancellationToken).ConfigureAwait(false)
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
						return this.FetchProfilesAsync(requestInfo, cancellationToken, requestInfo.Extra.TryGetValue("x-notifications-key", out var notificationsKey) && notificationsKey != null && notificationsKey.IsEquals(this.GetKey("Notifications", null)));

					// export
					else if ("export".IsEquals(identity))
						return this.ExportProfilesAsync(requestInfo, cancellationToken);

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
				? await Utility.Cache.GetAsync<string>($"{cacheKey}{pageNumber}:json", cancellationToken).ConfigureAwait(false)
				: "";

			if (!string.IsNullOrWhiteSpace(json))
				return JObject.Parse(json);

			// prepare pagination
			var totalRecords = pagination.Item1 > -1
				? pagination.Item1
				: -1;

			if (totalRecords < 0)
				totalRecords = string.IsNullOrWhiteSpace(query)
					? await Profile.CountAsync(filter, $"{cacheKey}:total", cancellationToken).ConfigureAwait(false)
					: await Profile.CountAsync(query, filter, cancellationToken).ConfigureAwait(false);

			var pageSize = pagination.Item3;

			var totalPages = new Tuple<long, int>(totalRecords, pageSize).GetTotalPages();
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
			await objects.ForEachAsync(async profile =>
			{
				profiles.Add(profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, cancellationToken).ConfigureAwait(false) as JObject));
			}, true, false).ConfigureAwait(false);

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
				await Utility.Cache.SetAsync($"{cacheKey}{pageNumber}:json", json, Utility.Cache.ExpirationTime / 2, cancellationToken).ConfigureAwait(false);
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
				await objects.ForEachAsync(async profile =>
				{
					var account = await Account.GetByIDAsync(profile.ID, cancellationToken).ConfigureAwait(false);
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
				}).ConfigureAwait(false);
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
			await objects.ForEachAsync(async profile =>
			{
				profiles.Add(profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, cancellationToken).ConfigureAwait(false) as JObject));
			}, true, false).ConfigureAwait(false);
			return new JObject
			{
				{ "Objects", profiles }
			};
		}
		#endregion

		#region Export profiles to Excel
		async Task<JToken> ExportProfilesAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (!await this.IsSystemAdministratorAsync(requestInfo, cancellationToken).ConfigureAwait(false))
				throw new AccessDeniedException();

			var processID = requestInfo.CorrelationID ?? UtilityService.NewUUID;
			var deviceID = requestInfo.Session.DeviceID;
			var requestJson = requestInfo.GetRequestJson();
			var filterBy = requestJson.Get<JObject>("FilterBy");
			var sortBy = requestJson.Get<JObject>("SortBy");
			var pagination = requestJson.Get("Pagination", new JObject());
			var pageSize = pagination.Get("PageSize", 100);
			var pageNumber = pagination.Get("PageNumber", 1);
			var maxPages = pagination.Get("MaxPages", 0);

			this.ExportProfiles(processID, deviceID, filterBy?.ToFilterBy<Profile>(), sortBy?.ToSortBy<Profile>() ?? Sorts<Profile>.Ascending("Name"), pageSize, pageNumber, maxPages);
			return new JObject();
		}

		void ExportProfiles(string processID, string deviceID, IFilterBy<Profile> filter, SortBy<Profile> sort, int pageSize, int pageNumber, int maxPages, int totalPages = 0)
			=> Task.Run(async () =>
			{
				try
				{
					var stopwatch = Stopwatch.StartNew();
					if (this.IsDebugLogEnabled)
						await this.WriteLogsAsync(processID, $"Start to export data to Excel - Filter: {filter?.ToJson().ToString(Formatting.None) ?? "N/A"} - Sort: {sort?.ToJson().ToString(Formatting.None) ?? "N/A"}", null, this.ServiceName, "Excel").ConfigureAwait(false);

					long totalRecords = 0;
					if (totalPages < 1)
					{
						totalRecords = await Profile.CountAsync(filter, null, false, null, 0, this.CancellationToken).ConfigureAwait(false);
						totalPages = totalRecords < 1 ? 0 : new Tuple<long, int>(totalRecords, pageSize).GetTotalPages();
					}

					var dataSet = totalPages < 1
						? ExcelService.ToDataSet<Profile>(null)
						: null;

					var exceptions = new List<Exception>();
					while (pageNumber <= totalPages && (maxPages == 0 || pageNumber <= maxPages))
					{
						new UpdateMessage
						{
							Type = "Users#Profile#Export",
							DeviceID = deviceID,
							Data = new JObject
							{
								{ "ProcessID", processID },
								{ "Status", "Processing" },
								{ "Percentage", $"{pageNumber * 100/totalPages:#0.0}%" }
							}
						}.Send();

						try
						{
							var objects = pageNumber <= totalPages && (maxPages == 0 || pageNumber <= maxPages)
								? await RepositoryMediator.FindAsync(null, filter, sort, pageSize, pageNumber, null, false, null, 0, this.CancellationToken).ConfigureAwait(false)
								: new List<Profile>();
							if (pageNumber < 2)
								dataSet = objects.ToDataSet(null, dataset => this.NormalizeProfiles(dataset.Tables[0].Rows));
							else
								dataSet.Tables[0].UpdateDataTable(objects, null, dataTable => this.NormalizeProfiles(dataTable.Rows));
						}
						catch (Exception ex)
						{
							exceptions.Add(new RepositoryOperationException($"Error occurred while preparing objects to export to Excel => {ex.GetTypeName(true)}: {ex.Message}", ex));
							await this.WriteLogsAsync(processID, $"Error occurred while preparing objects to export to Excel => {ex.GetTypeName(true)}: {ex.Message}", ex, this.ServiceName, "Excel").ConfigureAwait(false);
						}
						pageNumber++;
					}

					var filename = $"{processID}-profiles.xlsx";
					if (dataSet != null)
					{
						using (var stream = dataSet.SaveAsExcel())
							await stream.SaveAsBinaryAsync(Path.Combine(this.GetPath("Temp", Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data-files", "temp")), filename), this.CancellationToken).ConfigureAwait(false);
					}

					new UpdateMessage
					{
						Type = "Users#Profile#Export",
						DeviceID = deviceID,
						Data = new JObject
						{
							{ "ProcessID", processID },
							{ "Status", "Done" },
							{ "Percentage", "100%" },
							{ "Filename", filename },
							{ "NodeID", $"{this.ServiceName.Trim().ToLower()}.{this.NodeID}" },
							{
								"Exceptions",
								exceptions.Select(exception => new JObject
								{
									{ "Type", exception.GetType().ToString() },
									{ "Message", exception.Message },
									{ "Stack", exception.StackTrace }
								}).ToJArray()
							}
						}
					}.Send();

					stopwatch.Stop();
					if (this.IsDebugLogEnabled)
						await this.WriteLogsAsync(processID, $"Export objects to Excel was completed - Total: {totalRecords:###,###,##0} - Execution times: {stopwatch.GetElapsedTimes()}", null, this.ServiceName, "Excel").ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					var code = 500;
					var type = ex.GetTypeName(true);
					var message = ex.Message;
					var stack = ex.StackTrace;
					if (ex is WampException wampException)
					{
						var wampDetails = wampException.GetDetails();
						code = wampDetails.Item1;
						type = wampDetails.Item2;
						message = wampDetails.Item3;
						stack = wampDetails.Item4;
					}
					new UpdateMessage
					{
						Type = "Users#Profile#Export",
						DeviceID = deviceID,
						Data = new JObject
						{
							{ "ProcessID", processID },
							{ "Status", "Error" },
							{
								"Error", new JObject
								{
									{ "Code", code },
									{ "Type", type },
									{ "Message", message },
									{ "Stack", stack }
								}
							}
						}
					}.Send();
					await this.WriteLogsAsync(processID, $"Error occurred while exporting objects to Excel => {message}", ex, this.ServiceName, "Excel").ConfigureAwait(false);
				}
			}, this.CancellationToken).ConfigureAwait(false);

		void NormalizeProfiles(DataRowCollection rows)
		{
			foreach (DataRow row in rows)
				try
				{
					var email = row["Email"].ToString().ToLower();
					var name = row["Name"].ToString();
					name = string.IsNullOrWhiteSpace(name) || (name[0] >= '0' && name[0] <= '9') ? email : name;
					name = name.IndexOf("@") > 0 ? name.Left(name.IndexOf("@")) : name;
					var mobile = row["Mobile"]?.ToString()?.Replace(" ", "").Replace(".", "").Replace("-", "").Replace("(", "").Replace(")", "");
					mobile = string.IsNullOrWhiteSpace(mobile)
						? null
						: (mobile.StartsWith("+") || mobile.StartsWith("0") ? "" : mobile.StartsWith("84") ? "+" : "") + mobile;
					row["Name"] = name.IndexOf(".") > 0 ? name.GetCapitalizedFirstLetter() : name.GetCapitalizedWords();
					row["Email"] = email;
					row["Mobile"] = mobile?.Trim();
					row["BirthDay"] = DateTime.TryParse(row["BirthDay"]?.ToString(), out var birthday) ? birthday : null;
					row["Address"] = row["Address"]?.ToString()?.Replace("-", " - ").Replace("  ", " ").GetCapitalizedWords();
					row["County"] = row["County"]?.ToString()?.Replace("-", " - ").Replace("  ", " ").GetCapitalizedWords();
					row["Province"] = row["Province"]?.ToString()?.Replace("-", " - ").Replace("  ", " ").GetCapitalizedWords();
				}
				catch { }
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
			var gotRights = this.IsAuthenticated(requestInfo) && requestInfo.Session.User.ID.IsEquals(id);
			if (!gotRights)
				gotRights = requestInfo.Session.User.IsSystemAdministrator || await this.IsAuthorizedAsync(requestInfo, "profile", Components.Security.Action.View, cancellationToken).ConfigureAwait(false);
			var relatedService = gotRights ? null : this.GetRelatedService(requestInfo);
			if (!gotRights && relatedService != null)
				gotRights = await relatedService.CanManageAsync(requestInfo.Session.User, objectName, systemID, definitionID, objectID, cancellationToken).ConfigureAwait(false);
			if (!gotRights && requestInfo.GetHeaderParameter("x-app") == null)
				throw new AccessDeniedException();

			// response
			var response = profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, cancellationToken).ConfigureAwait(false) as JObject);
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
			var account = await Account.GetByIDAsync(id, cancellationToken).ConfigureAwait(false);
			var profile = await Profile.GetAsync<Profile>(account?.ID, cancellationToken).ConfigureAwait(false);
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
					: profile.Avatar.IsStartsWith(Utility.AvatarHttpURI)
						? profile.Avatar.Replace(Utility.FilesHttpURI, "~~")
						: profile.Avatar;

				if (account.Type.Equals(AccountType.BuiltIn) && !profile.Email.Equals(account.AccessIdentity))
					profile.Email = account.AccessIdentity;

				if (string.IsNullOrWhiteSpace(profile.Alias))
					profile.Alias = "";
			});

			// update
			await Task.WhenAll
			(
				Profile.UpdateAsync(profile, requestInfo.Session.User.ID, cancellationToken),
				requestInfo.Query.ContainsKey("related-service")
					? this.CallRelatedServiceAsync(requestInfo, null, "Profile", "PUT", profile.ID, null, cancellationToken)
					: Task.CompletedTask
			).ConfigureAwait(false);

			// send update message
			var response = profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, cancellationToken).ConfigureAwait(false) as JObject);
			await this.SendUpdateMessageAsync(new UpdateMessage
			{
				Type = "Users#Profile#Update",
				DeviceID = "*",
				ExcludedDeviceID = requestInfo.Session.DeviceID,
				Data = response
			}, cancellationToken).ConfigureAwait(false);

			// response
			return response;
		}
		#endregion

		async Task<JToken> ProcessActivationAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (!requestInfo.Verb.IsEquals("GET"))
				throw new MethodNotAllowedException(requestInfo.Verb);

			#region prepare
			var mode = requestInfo.Query.ContainsKey("mode") ? requestInfo.Query["mode"] : null;
			if (string.IsNullOrWhiteSpace(mode))
				throw new InvalidActivateInformationException();

			var code = requestInfo.Query.ContainsKey("code") ? requestInfo.Query["code"] : null;
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
			var identity = info.Get<string>("Account") ?? info.Get<string>("Email");
			var privileges = info.Get<List<Privilege>>("Privileges");
			var relatedService = info.Get<string>("RelatedService");
			var relatedUser = info.Get<string>("RelatedUser");
			var relatedInfo = info.Get<ExpandoObject>("RelatedInfo");

			// activate
			if (mode.IsEquals("Status"))
			{
				// check
				var account = await Account.GetByIDAsync(id, cancellationToken).ConfigureAwait(false);
				if (account == null && !string.IsNullOrWhiteSpace(identity))
					account = await Account.GetByAccessIdentityAsync(identity, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
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
						var relatedAccount = await Account.GetByIDAsync(relatedUser, cancellationToken).ConfigureAwait(false);
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
							await this.CallServiceAsync(new RequestInfo(relatedSession, relatedService, "Activate", "GET")
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
					AccessIdentity = identity,
					AccessKey = Account.GeneratePassword(id, info.Get<string>("Password")),
					AccessPrivileges = privileges ?? new List<Privilege>()
				};
				await Account.CreateAsync(account, cancellationToken).ConfigureAwait(false);

				// prepare response
				var response = account.GetAccountJson();

				// create profile
				var profile = new Profile
				{
					ID = id,
					Name = name,
					Email = identity
				};
				await Profile.CreateAsync(profile, cancellationToken).ConfigureAwait(false);

				// update information of related service
				if (!string.IsNullOrWhiteSpace(relatedService) && !string.IsNullOrWhiteSpace(relatedUser) && relatedInfo != null)
					try
					{
						var relatedAccount = await Account.GetByIDAsync(relatedUser, cancellationToken).ConfigureAwait(false);
						var relatedSession = new Services.Session(requestInfo.Session)
						{
							User = relatedAccount.GetAccountJson().Copy<User>()
						};
						await this.CallServiceAsync(new RequestInfo(relatedSession, relatedService, "Activate", "GET")
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
				return response;
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
			var account = await Account.GetByIDAsync(id, cancellationToken).ConfigureAwait(false);
			if (account == null)
				throw new InvalidActivateInformationException();

			// update new password
			account.AccessKey = Account.GeneratePassword(account.ID, password);
			account.LastAccess = DateTime.Now;
			account.Sessions = null;
			await Account.UpdateAsync(account, true, cancellationToken).ConfigureAwait(false);

			// response
			if (this.IsDebugResultsEnabled)
				await this.WriteLogsAsync(requestInfo, $"Active new password sucessful [ID: {account.ID}]").ConfigureAwait(false);
			return account.GetAccountJson();
		}
		#endregion

		#region Sync
		public override async Task<JToken> SyncAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default)
		{
			var stopwatch = Stopwatch.StartNew();
			await this.WriteLogsAsync(requestInfo, $"Start sync ({requestInfo.Verb} {requestInfo.GetURI()})").ConfigureAwait(false);
			using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, this.CancellationToken))
				try
				{
					// validate
					var json = await base.SyncAsync(requestInfo, cts.Token).ConfigureAwait(false);

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
					await this.WriteLogsAsync(requestInfo, $"Sync success - Execution times: {stopwatch.GetElapsedTimes()}").ConfigureAwait(false);
					if (this.IsDebugResultsEnabled)
						await this.WriteLogsAsync(requestInfo, $"- Request: {requestInfo.ToString(this.JsonFormat)}" + "\r\n" + $"- Response: {json?.ToString(this.JsonFormat)}").ConfigureAwait(false);
					return json;
				}
				catch (Exception ex)
				{
					throw this.GetRuntimeException(requestInfo, ex, stopwatch);
				}
		}

		async Task<JToken> SyncAccountAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var requestBody = requestInfo.GetBodyExpando();
			var account = await Account.GetByIDAsync(requestBody.Get<string>("ID"), cancellationToken).ConfigureAwait(false);
			if (account == null)
			{
				account = Account.CreateInstance(requestBody, null, acc => acc.AccessKey = acc.AccessKey ?? Account.GeneratePassword(acc.ID, Account.GeneratePassword(acc.AccessIdentity)));
				await Account.CreateAsync(account, cancellationToken).ConfigureAwait(false);
			}
			else
			{
				account.Fill(requestBody, null, acc => acc.AccessKey = acc.AccessKey ?? Account.GeneratePassword(acc.ID, Account.GeneratePassword(acc.AccessIdentity)));
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
			var requestBody = requestInfo.GetBodyExpando();
			var profile = await Profile.GetAsync<Profile>(requestBody.Get<string>("ID"), cancellationToken).ConfigureAwait(false);
			if (profile == null)
			{
				profile = Profile.CreateInstance(requestBody);
				await Profile.CreateAsync(profile, cancellationToken).ConfigureAwait(false);
			}
			else
			{
				profile.Fill(requestBody);
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
			=> base.SendSyncRequestAsync(requestInfo, cancellationToken);
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
								var account = await Account.GetByIDAsync(userID, cancellationToken).ConfigureAwait(false);
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
							var account = string.IsNullOrWhiteSpace(info.Item2) ? null : await Account.GetByIDAsync(info.Item2, cancellationToken).ConfigureAwait(false);
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
		void RegisterTimers()
		{
			// clean expired sessions (13 hours)
			this.StartTimer(async () =>
			{
				var userID = UtilityService.GetAppSetting("Users:SystemAccountID", "VIEAppsNGX-MMXVII-System-Account");
				var sessions = await Session.FindAsync(Filters<Session>.LessThan("ExpiredAt", DateTime.Now), null, 0, 1, null, this.CancellationTokenSource.Token).ConfigureAwait(false);
				await sessions.ForEachAsync(async session => await Session.DeleteAsync<Session>(session.ID, userID, this.CancellationToken).ConfigureAwait(false), true, false).ConfigureAwait(false);
			}, 13 * 60 * 60);

			// refresh sessions (10 minutes)
			this.StartTimer(async () =>
			{
				var userTimepoint = DateTime.Now.AddMinutes(-15);
				var visitorTimepoint = DateTime.Now.AddMinutes(-10);
				await this.Sessions.Select(kvp => new { SessionID = kvp.Key, LastActivity = kvp.Value.Item1, UserID = kvp.Value.Item2 })
					.ToList()
					.ForEachAsync(async info =>
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
							}, this.CancellationToken).ConfigureAwait(false);

						// refresh anonymous session
						else if (string.IsNullOrWhiteSpace(info.UserID))
						{
							var key = $"Session#{info.SessionID}";
							var session = await Utility.Cache.GetAsync<Session>(key, this.CancellationToken).ConfigureAwait(false);
							if (session != null)
								await Utility.Cache.SetAsync(key, session, 0, this.CancellationToken).ConfigureAwait(false);
							else
								this.Sessions.TryRemove(info.SessionID, out Tuple<DateTime, string> sessioninfo);
						}
					})
					.ConfigureAwait(false);
			}, 10 * 60);
		}
		#endregion

		#region Validate email/phone/otp & send SMS/OTP
		bool ValidateEmail(string input, out string output)
			=> (input ?? "").IsValidEmail(out output);

		bool ValidatePhone(string input, out string output)
			=> (input ?? "").IsValidPhone(out output, this.PhoneCountryCode);

		Task<JToken> CallOtpServiceAsync(RequestInfo requestInfo, TwoFactorsAuthenticationType type, string id, string stamp, string otp = null, CancellationToken cancellationToken = default, Dictionary<string, string> extra = null)
		{
			extra = new Dictionary<string, string>(extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
			{
				{ "Type", type.ToString() },
				{ "ID", id.Encrypt(this.EncryptionKey) },
				{ "Stamp", stamp.Encrypt(this.EncryptionKey) }
			};
			if (!string.IsNullOrWhiteSpace(otp))
				extra["Password"] = otp.Encrypt(this.EncryptionKey);
			return this.CallServiceAsync(new RequestInfo(requestInfo.Session, "AuthenticatorOTP", "Time-Based-OTP", "GET")
			{
				Header = new Dictionary<string, string>(requestInfo.Header ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
				Query = new Dictionary<string, string>(requestInfo.Query ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
				{
					["language"] = requestInfo.GetParameter("language") ?? "en-US"
				},
				Extra = extra,
				CorrelationID = requestInfo.CorrelationID
			}, cancellationToken);
		}

		async Task<JToken> SendSmsAsync(RequestInfo requestInfo, string phone, string message, Dictionary<string, string> parameters, CancellationToken cancellationToken)
		{
			if (!this.ValidatePhone(phone, out phone))
				throw new InformationInvalidException($"The phone number is invalid");

			var appName = requestInfo.GetAppName();
			var appPlatform = requestInfo.GetAppPlatform();
			var deviceID = requestInfo.GetDeviceID();
			var language = requestInfo.GetParameter("language") ?? "en-US";
			var location = await requestInfo.GetLocationAsync(cancellationToken).ConfigureAwait(false);
			var extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase);
			parameters?.ForEach(kvp => extra[kvp.Key] = kvp.Value);
			return await this.CallServiceAsync(new RequestInfo(requestInfo.Session, "Sms", requestInfo.GetParameter("x-sms-sender") ?? "Default", "POST")
			{
				Header = new Dictionary<string, string>(requestInfo.Header ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
				Query = new Dictionary<string, string>(requestInfo.Query ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
				{
					["language"] = language
				},
				Body = new JObject
				{
					{ "Phone", phone },
					{ "Message", message }
				}.ToString(Formatting.None),
				Extra = new Dictionary<string, string>(extra, StringComparer.OrdinalIgnoreCase)
				{
					["App"] = appName,
					["AppName"] = appName,
					["Platform"] = appPlatform,
					["AppPlatform"] = appPlatform,
					["AppDevice"] = deviceID,
					["DeviceID"] = deviceID,
					["Time"] = "vi-VN".IsEquals(language) ? DateTime.Now.ToString("hh:mm tt @ dd/MM/yyyy") : DateTime.Now.ToString("hh:mm tt @ MM/dd/yyyy"),
					["Location"] = location,
					["IP"] = requestInfo.Session.IP
				},
				CorrelationID = requestInfo.CorrelationID
			}, cancellationToken).ConfigureAwait(false);
		}

		Task<JToken> SendOtpSmsAsync(RequestInfo requestInfo, Account account, string phone, bool isEncrypted, CancellationToken cancellationToken)
		{
			if (!this.ValidatePhone(isEncrypted ? phone.Decrypt(this.AuthenticationKey, true) : phone, out phone))
				throw new InformationInvalidException($"The phone number is invalid");

			var otp = OTPService.GeneratePassword($"{account.ID}@{phone.Encrypt(this.AuthenticationKey, true)}".ToLower().GetHMACSHA512Hash(this.AuthenticationKey), Int32.TryParse(UtilityService.GetAppSetting("OTPs:Interval", ""), out var interval) && interval >= 300 ? interval : 900, Int32.TryParse(UtilityService.GetAppSetting("OTPs:Digits", ""), out var digits) && digits > 3 ? digits : 6);
			var message = requestInfo.GetParameter("x-sms-otp-template") ?? UtilityService.GetAppSetting("OTPs:Template");
			if (string.IsNullOrWhiteSpace(message))
				message = "vi-VN".IsEquals(requestInfo.GetParameter("language") ?? "en-US")
					? "Sử dụng mã {{OTP}} để xác nhận truy cập trên app {{AppName}}"
					: "Use the {{OTP}} code to confirm your access on {{AppName}} app";

			return this.SendSmsAsync(requestInfo, phone, message, new Dictionary<string, string>
			{
				["OTP"] = otp,
				["Code"] = otp,
				["Phone"] = phone,
				["PhoneNumber"] = phone,
				["Name"] = account.Profile?.Name,
				["Email"] = account.Profile?.Email,
				["Account"] = account.AccessIdentity,
				["AccountID"] = account.ID
			}, cancellationToken);
		}
		#endregion

	}
}