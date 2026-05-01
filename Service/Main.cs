#region Related components
using System;
using System.IO;
using System.Linq;
using System.Data;
using System.Dynamic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Core.Contracts;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Repository;
using net.vieapps.Components.Security;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.Users
{
	public class ServiceComponent : ServiceBase
	{
		public override string ServiceName => "Users";

		public ServiceComponent() : base()
			=> this.Sessions = new(() => this.TrackStatistics(), () => this.SendStatistics(this.IsUpdater, false), (ex, correlationID) => this.WriteLogsAsync(correlationID, $"Error occured while tracking sessions => {ex.Message}", ex, "Sessions"));

		public override void Dispose()
		{
			this.Sessions.Dispose();
			base.Dispose();
		}

		#region Properties
		Sessions Sessions { get; }

		Statistics Statistics { get; } = new();

		(long Total, long TotalOfCurrentYear, long TotalOfCurrentMonth, long TotalOfCurrentDay) LastStatistics { get; set; } = (0, 0, 0, 0);

		string ActivationKey => this.GetKey("Activation", "VIEApps-56BA2999-NGX-A2E4-Services-4B54-Activation-83EB-Key-693C250DC95D");

		string AuthenticationKey => this.GetKey("Authentication", "VIEApps-65E47754-NGX-50C0-Services-4565-Authentication-BA55-Key-A8CC23879C5D");

		string CaptchaKey => this.GetKey("Captcha", null);

		string CaptchaExtraKey => this.GetKey("Captcha:Extra", CryptoService.DEFAULT_PASS_PHRASE);

		HashSet<string> WindowsAD { get; } = UtilityService.GetAppSetting("Users:WindowsAD", "vieapps.net|vieapps.com").ToLower().ToHashSet("|", true);

		Dictionary<string, string> WindowsADEmails { get; } = UtilityService.GetAppSetting("Users:WindowsAD:Emails", "vieapps.com:vieapps.net").ToLower().ToList("|", true).ToDictionary(value => value.ToArray(":").First(), value => value.ToArray(":").Last());

		string PhoneCountryCode { get; } = UtilityService.GetAppSetting("Users:Phone:CountryCode", "84");

		bool IsUpdater { get; } = "true".IsEquals(UtilityService.GetAppSetting("Users:Updater", "true"));

		int UpdaterFrequency { get; } = Int32.TryParse(UtilityService.GetAppSetting("Users:Updater:Frequency", "0"), out var frequency) && frequency > 13 && frequency < 300 ? frequency : 0;

		string BlackIPsServiceName { get; } = UtilityService.GetAppSetting("Users:BlackIPs:Service", "Portals");

		string BlackIPsObjectName { get; } = UtilityService.GetAppSetting("Users:BlackIPs:Object", "Black.IPs");

		string BlackIPsVerb { get; } = UtilityService.GetAppSetting("Users:BlackIPs:Verb", "FETCH");

		protected override Privileges Privileges => new Privileges();

		IDisposable CacheCommunicator { get; set; }

		IDisposable SecondaryCommunicator { get; set; }
		#endregion

		#region Register the service
		void RegisterCommunicators()
		{
			this.CacheCommunicator?.Dispose();
			this.CacheCommunicator = Router.GotBackupRouter()
				? Router.BackupChannel.AssignProcessL1CacheRequest(Utility.Cache, this)
				: Router.IncomingChannel.AssignProcessL1CacheRequest(Utility.Cache, this);
			Utility.Cache.AssignSendL1CacheRequest(this, Router.GotBackupRouter());
			if (Router.GotBackupRouter())
			{
				this.SecondaryCommunicator?.Dispose();
				this.SecondaryCommunicator = Router.BackupChannel.Subscribe<CommunicateMessage>
				(
					"messages.services.users",
					message => this.NodeID.IsEquals(message.ExcludedNodeID) ? Task.CompletedTask : this.ProcessInterCommunicateMessageAsync(message, this.CancellationToken),
					exception => this.WriteLogsAsync(UtilityService.NewUUID, this.Logger, $"Error occurred while processing an inter-communicate message of {this.ServiceName} service => {exception.Message}", exception, this.ServiceName, "Errors", LogLevel.Error)
				);
			}
		}

		public override Task RegisterServiceAsync(IEnumerable<string> args, Action<IService> onSuccess = null, Action<Exception> onError = null)
			=> base.RegisterServiceAsync
			(
				args,
				_ =>
				{
					this.RegisterCommunicators();
					onSuccess?.Invoke(this);
				},
				onError
			);

		public override Task UnregisterServiceAsync(IEnumerable<string> args, bool available = true, Action<IService> onSuccess = null, Action<Exception> onError = null)
			=> base.UnregisterServiceAsync
			(
				args,
				available,
				_ =>
				{
					this.CacheCommunicator?.Dispose();
					this.CacheCommunicator = null;
					this.SecondaryCommunicator?.Dispose();
					this.SecondaryCommunicator = null;
					onSuccess?.Invoke(this);
				},
				onError
			);
		#endregion

		#region Start & Stop the service
		public override Task StartAsync(string[] args = null, bool initializeRepository = true, Action<IService> next = null)
		{
			Utility.PepperHash = this.EncryptionKey.GetHMACBLAKE128Hash(this.ValidationKey).ToHex();
			Utility.OAuths = UtilityService.GetAppSetting("Users:OAuths", "").ToList();
			if ("false".IsEquals(UtilityService.GetAppSetting("Users:AllowRegister", "true")))
				Utility.AllowRegister = false;

			Utility.Logger = this.Logger;
			Utility.ActivateHttpURI = this.GetHttpURI("Portals", "https://portals.vieapps.net").RemoveURITrail() + "/home?prego=activate&mode={{mode}}&code={{code}}";
			Utility.FilesHttpURI = this.GetHttpURI("Files", "https://fs.vieapps.net").RemoveURITrail();
			Utility.CaptchaHttpURI = this.GetHttpURI("Captchas", Utility.FilesHttpURI).RemoveURITrail() + "/captchas/";
			Utility.AvatarHttpURI = this.GetHttpURI("Avatars", Utility.FilesHttpURI).RemoveURITrail() + "/avatars/";
			this.Logger?.LogInformation($"System Administrators: {User.SystemAdministrators.Join(",")}");

			return this.StartAsync(args, (_, _) => this.RegisterCommunicators(), initializeRepository, Utility.Cache, _ =>
			{
				this.LoadStatisticsAsync(this.IsUpdater).Execute(ex => this.Logger?.LogInformation($"Error occurred while loading statistics => {ex.Message}", ex));
				this.RegisterTimers();
				next?.Invoke(this);
			});
		}

		protected override async Task StopAsync(string[] args, bool available, bool disconnect, Action<IService> next = null)
		{
			if (this.IsUpdater)
				await this.DumpStatisticsAsync().ConfigureAwait(false);
			await base.StopAsync(args, available, disconnect, next).ConfigureAwait(false);
		}
		#endregion

		public override async Task<JToken> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default)
		{
			var stopwatch = Stopwatch.StartNew();
			await this.WriteLogsAsync(requestInfo, $"Begin request ({requestInfo.Verb} {requestInfo.GetURI()})").ConfigureAwait(false);

			using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, this.CancellationToken);
			try
			{
				JToken json = null;
				switch (requestInfo.ObjectName.ToLower())
				{
					case "statistics":
					case "visit.statistics":
					case "system.statistics":
					case "session.statistics":
					case "visitstatistics":
					case "systemstatistics":
					case "sessionstatistics":
						json = await this.ProcessStatisticsAsync(requestInfo, cts.Token).ConfigureAwait(false);
						break;

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

					case "token":
						json = await this.ProcessTokenAsync(requestInfo, cts.Token).ConfigureAwait(false);
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
						var captcha = CaptchaService.GenerateCode(requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Salt", out var salt) ? salt : null, this.CaptchaKey);
						json = new JObject
						{
							["Code"] = captcha,
							["Uri"] = $"{Utility.CaptchaHttpURI}{captcha.Url64Encode()}/{$"{(requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Mode", out var mode) && !string.IsNullOrWhiteSpace(mode) ? mode : "small")}-{UtilityService.NewUUID.Substring(UtilityService.GetRandomNumber(3, 23))}".Url64Encode()}/{(string.IsNullOrWhiteSpace(this.CaptchaKey) ? "" : $"{this.CaptchaKey}:{UtilityService.NewUUID}".Encrypt(this.CaptchaExtraKey).ToBase64Url(true) + "/")}{(requestInfo.GetParameter("register") ?? UtilityService.NewUUID.Encrypt(this.EncryptionKey, true)).Substring(UtilityService.GetRandomNumber(13, 43), 13).Reverse()}.webp"
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

		#region Related services
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

		#region Instructions
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

		async Task<((string Subject, string Body) Envelop, (string Email, string Signature) Sender, (string Host, int Port, bool EnableSsl, string User, string Password) Server)> GetInstructionsAsync(RequestInfo requestInfo, string mode = "reset", CancellationToken cancellationToken = default)
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

			return
			(
				(subject, body.NormalizeHTMLBreaks()),
				(emailSender, emailSignature),
				(smtpServerHost, smtpServerPort, smtpServerEnableSsl, smtpUser, smtpUserPassword)
			);
		}
		#endregion

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
			else if (this.Sessions.Exist(requestInfo.Session.SessionID))
				return new JObject
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "Existed", true }
				};

			var session = await Utility.Cache.GetAsync<Session>(requestInfo.Session.SessionID.GetCacheKey<Session>(), cancellationToken).ConfigureAwait(false);
			if (session == null && !requestInfo.Session.User.ID.Equals("") && !requestInfo.Session.User.IsSystemAccount)
				session = await Session.GetAsync(requestInfo.Session.SessionID, cancellationToken).ConfigureAwait(false);

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
			if (requestInfo.Extra == null || !requestInfo.Extra.TryGetValue("Signature", out var signature) || !signature.Equals(requestInfo.GetParameter("x-app-token")?.GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException("The signature is not found or invalid");
			var session = requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount
				? await Utility.Cache.FetchAsync<Session>(requestInfo.Session.SessionID, cancellationToken).ConfigureAwait(false)
				: await Session.GetAsync(requestInfo.Session.SessionID, cancellationToken).ConfigureAwait(false);
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
			if (requestInfo.Extra == null || !requestInfo.Extra.TryGetValue("Signature", out var signature) || !signature.Equals(requestInfo.Body.GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException("The signature is not found or invalid");

			var requestBody = requestInfo.GetBodyExpando() ?? throw new InformationRequiredException();

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
				var session = await Session.GetAsync(requestInfo.Session.SessionID, cancellationToken, false).ConfigureAwait(false);
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

				// remove duplicated sessions
				await Session.DeleteManyAsync(Filters<Session>.And(Filters<Session>.Equals("DeviceID", session.DeviceID), Filters<Session>.NotEquals("ID", session.ID)), null, cancellationToken).ConfigureAwait(false);

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

			var identity = requestBody.Get("Account", requestBody.Get("Email", "")).Decrypt(this.EncryptionKey).Trim().ToLower();
			var password = requestBody.Get("Password", "").Decrypt(this.EncryptionKey);
			var domain = identity.IsContains("@")
				? identity.Right(identity.Length - identity.PositionOf("@") - 1).Trim()
				: null;
			var type = !string.IsNullOrWhiteSpace(domain) && this.WindowsAD.Contains(domain)
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
					Header = new Dictionary<string, string>(requestInfo.Header ?? [], StringComparer.OrdinalIgnoreCase),
					Query = new Dictionary<string, string>(requestInfo.Query ?? [], StringComparer.OrdinalIgnoreCase)
					{
						["language"] = requestInfo.GetParameter("language") ?? "en-US"
					},
					Body = body,
					Extra = new Dictionary<string, string>(requestInfo.Query ?? [], StringComparer.OrdinalIgnoreCase)
					{
						["Signature"] = body.GetHMACSHA256(this.ValidationKey)
					}
				}, cancellationToken).ConfigureAwait(false);

				// prepare account & profile
				if (requestInfo.Extra == null || !requestInfo.Extra.ContainsKey("x-no-account"))
				{
					var email = this.WindowsADEmails.TryGetValue(domain, out var edomain) && !string.IsNullOrWhiteSpace(edomain) ? $"{username}@{edomain}" : identity;
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
							Email = email
						};
						await Profile.CreateAsync(profile, cancellationToken).ConfigureAwait(false);
					}
					else if (!email.IsEquals(identity))
					{
						var profile = await Profile.GetAsync(account.ID, cancellationToken).ConfigureAwait(false);
						if (profile != null && !email.IsEquals(profile.Email))
						{
							profile.Email = email;
							await Profile.UpdateAsync(profile, true, cancellationToken).ConfigureAwait(false);
						}
					}
				}
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
			if (requestInfo.Extra == null || !requestInfo.Extra.ContainsKey("Signature") || !requestInfo.Extra["Signature"].Equals(requestInfo.GetParameter("x-app-token")?.GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException("The signature is not found or invalid");

			// remove session
			await Session.DeleteAsync(requestInfo.Session.SessionID, requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false);

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

			var account = await Account.GetByIDAsync(id, cancellationToken).ConfigureAwait(false) ?? throw new InformationNotFoundException();
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
					await Account.DeleteAsync(mappingAccount.ID, account.ID, cancellationToken).ConfigureAwait(false);
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
					return "reset".IsEquals(identity)
						? this.ResetPasswordAsync(requestInfo, cancellationToken)
						: "renew".IsEquals(identity)
							? this.RenewPasswordAsync(requestInfo, cancellationToken)
							: "password".IsEquals(identity)
								? this.UpdatePasswordAsync(requestInfo, cancellationToken)
								: "email".IsEquals(identity)
									? this.UpdateEmailAsync(requestInfo, cancellationToken)
									: this.SetPrivilegesAsync(requestInfo, cancellationToken);

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
			var account = (!string.IsNullOrWhiteSpace(identity) && identity.IsValidUUID()
				? await Account.GetByIDAsync(identity, cancellationToken).ConfigureAwait(false)
				: await Account.GetByAccessIdentityAsync(this.ValidatePhone(identity, out var phone) ? phone : identity, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false)) ?? throw new InformationNotFoundException();

			// response
			if (requestInfo.ContainsKey("x-status") || account.TwoFactorsAuthentication.Required)
			{
				this.SendStatistics(this.IsUpdater);
				var location = await requestInfo.GetLocationAsync(cancellationToken).ConfigureAwait(false);
				return account.GetAccountJson(true, this.AuthenticationKey, json =>
				{
					json["IP"] = requestInfo.Session.IP;
					json["Location"] = location;
				});
			}
			return account.GetAccountJson();
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
			var identity = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Account", out var avalue) ? avalue.Decrypt(this.EncryptionKey).Trim().ToLower() : null;
			if (string.IsNullOrWhiteSpace(identity))
				identity = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Email", out var evalue) ? evalue.Decrypt(this.EncryptionKey).Trim().ToLower() : null;
			var password = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Password", out var pvalue) ? pvalue.Decrypt(this.EncryptionKey) : null;
			if (string.IsNullOrWhiteSpace(password))
				password = Account.GeneratePassword(identity);

			// check existing account
			if (await Account.GetByAccessIdentityAsync(identity, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false) != null)
				throw new InformationExistedException($"The identity ({identity}) has been used for another account");

			// related: privileges, service, extra info
			var privileges = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Privileges", out var privalue)
				? JArray.Parse(privalue.Decrypt(this.EncryptionKey)).ToList<Privilege>()
				: null;

			var relatedService = requestInfo.GetQueryParameter("related-service");
			var relatedInfo = !string.IsNullOrWhiteSpace(relatedService) && requestInfo.Extra != null && requestInfo.Extra.TryGetValue("RelatedInfo", out var rvalue)
				? rvalue.Decrypt(this.EncryptionKey).ToExpandoObject()
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
					Status = requestBody.Get("Statistics", "Registered").ToEnum<AccountStatus>(),
					Type = requestBody.Get("Type", "BuiltIn").ToEnum<AccountType>(),
					AccessIdentity = identity,
					AccessKey = password,
					AccessPrivileges = privileges ?? []
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
				{ "Mode", isCreateNew ? "Statistics" : "Create"  }
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

			var from = instructions.Sender.Email;
			var to = $"{name} <{identity}>";

			var subject = instructions.Envelop.Subject;
			if (string.IsNullOrWhiteSpace(subject))
				subject = @"[{{@request.Session(AppName)}}] Activate your account";

			var body = instructions.Envelop.Body;
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

			var smtpServerHost = instructions.Server.Host;
			var smtpServerPort = instructions.Server.Port;
			var smtpServerEnableSsl = instructions.Server.EnableSsl;
			var smtpServerUsername = instructions.Server.User;
			var smtpServerPassword = instructions.Server.Password;

			var inviter = mode.Equals("invite") ? await Profile.GetAsync(requestInfo.Session.User.ID, cancellationToken).ConfigureAwait(false) : null;
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
				{ "EmailSignature", instructions.Sender.Signature }
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
				var serviceName = requestInfo.GetParameter("related-service");
				var objectName = requestInfo.GetParameter("related-object");
				var systemID = requestInfo.GetParameter("related-system");
				var definitionID = requestInfo.GetParameter("related-definition");
				var objectID = requestInfo.GetParameter("related-object-identity");
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
			var serviceName = requestInfo.GetParameter("related-service");
			var objectName = requestInfo.GetParameter("related-object");
			var systemID = requestInfo.GetParameter("related-system");
			var entityInfo = requestInfo.GetParameter("related-entity");
			var objectID = requestInfo.GetParameter("related-object-identity");

			// check permission => only system administrator or manager of the specified service can do
			var isSystemAdministrator = requestInfo.Session.User.IsSystemAdministrator;
			var gotRights = isSystemAdministrator;
			var relatedService = gotRights ? null : this.GetRelatedService(requestInfo);
			if (!gotRights && relatedService != null)
				gotRights = await relatedService.CanManageAsync(requestInfo.Session.User, objectName, systemID, entityInfo, objectID, cancellationToken).ConfigureAwait(false);
			if (!gotRights)
				throw new AccessDeniedException();

			// get account
			var account = await Account.GetByIDAsync(requestInfo.GetObjectIdentity(), cancellationToken).ConfigureAwait(false) ?? throw new InformationNotFoundException();

			// roles of a system
			if (!string.IsNullOrWhiteSpace(systemID) && requestInfo.Extra != null && (requestInfo.Extra.ContainsKey("Roles") || requestInfo.Extra.ContainsKey("AddedRoles") || requestInfo.Extra.ContainsKey("RemovedRoles")))
				try
				{
					if (!account.AccessRoles.TryGetValue(systemID, out var roles))
						roles = [];
					if (requestInfo.Extra.TryGetValue("Roles", out var extraRoles))
						account.AccessRoles[systemID] = roles.Concat(JArray.Parse(extraRoles.Decrypt(this.EncryptionKey)).ToList<string>()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
					else if (requestInfo.Extra.TryGetValue("AddedRoles", out var addedRoles))
						account.AccessRoles[systemID] = roles.Concat(JArray.Parse(addedRoles.Decrypt(this.EncryptionKey)).ToList<string>()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
					else if (requestInfo.Extra.TryGetValue("RemovedRoles", out var removedRoles))
						account.AccessRoles[systemID] = roles.Except(JArray.Parse(removedRoles.Decrypt(this.EncryptionKey)).ToList<string>()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
				}
				catch (Exception ex)
				{
					await this.WriteLogsAsync(requestInfo, $"Error while processing roles of an user account [{account.ID}] => {ex.Message}", ex, LogLevel.Error).ConfigureAwait(false);
				}

			// privileges of a service
			if (requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Privileges", out var extraPrivileges))
				try
				{
					var allPrivileges = extraPrivileges.Decrypt(this.EncryptionKey).ToJson().ToExpandoObject();
					if (isSystemAdministrator)
					{
						(allPrivileges as IDictionary<string, object>).Keys.ForEach(svcName =>
						{
							var svcPrivileges = allPrivileges.Get<List<Privilege>>(svcName).Where(p => p.ServiceName.IsEquals(svcName)).ToList();
							if (svcPrivileges.Count == 1 && svcPrivileges[0].ObjectName.Equals("") && svcPrivileges[0].Role.Equals(PrivilegeRole.Viewer.ToString()))
								svcPrivileges = [];
							account.AccessPrivileges = account.AccessPrivileges.Where(p => !p.ServiceName.IsEquals(svcName)).Concat(svcPrivileges).ToList();
						});
					}
					else if (!string.IsNullOrWhiteSpace(serviceName))
					{
						var svcPrivileges = allPrivileges.Get<List<Privilege>>(serviceName).Where(p => p.ServiceName.IsEquals(serviceName)).ToList();
						if (svcPrivileges.Count == 1 && svcPrivileges[0].ObjectName.Equals("") && svcPrivileges[0].Role.Equals(PrivilegeRole.Viewer.ToString()))
							svcPrivileges = [];
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
					this.WriteLogs(requestInfo, $"Error while preparing info of an user account [{session.ID} @ {user.ID}] => {ex.Message}", ex, LogLevel.Error);
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
			var identity = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Account", out string value) ? value.Decrypt(this.EncryptionKey) : null;
			if (string.IsNullOrWhiteSpace(identity))
				identity = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Email", out value) ? value.Decrypt(this.EncryptionKey) : null;

			var account = await Account.GetByAccessIdentityAsync(identity, AccountType.BuiltIn, cancellationToken).ConfigureAwait(false);
			if (account == null)
				return new JObject
				{
					{ "Message", "Please check your email and follow the instruction to activate" }
				};

			// prepare
			var password = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Password", out value) ? value.Decrypt(this.EncryptionKey) : null;
			if (string.IsNullOrWhiteSpace(password))
				password = Account.GeneratePassword(identity);

			var code = new JObject
			{
				{ "ID", account.ID },
				{ "Password", password },
				{ "Time", DateTime.Now }
			}.ToString(Formatting.None).Encrypt(this.ActivationKey).ToBase64Url(true);

			var uri = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Uri", out value) ? value.Decrypt(this.EncryptionKey) : null;
			if (string.IsNullOrWhiteSpace(uri))
				uri = requestInfo.Query.TryGetValue("uri", out value) ? value.Url64Decode() : Utility.ActivateHttpURI;

			uri = uri.Format(new Dictionary<string, object>
			{
				["mode"] = "password",
				["code"] = code
			});

			// prepare activation email
			var instructions = await this.GetInstructionsAsync(requestInfo, "reset", cancellationToken).ConfigureAwait(false);

			var from = instructions.Sender.Email;
			var to = $"{account.Profile.Name} <{account.AccessIdentity}>";

			var subject = instructions.Envelop.Subject;
			if (string.IsNullOrWhiteSpace(subject))
				subject = @"[{{@request.Session(AppName)}}] Activate your new password";

			var body = instructions.Envelop.Body;
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

			var smtpServerHost = instructions.Server.Host;
			var smtpServerPort = instructions.Server.Port;
			var smtpServerEnableSsl = instructions.Server.EnableSsl;
			var smtpServerUsername = instructions.Server.User;
			var smtpServerPassword = instructions.Server.Password;

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
				{ "EmailSignature", instructions.Sender.Signature }
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

				var otp = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("OtpCode", out string value) ? value.Decrypt(this.EncryptionKey) : null;
				if (string.IsNullOrWhiteSpace(otp))
					throw new InformationInvalidException();

				var stamp = phone.Encrypt(this.AuthenticationKey, true);
				if (account.TwoFactorsAuthentication.Settings.FirstOrDefault(provider => provider.Type.Equals(TwoFactorsAuthenticationType.SMS) && provider.Stamp.Equals(stamp)) == null)
					throw new InformationInvalidException();

				// validate
				await this.CallOtpServiceAsync(requestInfo, TwoFactorsAuthenticationType.SMS, account.ID, stamp, otp, cancellationToken).ConfigureAwait(false);

				// update
				var password = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Password", out value) ? value.Decrypt(this.EncryptionKey) : null;
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
				{ "Statistics", "Sent" }
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

			var from = instructions.Sender.Email;
			var to = $"{account.Profile?.Name ?? email} <{email}>";

			var subject = instructions.Envelop.Subject;
			if (string.IsNullOrWhiteSpace(subject))
				subject = @"[{{@request.Session(AppName)}}] Your account has been updated";

			var body = instructions.Envelop.Body;
			if (string.IsNullOrWhiteSpace(body))
				body = @"Hi <b>{{@params(Name)}}</b>
				<br/>
				These are your account information:
				<blockquote>
					Account: <b>{{@params(Account)}}</b>
					Password (new): <b>{{@params(Password)}}</b>
				</blockquote>";

			var smtpServerHost = instructions.Server.Host;
			var smtpServerPort = instructions.Server.Port;
			var smtpServerEnableSsl = instructions.Server.EnableSsl;
			var smtpServerUsername = instructions.Server.User;
			var smtpServerPassword = instructions.Server.Password;

			var @params = new JObject
			{
				{ "Account", account.AccessIdentity },
				{ "Password", password },
				{ "Email", email },
				{ "Name", account.Profile?.Name },
				{ "Time", DateTime.Now },
				{ "Location", await requestInfo.GetLocationAsync(cancellationToken).ConfigureAwait(false) },
				{ "EmailSignature", instructions.Sender.Signature }
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

			var from = instructions.Sender.Email;
			var to = $"{account.Profile.Name} <{account.AccessIdentity}>";

			var subject = instructions.Envelop.Subject;
			if (string.IsNullOrWhiteSpace(subject))
				subject = @"[{{@request.Session(AppName)}}] Your account has been updated";

			var body = instructions.Envelop.Body;
			if (string.IsNullOrWhiteSpace(body))
				body = @"Hi <b>{{@params(Name)}}</b>
				<br/>
				These are your account information:
				<blockquote>
					Your new login  email: <b>{{@params(Email)}}</b>
					Old login email: <b>{{@params(OldEmail)}}</b>
				</blockquote>";

			var smtpServerHost = instructions.Server.Host;
			var smtpServerPort = instructions.Server.Port;
			var smtpServerEnableSsl = instructions.Server.EnableSsl;
			var smtpServerUsername = instructions.Server.User;
			var smtpServerPassword = instructions.Server.Password;

			var @params = new JObject
			{
				{ "Host", requestInfo.GetQueryParameter("host") ?? "unknown" },
				{ "Email", account.AccessIdentity },
				{ "OldEmail", oldEmail },
				{ "Name", account.Profile.Name },
				{ "Time", DateTime.Now },
				{ "Location", await requestInfo.GetLocationAsync(cancellationToken).ConfigureAwait(false) },
				{ "EmailSignature", instructions.Sender.Signature }
			}.ToExpandoObject();
			var parameters = $"{subject}\r\n{body}".PrepareDoubleBracesParameters(null, requestInfo.AsExpandoObject, @params);

			// send an email
			await this.SendEmailAsync(from, to, subject.Format(parameters), body.Format(parameters), smtpServerHost, smtpServerPort, smtpServerEnableSsl, smtpServerUsername, smtpServerPassword, cancellationToken).ConfigureAwait(false);

			// response
			return account.Profile.ToJson();
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
					if ("fetch".IsEquals(identity))
						return this.FetchProfilesAsync(requestInfo, cancellationToken, requestInfo.Extra.TryGetValue("x-notifications-key", out var notificationsKey) && notificationsKey != null && notificationsKey.IsEquals(this.GetKey("Notifications", null)), !requestInfo.Extra.TryGetValue("x-fetch-sessions", out var fetchSessions) || !"false".IsEquals(fetchSessions));

					// export
					if ("export".IsEquals(identity))
						return this.ExportProfilesAsync(requestInfo, cancellationToken);

					// get details of a profile
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
			var (totalRecords, totalPages, pageSize, pageNumber) = request.Get<ExpandoObject>("Pagination")?.GetPagination() ?? (-1, 0, 20, 1);

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
			totalRecords = totalRecords > -1 ? totalRecords : -1;
			if (totalRecords < 0)
				totalRecords = string.IsNullOrWhiteSpace(query)
					? await Profile.CountAsync(filter, $"{cacheKey}:total", cancellationToken).ConfigureAwait(false)
					: await Profile.CountAsync(query, filter, cancellationToken).ConfigureAwait(false);

			totalPages = (totalRecords, pageSize).GetTotalPages();
			if (totalPages > 0 && pageNumber > totalPages)
				pageNumber = totalPages;

			// search
			var objects = totalRecords > 0
				? string.IsNullOrWhiteSpace(query)
					? await Profile.FindAsync(filter, sort, pageSize, pageNumber, $"{cacheKey}{pageNumber}", cancellationToken).ConfigureAwait(false)
					: await Profile.SearchAsync(query, filter, null, pageSize, pageNumber, cancellationToken).ConfigureAwait(false)
				: [];

			// build result
			var profiles = new JArray();
			await objects.ForEachAsync(async profile =>
			{
				profiles.Add(profile.GetProfileJson(await this.GetProfileRelatedJsonAsync(requestInfo, cancellationToken).ConfigureAwait(false) as JObject));
			}, true, false).ConfigureAwait(false);

			var result = new JObject
			{
				{ "FilterBy", (filter ?? new FilterBys<Profile>()).ToClientJson(query) },
				{ "SortBy", sort?.ToClientJson() },
				{ "Pagination", (totalRecords, totalPages, pageSize, pageNumber).GetPagination() },
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
		async Task<JToken> FetchProfilesAsync(RequestInfo requestInfo, CancellationToken cancellationToken, bool isContactRequest = false, bool fetchSessions = true)
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
				if (fetchSessions)
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
					{ "Sessions", sessions.TryGetValue(profile.ID, out var session) ? session : null }
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
						totalPages = totalRecords < 1 ? 0 : (totalRecords, pageSize).GetTotalPages();
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
								{ "Statistics", "Processing" },
								{ "Percentage", $"{pageNumber * 100/totalPages:#0.0}%" }
							}
						}.Send();

						try
						{
							var objects = pageNumber <= totalPages && (maxPages == 0 || pageNumber <= maxPages)
								? await RepositoryMediator.FindAsync(null, filter, sort, pageSize, pageNumber, null, false, null, 0, this.CancellationToken).ConfigureAwait(false)
								: [];
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
							{ "Statistics", "Done" },
							{ "Percentage", "100%" },
							{ "Filename", filename },
							{ "NodeID", Extensions.GetUniqueName(this.ServiceName, this.NodeID) },
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
						code = wampDetails.Code;
						type = wampDetails.Message;
						message = wampDetails.Type;
						stack = wampDetails.Stack;
					}
					new UpdateMessage
					{
						Type = "Users#Profile#Export",
						DeviceID = deviceID,
						Data = new JObject
						{
							{ "ProcessID", processID },
							{ "Statistics", "Error" },
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
			var profile = await Profile.GetAsync(id, cancellationToken).ConfigureAwait(false) ?? throw new InformationNotFoundException();

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
			if (requestInfo.ContainsKey("x-app"))
				new UpdateMessage
				{
					Type = $"{this.ServiceName}#Profile",
					Data = response,
					DeviceID = requestInfo.Session.DeviceID
				}.Send();
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
			var profile = await Profile.GetAsync(account?.ID, cancellationToken).ConfigureAwait(false);
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
			var mode = requestInfo.Query.TryGetValue("mode", out string value) ? value : null;
			if (string.IsNullOrWhiteSpace(mode))
				throw new InvalidActivateInformationException();

			var code = requestInfo.Query.TryGetValue("code", out value) ? value : null;
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
			if (mode.IsEquals("password"))
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
			if (mode.IsEquals("Statistics"))
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
			var account = await Account.GetByIDAsync(id, cancellationToken).ConfigureAwait(false) ?? throw new InvalidActivateInformationException();

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

		async Task<JToken> ProcessTokenAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var isSystemAdministrator = await this.IsSystemAdministratorAsync(requestInfo.Session.User, requestInfo.CorrelationID, cancellationToken).ConfigureAwait(false);
			switch (requestInfo.Verb)
			{
				case "GET":
					return "search".IsEquals(requestInfo.GetObjectIdentity())
						? isSystemAdministrator
							? await this.SearchTokensAsync(requestInfo, cancellationToken).ConfigureAwait(false)
							: throw new AccessDeniedException()
						: await this.GetTokenAsync(requestInfo, isSystemAdministrator && requestInfo.ContainsKey("x-as-json"), cancellationToken).ConfigureAwait(false);

				case "POST":
					return isSystemAdministrator
						? await this.CreateTokenAsync(requestInfo, cancellationToken).ConfigureAwait(false)
						: throw new AccessDeniedException();

				case "DELETE":
					return isSystemAdministrator
						? await this.DeleteTokenAsync(requestInfo, cancellationToken).ConfigureAwait(false)
						: throw new AccessDeniedException();

				default:
					throw new MethodNotAllowedException(requestInfo.Verb);
			}
		}

		#region Working with tokens
		async Task<JToken> PrepareTokenAsync(RequestInfo requestInfo, Token token, bool updateTimes, bool asJSON, CancellationToken cancellationToken)
		{
			Account account = null;
			User user = null;

			var session = await Session.GetAsync(token.SessionID, cancellationToken).ConfigureAwait(false);
			if (session == null)
			{
				var deviceID = string.IsNullOrWhiteSpace(requestInfo.Session.DeviceID) ? $"{UtilityService.NewUUID}@vieapps-ngx-apis" : requestInfo.Session.DeviceID;
				account = string.IsNullOrWhiteSpace(token.UserID)
					? null
					: await Account.GetAsync(token.UserID, cancellationToken).ConfigureAwait(false) ?? throw new InformationNotFoundException("User is not found");
				user = new User(account?.ID ?? "", token.SessionID, deviceID, account?.Roles ?? [$"{SystemRole.All}"], account?.AccessPrivileges ?? [], "APIs");

				session = new Session(requestInfo.Session)
				{
					ID = token.SessionID,
					UserID = token.UserID,
					DeviceID = deviceID,
					ExpiredAt = token.Expires,
					AccessToken = user.GetAccessToken(this.ECCKey, payload => payload["exp"] = token.Expires.ToUnixTimestamp()),
					Verified = true
				};
				await Session.CreateAsync(session, cancellationToken).ConfigureAwait(false);
			}
			else if (updateTimes && session.RenewedAt < DateTime.Now.AddMinutes(-15))
			{
				session.IssuedAt = DateTime.Now;
				session.RenewedAt = DateTime.Now;
				await Session.UpdateAsync(session, false, cancellationToken).ConfigureAwait(false);
			}

			var sendUpdateMessage = false;
			if (updateTimes && token.LastAccess < DateTime.Now.AddMinutes(-5))
			{
				sendUpdateMessage = true;
				token.LastAccess = DateTime.Now;
				await Token.UpdateAsync(token, false, cancellationToken).ConfigureAwait(false);
			}

			account ??= await Account.GetAsync(token.UserID, cancellationToken).ConfigureAwait(false);
			user ??= new User(account?.ID ?? "", token.SessionID, session.DeviceID, account?.Roles ?? [$"{SystemRole.All}"], account?.AccessPrivileges ?? [], "APIs");

			var authenticateToken = user.GetAuthenticateToken(this.EncryptionKey, this.JWTKey, payload =>
			{
				payload["exp"] = session.ExpiredAt.ToUnixTimestamp();
				payload["2fa"] = $"{session.Verified}|{UtilityService.NewUUID}".Encrypt(this.EncryptionKey, true);
				payload["dev"] = (session.DeveloperID ?? "").Encrypt(this.EncryptionKey, true);
				payload["app"] = (session.AppID ?? "").Encrypt(this.EncryptionKey, true);
				payload["tid"] = token.ID;
			});

			if (sendUpdateMessage)
				new UpdateMessage
				{
					Type = "Users#Token#Update",
					DeviceID = "*",
					Data = token.ToJson(json => json["Token"] = null)
				}.Send();

			return asJSON
				? token.ToJson(json => json["Token"] = new JObject
					{
						["Bearer"] = $"Bearer {authenticateToken}",
						["Basic"] = $"Basic {$"{token.ID}:{$"{token.UserID}:{token.SessionID}".Encrypt(this.EncryptionKey, true)}".ToBase64Url()}"
					})
				: new JObject
				{
					["Token"] = authenticateToken,
					["Session"] = session.ToSession(account, obj =>
					{
						obj.User = user;
						obj.IP = requestInfo.Session.IP;
						obj.AppName = token.Title;
						obj.AppPlatform = $"APIs based ({requestInfo.Session.AppPlatform})";
						obj.AppAgent = requestInfo.Session.AppAgent;
						obj.AppOrigin = requestInfo.Session.AppOrigin;
						obj.AppMode = "APIs";
					}).ToJson()
				};
		}

		async Task<JToken> SearchTokensAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// prepare
			var request = requestInfo.GetRequestExpando();

			var query = request.Get<string>("FilterBy.Query");
			var filter = request.Get<ExpandoObject>("FilterBy")?.ToFilterBy<Token>();
			var sort = request.Get<ExpandoObject>("SortBy")?.ToSortBy<Token>();
			if (sort == null && string.IsNullOrWhiteSpace(query))
				sort = Sorts<Token>.Ascending("Title");

			// prepare pagination
			var (totalRecords, totalPages, pageSize, pageNumber) = request.Get<ExpandoObject>("Pagination")?.GetPagination() ?? (-1, 0, 20, 1);
			totalRecords = totalRecords > -1
				? totalRecords
				: string.IsNullOrWhiteSpace(query)
					? await Token.CountAsync(filter, null, cancellationToken).ConfigureAwait(false)
					: await Token.CountAsync(query, filter, cancellationToken).ConfigureAwait(false);

			totalPages = (totalRecords, pageSize).GetTotalPages();
			if (totalPages > 0 && pageNumber > totalPages)
				pageNumber = totalPages;

			// search
			var tokens = totalRecords > 0
				? string.IsNullOrWhiteSpace(query)
					? await Token.FindAsync(filter, sort, pageSize, pageNumber, null, cancellationToken).ConfigureAwait(false)
					: await Token.SearchAsync(query, filter, null, pageSize, pageNumber, cancellationToken).ConfigureAwait(false)
				: [];

			// build result
			var objects = new JArray();
			await tokens.ForEachAsync(async token => objects.Add(await this.PrepareTokenAsync(requestInfo, token, false, true, cancellationToken).ConfigureAwait(false)), true, false).ConfigureAwait(false);

			return new JObject
			{
				{ "FilterBy", (filter ?? new FilterBys<Token>()).ToClientJson(query) },
				{ "SortBy", sort?.ToClientJson() },
				{ "Pagination", (totalRecords, totalPages, pageSize, pageNumber).GetPagination() },
				{ "Objects", objects }
			};
		}

		async Task<JToken> GetTokenAsync(RequestInfo requestInfo, bool asJSON, CancellationToken cancellationToken)
		{
			string userID = null, sessionID = null;
			var identity = asJSON
				? requestInfo.GetObjectIdentity()
				: requestInfo.GetHeaderParameter("x-authorization-token");

			if (!asJSON && (!requestInfo.TryGetHeaderParameter("x-authorization-signature", out var signature) || !signature.Equals(identity?.GetHMACSHA256(this.ValidationKey))))
				throw new InvalidTokenException("Token is invalid");

			if (!asJSON)
				try
				{
					if ("Basic".IsEquals(requestInfo.GetHeaderParameter("x-authorization-mode")))
					{
						var data = identity.FromBase64Url().ToList(":");
						identity = data.First();
						data = data.Last().Decrypt(this.EncryptionKey, true).ToList(":");
						userID = data.First();
						sessionID = data.Last();
					}
					else
						identity.ParseAuthenticateToken(this.EncryptionKey, this.JWTKey, 123456789, (payload, user) =>
						{
							identity = payload.Get<string>("tid");
							userID = user.ID;
							sessionID = user.SessionID;
						});
				}
				catch (Exception ex)
				{
					throw new InvalidTokenException("Token is invalid", ex);
				}

			var token = await Token.GetAsync(identity, cancellationToken).ConfigureAwait(false) ?? throw new TokenNotFoundException("Token is not found");

			if (!asJSON && (!token.UserID.IsEquals(userID) || !token.SessionID.IsEquals(sessionID)))
				throw new InvalidTokenException("Token is invalid");

			return token.Expires > DateTime.Now
				? await this.PrepareTokenAsync(requestInfo, token, true, asJSON, cancellationToken).ConfigureAwait(false)
				: throw new TokenExpiredException("Token is expired");
		}

		async Task<JToken> CreateTokenAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var request = requestInfo.GetBodyExpando();
			var token = new Token
			{
				ID = UtilityService.NewUUID,
				Title = request.Get<string>("Title"),
				UserID = request.Get("UserID", ""),
				SessionID = UtilityService.NewUUID,
				Expires = DateTime.TryParse(request.Get<string>("Expires"), out var expires) && expires > DateTime.Now ? expires : DateTime.Now.AddYears(10),
				CreatedID = requestInfo.Session.User.ID
			};

			if (!string.IsNullOrWhiteSpace(token.UserID) && await Account.GetAsync(token.UserID, cancellationToken).ConfigureAwait(false) == null)
				throw new InformationNotFoundException("User is not found");

			await Token.CreateAsync(token, cancellationToken).ConfigureAwait(false);
			var response = await this.PrepareTokenAsync(requestInfo, token, false, true, cancellationToken).ConfigureAwait(false);
			new UpdateMessage
			{
				Type = "Users#Token#Create",
				DeviceID = "*",
				Data = response
			}.Send();
			return response;
		}

		async Task<JToken> DeleteTokenAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var token = await Token.GetAsync(requestInfo.GetObjectIdentity(), cancellationToken).ConfigureAwait(false) ?? throw new TokenNotFoundException("Token is not found");
			await Task.WhenAll
			(
				Token.DeleteAsync(token.ID, requestInfo.Session.User.ID, cancellationToken),
				Session.DeleteAsync(token.SessionID, requestInfo.Session.User.ID, cancellationToken)
			).ConfigureAwait(false);

			var response = token.ToJson();
			new UpdateMessage
			{
				Type = "Users#Token#Delete",
				DeviceID = "*",
				Data = response
			}.Send();
			return response;
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
				account = Account.CreateInstance(requestBody, acc => acc.AccessKey = acc.AccessKey ?? Account.GeneratePassword(acc.ID, Account.GeneratePassword(acc.AccessIdentity)));
				await Account.CreateAsync(account, cancellationToken).ConfigureAwait(false);
			}
			else
			{
				account.Fill(requestBody, acc => acc.AccessKey = acc.AccessKey ?? Account.GeneratePassword(acc.ID, Account.GeneratePassword(acc.AccessIdentity)));
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
			var profile = await Profile.GetAsync(requestBody.Get<string>("ID"), cancellationToken).ConfigureAwait(false);
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

		#region Statistics
		async Task<JToken> ProcessStatisticsAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (requestInfo.Verb.IsEquals("GET"))
			{
				if (requestInfo.ObjectName.IsEquals("Statistics") && "fetch".IsEquals(requestInfo.GetObjectIdentity()))
					return this.SendStatistics();

				var isSystemAdministrator = await this.IsSystemAdministratorAsync(requestInfo, cancellationToken).ConfigureAwait(false);
				if (isSystemAdministrator)
				{
					if (requestInfo.ContainsKey("x-normalize"))
					{
						if (this.IsUpdater)
							this.NormalizeStatisticsAsync(requestInfo.GetParameter("x-clone-date"), requestInfo.GetParameter("x-clone-date-by"), requestInfo.GetParameter("x-clone-min"), requestInfo.GetParameter("x-clone-max"), requestInfo.ContainsKey("x-clone-as-set"), requestInfo.GetParameter("x-suffix")).Execute(ex => this.Logger.LogInformation($"Error occurred while normalizing => {ex.Message}", ex));
						else
							new CommunicateMessage(this.ServiceName)
							{
								Type = "Statistics#Normalize",
								Data = new JObject
								{
									["X-Correlation-ID"] = requestInfo.CorrelationID,
									["X-Clone-Date"] = requestInfo.GetParameter("x-clone-date"),
									["X-Clone-Date-By"] = requestInfo.GetParameter("x-clone-date-by"),
									["X-Clone-Min"] = requestInfo.GetParameter("x-clone-min"),
									["X-Clone-Max"] = requestInfo.GetParameter("x-clone-max"),
									["X-Clone-As-Set"] = requestInfo.ContainsKey("x-clone-as-set"),
									["X-Suffix"] = requestInfo.GetParameter("x-suffix")
								}
							}.Send(Router.GotBackupRouter());
					}

					if (requestInfo.ContainsKey("x-save"))
					{
						if (this.IsUpdater)
							this.Statistics.SaveAsync(this.CancellationToken).Execute(ex => this.Logger.LogInformation($"Error occurred while saving => {ex.Message}", ex));
						else
							new CommunicateMessage(this.ServiceName)
							{
								Type = "Statistics#Save"
							}.Send(Router.GotBackupRouter());
					}

					if (requestInfo.ContainsKey("x-reload"))
					{
						new CommunicateMessage(this.ServiceName)
						{
							Type = "Statistics#Reload",
							Data = new JObject
							{
								["X-Correlation-ID"] = requestInfo.CorrelationID,
								["X-Dont-Reload-Sessions"] = requestInfo.ContainsKey("x-dont-reload-sessions")
							}
						}.Send(Router.GotBackupRouter());
						if (Router.GotBackupRouter())
							this.ReloadStatisticsAsync(requestInfo.CorrelationID, !requestInfo.ContainsKey("x-dont-reload-sessions")).Execute(ex => this.Logger.LogInformation($"Error occurred while reloading => {ex.Message}", ex));
					}

					if (requestInfo.ContainsKey("x-dump"))
						await this.DumpStatisticsAsync(requestInfo.GetParameter("x-suffix"), Router.GotBackupRouter()).ConfigureAwait(false);

					if ((requestInfo.ContainsKey("x-blackip") || requestInfo.ContainsKey("x-blackips")) && !string.IsNullOrWhiteSpace(this.BlackIPsServiceName))
						new CommunicateMessage(this.BlackIPsServiceName)
						{
							Type = $"BlackIPs#{(requestInfo.ContainsKey("x-clear") || requestInfo.ContainsKey("x-reset") ? "Reset" : requestInfo.ContainsKey("x-remove") ? "Remove" : "Update")}",
							Data = requestInfo.ContainsKey("x-clear") || requestInfo.ContainsKey("x-reset") ? [] : (requestInfo.GetParameter("ips") ?? requestInfo.GetParameter("ip") ?? "").ToList().ToJArray()
						}.Send();

					else if ((requestInfo.ContainsKey("x-harmfulip") || requestInfo.ContainsKey("x-harmfulips")) && !string.IsNullOrWhiteSpace(this.BlackIPsServiceName))
						new CommunicateMessage(this.BlackIPsServiceName)
						{
							Type = $"HarmfulIPs#{(requestInfo.ContainsKey("x-pause") ? "Pause" : requestInfo.ContainsKey("x-resume") ? "Resume" : "Sync")}"
						}.Send();

					else if (requestInfo.ContainsKey("x-clear"))
					{
						new CommunicateMessage(this.ServiceName)
						{
							Type = "Session#Clear",
							ExcludedNodeID = this.NodeID
						}.Send(Router.GotBackupRouter());
						await this.Sessions.ClearAsync(this.IsUpdater ? ids => Utility.Cache.RemoveAsync(ids.Select(id => id.GetCacheKey<Session>()), cancellationToken) : null).ConfigureAwait(false);
					}

					if (requestInfo.ContainsKey("x-pause-harmful-request") && !string.IsNullOrWhiteSpace(this.BlackIPsServiceName))
						new CommunicateMessage(this.BlackIPsServiceName)
						{
							Type = "HarmfulIPs#Pause"
						}.Send();

					if (requestInfo.ContainsKey("x-resume-harmful-request") && !string.IsNullOrWhiteSpace(this.BlackIPsServiceName))
						new CommunicateMessage(this.BlackIPsServiceName)
						{
							Type = "HarmfulIPs#Resume"
						}.Send();

					if (requestInfo.ContainsKey("x-reset-blackips") && !string.IsNullOrWhiteSpace(this.BlackIPsServiceName))
						new CommunicateMessage(this.BlackIPsServiceName)
						{
							Type = "BlackIPs#Reset"
						}.Send();

					if (requestInfo.ContainsKey("x-enable-track"))
					{
						new CommunicateMessage("Portals") { Type = "Sessions#Track#Enable" }.Send();
						new CommunicateMessage("Files") { Type = "Sessions#Track#Enable" }.Send();
					}

					if (requestInfo.ContainsKey("x-disable-track"))
					{
						new CommunicateMessage("Portals") { Type = "Sessions#Track#Disable" }.Send();
						new CommunicateMessage("Files") { Type = "Sessions#Track#Disable" }.Send();
					}
				}

				return requestInfo.ObjectName.IsEquals("Visit.Statistics")
					? await this.ProcessVisitStatisticsAsync(requestInfo, cancellationToken).ConfigureAwait(false)
					: requestInfo.ObjectName.IsEquals("System.Statistics")
						? await this.ProcessSystemStatisticsAsync(requestInfo, cancellationToken).ConfigureAwait(false)
						: await this.ProcessSessionStatisticsAsync(requestInfo, isSystemAdministrator, cancellationToken).ConfigureAwait(false);
			}

			throw new MethodNotAllowedException(requestInfo.Verb);
		}

		async Task<JToken> ProcessVisitStatisticsAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (this.Statistics.Years.IsEmpty)
				await this.Statistics.LoadAsync(false, cancellationToken).ConfigureAwait(false);

			var asSummary = requestInfo.ContainsKey("x-sum") || requestInfo.ContainsKey("x-summary");
			var addDayDetails = !requestInfo.ContainsKey("x-no-day-details");
			var addHourDetails = addDayDetails && !requestInfo.ContainsKey("x-no-hour-details");
			
			var statistics = this.Statistics.ToJson(asSummary, addDayDetails, addHourDetails);
			var now = DateTime.Now;

			if (DateTime.TryParse($"{requestInfo.GetParameter("x-day")}T00:00:00".Left(19), out var specifiedDay) || DateTime.TryParse($"{requestInfo.GetParameter("x-month")}T00:00:00".Left(19), out var specifiedMonth))
			{
				var bySpecifiedMonth = DateTime.TryParse($"{requestInfo.GetParameter("x-month")}T00:00:00".Left(19), out specifiedMonth);
				if (bySpecifiedMonth)
					specifiedDay = specifiedMonth;

				var yearID = specifiedDay.Year.ToString("0000");
				this.Statistics.Years.Select(kvp => kvp.Key).ForEach(year =>
				{
					if (year != yearID)
						statistics.Remove(year);
				});

				var yearJson = statistics.Get<JObject>(yearID);
				var monthsJson = yearJson?.Get<JObject>("Months");
				for (var index = 1; index <= 12; index++)
				{
					if (index != specifiedDay.Month)
						(monthsJson ?? yearJson)?.Remove(index.ToString("00"));
				}

				var monthID = specifiedDay.Month.ToString("00");
				var monthJson = monthsJson?.Get<JObject>(monthID) ?? yearJson.Get<JObject>(monthID);
				var daysJson = monthsJson?.Get<JObject>(monthID)?.Get<JObject>("Days");
				if (!bySpecifiedMonth)
					for (var index = 1; index <= 31; index++)
					{
						if (index != specifiedDay.Day)
							(daysJson ?? monthJson)?.Remove(index.ToString("00"));
					}

				if (specifiedDay.Day == now.Day && specifiedDay.Month == now.Month && specifiedDay.Year == now.Year)
				{
					var hoursJson = daysJson?.Get<JObject>("Hours");
					if (hoursJson != null)
					{
						if (now.Hour < 23)
							for (var index = 23; index > now.Hour; index--)
								hoursJson.Remove(index.ToString("00"));

						var hourJson = specifiedDay.Hour == now.Hour && now.Minute < 59 ? hoursJson.Get<JObject>(now.Hour.ToString("00")) : null;
						if (hourJson != null)
							for (var index = 59; index > now.Minute; index--)
								hourJson.Remove(index.ToString("00"));
					}
				}
			}

			else
			{
				var yearID = now.Year.ToString("0000");
				var monthID = now.Month.ToString("00");
				var dayID = now.Day.ToString("00");
				var hourID = now.Hour.ToString("00");

				var daysJson = statistics.Get<JObject>(yearID)?.Get<JObject>("Months").Get<JObject>(monthID)?.Get<JObject>("Days")?.Get<JObject>(dayID);
				var hoursJson = daysJson?.Get<JObject>("Hours");
				if (hoursJson != null)
				{
					if (now.Hour <= 23)
						for (var index = 23; index > now.Hour; index--)
							hoursJson.Remove(index.ToString("00"));

					var hourJson = hoursJson.Get<JObject>(hourID);
					if (hourJson != null)
						for (var index = 59; index > now.Minute; index--)
							hourJson.Remove(index.ToString("00"));
				}
			}

			return statistics;
		}

		async Task<JToken> ProcessSystemStatisticsAsync(RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (!DateTime.TryParse(requestInfo.GetParameter("x-time"), out var time))
				time = DateTime.Now.AddMinutes(-1);

			var systemStatistics = await this.Statistics.GetSystemStatisticsAsync(time, cancellationToken).ConfigureAwait(false);
			return systemStatistics[time.Hour * 60 + time.Minute]?.GetString().ToJson(json => json["Time"] = time.ToIsoString()) ?? new JObject();
		}

		async Task<JToken> ProcessSessionStatisticsAsync(RequestInfo requestInfo, bool isSystemAdministrator, CancellationToken cancellationToken)
		{
			var ipAddressses = string.IsNullOrWhiteSpace(this.BlackIPsServiceName) || string.IsNullOrWhiteSpace(this.BlackIPsObjectName) || string.IsNullOrWhiteSpace(this.BlackIPsVerb)
				? new JObject
				{
					["BlackIPs"] = new JArray(),
					["HarmfulIPs"] = new JArray()
				}
				: await this.CallServiceAsync(new RequestInfo(requestInfo)
				{
					ServiceName = this.BlackIPsServiceName,
					ObjectName = this.BlackIPsObjectName,
					Verb = this.BlackIPsVerb
				}, cancellationToken).ConfigureAwait(false) as JObject;

			var sessions = this.Sessions.Get();

			if (requestInfo.TryGetParameter("x-user-id", out var userID))
				sessions = sessions.Where(info => userID.IsEquals(info.Session.UserID));
			else if (requestInfo.ContainsKey("x-user") || requestInfo.ContainsKey("x-authenticated"))
				sessions = sessions.Where(info => !string.IsNullOrWhiteSpace(info.Session.UserID));
			else if (requestInfo.ContainsKey("x-visitor") || requestInfo.ContainsKey("x-anonymous"))
				sessions = requestInfo.ContainsKey("x-crawler")
					? sessions.Where(info => string.IsNullOrWhiteSpace(info.Session.UserID))
					: sessions.Where(info => string.IsNullOrWhiteSpace(info.Session.UserID) && string.IsNullOrWhiteSpace(info.User.Name));
			else if (requestInfo.ContainsKey("x-crawler"))
				sessions = sessions.Where(info => string.IsNullOrWhiteSpace(info.Session.UserID) && "Crawler".IsEquals(info.User.Name));

			if (requestInfo.TryGetParameter("x-ip", out var ip))
				sessions = sessions.Where(info => info.Session.IP.IsStartsWith(ip));

			if (requestInfo.TryGetParameter("x-country", out var country))
				sessions = requestInfo.TryGetParameter("x-region", out var region)
					? sessions.Where(info => info.User.Location.IsEndsWith($"{region}, {country}"))
					: sessions.Where(info => info.User.Location.IsEndsWith(country));

			if (requestInfo.TryGetParameter("x-service", out var service))
			{
				sessions = sessions.Where(info => service.IsEquals(info.Service.Name));
				if (requestInfo.TryGetParameter("x-system-id", out var systemID))
					sessions = sessions.Where(info => systemID.IsEquals(info.Service.SystemID));
			}

			if (requestInfo.TryGetParameter("x-os", out var os))
				sessions = sessions.Where(info => info.Session.OSInfo.IsStartsWith(os));

			sessions = requestInfo.TryGetParameter("x-order-by", out var orderBy) && (orderBy.IsStartsWith("asc") || orderBy.IsStartsWith("old"))
				? sessions.OrderBy(info => info.LastAccess)
				: sessions.OrderByDescending(info => info.LastAccess);

			if (requestInfo.TryGetParameter("x-skip", out var skip) && Int32.TryParse(skip, out var skipRecords) && skipRecords > 0)
				sessions = sessions.Skip(skipRecords);

			if (requestInfo.TryGetParameter("x-max", out var max) && Int32.TryParse(max, out var maxRecords) && maxRecords > 0)
				sessions = sessions.Take(maxRecords);

			if (this.Statistics.Years.IsEmpty)
				await this.Statistics.LoadAsync(false, cancellationToken).ConfigureAwait(false);

			this.PrepareStatistics();
			var onlyStatistics = requestInfo.ContainsKey("x-statistics") || !isSystemAdministrator;
			var statistics = this.GetStatistics(onlyStatistics ? sessions : null, (_, statisticsJson) =>
			{
				var sessionsJson = statisticsJson;
				if (!onlyStatistics)
					sessionsJson["Sessions"] = sessions.Count();

				return new JObject
				{
					["Sessions"] = sessionsJson,
					["Visits"] = new JObject
					{
						["Total"] = this.LastStatistics.Total,
						["Year"] = this.LastStatistics.TotalOfCurrentYear,
						["Month"] = this.LastStatistics.TotalOfCurrentMonth,
						["Day"] = this.LastStatistics.TotalOfCurrentDay
					},
					["BlackIPs"] = ipAddressses.Get<JArray>("BlackIPs"),
					["HarmfulIPs"] = ipAddressses.Get<JArray>("HarmfulIPs")
				};
			});

			statistics = onlyStatistics
				? statistics
				: new JObject
				{
					["Statistics"] = statistics,
					["Sessions"] = sessions.ToList().Select(info => new JObject
					{
						["ID"] = info.Session.ID,
						["Time"] = info.LastAccess.ToIsoString(),
						["IP"] = info.Session.IP,
						["Location"] = info.User.Location,
						["User"] = string.IsNullOrWhiteSpace(info.Session.UserID) ? new JValue(info.User.Name ?? "Visitor") : info.User.ToJson(json =>
						{
							json["ID"] = info.Session.UserID;
							json.Remove("Location");
							json.Remove("LastAccess");
						}),
						["App"] = new JObject
						{
							["DeviceID"] = info.Session.DeviceID,
							["AppInfo"] = info.Session.AppInfo,
							["OSInfo"] = info.Session.OSInfo
						},
						["Service"] = info.Service.ToJson(json =>
						{
							if (string.IsNullOrWhiteSpace(info.Service.SystemID))
								json.Remove("SystemID");
						})
					}).ToJArray()
				};

			if (requestInfo.ContainsKey("x-latest") && isSystemAdministrator && !onlyStatistics)
			{
				var latest = new List<JObject>();
				var latestSessions = await Session.FindAsync(null, Sorts<Session>.Descending("RenewedAt"), requestInfo.TryGetParameter("x-latest", out var xlatest) && Int32.TryParse(xlatest, out var pageSize) && pageSize > 0 ? pageSize : 100, 1, null, false, null, 0, cancellationToken).ConfigureAwait(false);
				await latestSessions.ForEachAsync(async session =>
				{
					var profile = await Profile.GetAsync(session.UserID, cancellationToken).ConfigureAwait(false);
					latest.Add(new JObject
					{
						["ID"] = session.ID,
						["IP"] = session.IP,
						["User"] = $"{profile?.Name} - {profile?.Email}",
						["App"] = $"{session.AppInfo} - {session.OSInfo}",
						["Time"] = session.RenewedAt.ToIsoString(),
						["Elapsed"] = session.RenewedAt.GetElapsedTimes()
					});
				}, true, false).ConfigureAwait(false);
				statistics["Latest"] = latest.ToJArray();
			}

			return statistics;
		}

		JObject GetStatistics(IEnumerable<SessionInfo> sessions, Func<IEnumerable<SessionInfo>, JObject, JObject> transformer = null)
		{
			sessions ??= this.Sessions.Get();
			var total = 0;
			var user = 0;
			var crawler = 0;
			foreach (var sessionInfo in sessions)
			{
				total++;
				if (!string.IsNullOrWhiteSpace(sessionInfo.Session?.UserID))
					user++;
				else if ("Crawler".IsEquals(sessionInfo.User?.Name))
					crawler++;
			}
			var statistics = new JObject
			{
				["Total"] = total,
				["User"] = user,
				["Visitor"] = total - user - crawler,
				["Crawler"] = crawler
			};
			return transformer != null ? transformer(sessions, statistics) : statistics;
		}

		JObject SendStatistics()
		{
			if (this.Statistics.Years.IsEmpty)
				return new();

			var statistics = this.GetStatistics(null, (_, sessions) => new JObject
			{
				["Sessions"] = sessions,
				["Visits"] = new JObject
				{
					["Total"] = this.LastStatistics.Total,
					["Year"] = this.LastStatistics.TotalOfCurrentYear,
					["Month"] = this.LastStatistics.TotalOfCurrentMonth,
					["Day"] = this.LastStatistics.TotalOfCurrentDay
				}
			});

			new UpdateMessage
			{
				Type = "Users#Session#Statistics",
				DeviceID = "*",
				Data = statistics
			}.Send();
			return statistics;
		}

		void SendStatistics(bool isUpdater, bool sendRequestIfNot = true)
		{
			if (isUpdater)
				this.SendStatistics();

			else if (sendRequestIfNot)
				new CommunicateMessage(this.ServiceName)
				{
					Type = "VisitStatistics#Send",
					ExcludedNodeID = this.NodeID
				}.Send(Router.GotBackupRouter());
		}

		void PrepareStatistics()
			=> this.LastStatistics = (this.Statistics.Years.Values.Sum(year => year.Sum(true)), this.Statistics.TotalOfCurrentYear, this.Statistics.TotalOfCurrentMonth, this.Statistics.TotalOfCurrentDay);

		int TrackStatistics(JObject data = null)
			=> data != null ? this.Statistics.Update(data) : this.Statistics.Update();

		async Task LoadStatisticsAsync(bool isUpdater)
		{
			await Task.WhenAll
			(
				this.Statistics.LoadDumpStatisticsAsync(this.CancellationToken),
				this.Sessions.LoadDumpAsync(this.CancellationToken)
			).ConfigureAwait(false);
			this.SendSessionStatisticsSyncRequest();

			if (isUpdater)
			{
				await this.Statistics.LoadAsync(true, this.CancellationToken).ConfigureAwait(false);
				this.SendVisitStatistics();
			}
			this.SendVisitStatisticsSyncRequest();

			await Task.Delay(UtilityService.GetRandomNumber(2345, 3456), this.CancellationToken).ConfigureAwait(false);
			await this.Statistics.LoadAsync(false, this.CancellationToken).ConfigureAwait(false);
			this.PrepareStatistics();
			this.Logger?.LogInformation($"Statistics had been loaded {(this.IsUpdater ? this.GetDataLogsOfStatistics(() => this.SendStatistics()) : "")}");
		}

		Task DumpStatisticsAsync(bool all = false, string suffix = null)
			=> Task.WhenAll
			(
				this.Statistics.DumpVisitStatisticsAsync(all, this.CancellationToken, suffix),
				this.Statistics.DumpSystemStatisticsAsync(all, this.CancellationToken, suffix),
				this.Sessions.DumpAsync(this.CancellationToken)
			);

		Task DumpStatisticsAsync(string suffix, bool gotBackupRouter)
		{
			new CommunicateMessage(this.ServiceName)
			{
				Type = "Statistics#Dump",
				ExcludedNodeID = this.NodeID,
				Data = new JObject
				{
					["X-Suffix"] = suffix
				}
			}.Send(gotBackupRouter);
			return this.DumpStatisticsAsync(true, suffix);
		}

		async Task NormalizeStatisticsAsync(string cloneDate, string cloneDateBy, string cloneMin, string cloneMax, bool cloneAsSet, string suffix)
		{
			if (DateTime.TryParse($"{cloneDate}T00:00:00".Left(20), out var dateBeCloned) && DateTime.TryParse($"{cloneDateBy}T00:00:00".Left(20), out var dateCloneOf))
			{
				if (!Int32.TryParse(cloneMin, out var minCounters) || minCounters < 1)
					minCounters = 13;

				if (!Int32.TryParse(cloneMax, out var maxCounters) || maxCounters < 1)
					maxCounters = 99;

				var min = Math.Min(minCounters, maxCounters);
				var max = Math.Max(minCounters, maxCounters);

				var cloneOf = this.Statistics.GetDay(dateCloneOf.Day.ToString("00"), dateCloneOf.Month.ToString("00"), dateCloneOf.Year.ToString("0000"), false);
				var beCloned = this.Statistics.GetDay(dateBeCloned.Day.ToString("00"), dateBeCloned.Month.ToString("00"), dateBeCloned.Year.ToString("0000"), false);

				for (var hour = 0; hour < 24; hour++)
					for (var minute = 0; minute < 60; minute++)
					{
						var counter = cloneOf.Minutes[hour * 60 + minute] + UtilityService.GetRandomNumber(min, max);
						if (cloneAsSet)
							beCloned.Set(hour, minute, counter);
						else
							beCloned.Update(hour, minute, counter);
					}

				var info = (dateBeCloned.Year, dateBeCloned.Month.ToString("00"), beCloned);
				var systemStatistics = await this.Statistics.GetSystemStatisticsAsync(dateBeCloned, this.CancellationToken).ConfigureAwait(false);
				var instance = await Statistics.Info.LoadAsync(dateBeCloned, this.CancellationToken).ConfigureAwait(false);
				await Statistics.Info.SaveAsync(instance, info, systemStatistics, this.CancellationToken).ConfigureAwait(false);

				this.Logger?.LogInformation($"------------- Statistics were cloned [{dateCloneOf:yyyy-MM-dd} => {dateBeCloned:yyyy-MM-dd}] - Counters: {cloneOf.Sum():###,###,###,##0} => {beCloned.Sum():###,###,###,##0} {this.GetDataLogsOfStatistics()}");
				new CommunicateMessage(this.ServiceName)
				{
					Type = "Statistics#Reload",
					ExcludedNodeID = this.NodeID,
					Data = new JObject
					{
						["X-Dont-Reload-Sessions"] = true
					}
				}.Send(Router.GotBackupRouter());
				this.PrepareStatistics();
				this.SendStatistics();
			}

			else
			{
				this.Logger?.LogInformation("------------- Normalizing....");
				var counter = 0;
				var total = this.Statistics.Years.Values.Sum(year => year.Months.Values.Sum(month => month.Days.Count));
				foreach (var year in this.Statistics.Years.Values)
					foreach (var month in year.Months.Values)
						foreach (var day in month.Days.Values)
						{
							var info = (month.Year, Month: month.Name, Day: day);
							counter++;
							try
							{
								var instance = await Statistics.Info.LoadAsync(info, this.CancellationToken).ConfigureAwait(false);
								instance = instance != null
									? await Statistics.Info.SaveAsync(instance, info, instance._systemStatistics, this.CancellationToken).ConfigureAwait(false)
									: await Statistics.Info.SaveAsync(instance, info, this.Statistics.GetSystemStatistics(info), this.CancellationToken).ConfigureAwait(false);
								this.Logger?.LogInformation($"------ Normalized {counter:###,##0}/{total:###,##0} [#{instance.ID}] => {info.Day.Sum():###,###,##0} @ {info.Year:0000}-{info.Month}-{info.Day.Name}");
							}
							catch (Exception ex)
							{
								this.Logger?.LogInformation($"Error occurred while normalizing => {ex.Message}", ex);
							}
						}
				this.Logger?.LogInformation($"------------- Statistics had been normalized ({total:###,##0} records) {this.GetDataLogsOfStatistics()}");
				this.SendStatistics();
				new CommunicateMessage(this.ServiceName)
				{
					Type = "Statistics#Reload",
					ExcludedNodeID = this.NodeID,
					Data = new JObject
					{
						["X-Dont-Reload-Sessions"] = true
					}
				}.Send(Router.GotBackupRouter());
			}

			await this.DumpStatisticsAsync(suffix, Router.GotBackupRouter()).ConfigureAwait(false);
		}

		async Task ReloadStatisticsAsync(string correlationID, bool reloadSessions)
		{
			await this.Statistics.LoadAsync(false, this.CancellationToken, true, false).ConfigureAwait(false);
			this.PrepareStatistics();
			if (reloadSessions)
			{
				await this.Sessions.ReloadAsync(correlationID, this.CancellationToken).ConfigureAwait(false);
				await this.Sessions.CleanupAsync().ConfigureAwait(false);
			}
			this.Logger?.LogInformation($"Statistics had been re-loaded {(this.IsUpdater ? this.GetDataLogsOfStatistics(() => this.SendStatistics()) : "")}");
		}

		string GetDataLogsOfStatistics(System.Action onCompleted = null)
		{
			var logs = "";
			foreach (var year in this.Statistics.Years.Values.OrderByDescending(@object => @object.Name))
			{
				var yearLogs = "";
				foreach (var month in year.Months.Values.OrderByDescending(@object => @object.Name))
				{
					var monthLogs = "";
					foreach (var day in month.Days.Values.OrderByDescending(@object => @object.Name))
						monthLogs += $"\r\n--------------------- {year.Name}-{month.Name}-{day.Name} => {day.Sum():###,###,###,###0}";
					yearLogs += $"\r\n------------------ {year.Name}-{month.Name} - Number of days: {month.Days.Count} => {month.Sum():###,###,###,###,###,###0}" + monthLogs;
				}
				logs += (logs != "" ? "\r\n" : "") + $"------------- {year.Name} - Number of months: {year.Months.Count} => {year.Sum():###,###,###,###,###,###0}" + yearLogs;
			}
			logs = $"-------------\r\n"
				+ $"[{this.IsUpdater}] - Number of years: {this.Statistics.Years.Count:###,##0} - Number of months: {this.Statistics.Years.Values.Sum(year => year.Months.Count):###,##0} - Number of days: {this.Statistics.Years.Values.Sum(year => year.Months.Values.Sum(month => month.Days.Count)):###,##0}\r\n"
				+ $"------------- Counters - Total: {this.Statistics.Total:###,###,###,###,###,###,###,###0} | Year: {this.Statistics.TotalOfCurrentMonth:###,###,###,###,###,###,###,###0} | Month: {this.Statistics.TotalOfCurrentMonth:###,###,###,###,###,###,###,###0}\r\n{logs}";
			onCompleted?.Invoke();
			return logs;
		}

		void SendVisitStatistic(int counters, string minuteID, string hourID, string dayID = null, string monthID = null, string yearID = null)
			=> new CommunicateMessage(this.ServiceName)
			{
				Type = "VisitStatistics#Update",
				ExcludedNodeID = this.NodeID,
				Data = new JObject
				{
					["Year"] = yearID,
					["Month"] = monthID,
					["Day"] = dayID,
					["Hour"] = hourID,
					["Minute"] = minuteID,
					["Counters"] = counters
				}
			}.Send(Router.GotBackupRouter());

		void SendVisitStatistics(bool all = false)
		{
			if (all)
				this.Statistics.Years.Values.ForEach(year => year.Months.Values.ForEach(month => month.Days.Values.ForEach(day =>
				{
					for (var hour = 0; hour < 24; hour++)
						for (var minute = 0; minute < 60; minute++)
						{
							var minuteID = minute.ToString("00");
							var hourID = hour.ToString("00");
							var counters = this.Statistics.Get(minuteID, hourID, day.Name, month.Name, year.Name);
							this.SendVisitStatistic(counters, minuteID, hourID, day.Name, month.Name, year.Name);
						}
				})));
			else
			{
				var now = DateTime.Now;
				var yearID = now.Year.ToString("0000");
				var monthID = now.Month.ToString("00");
				var dayID = now.Day.ToString("00");
				var hourID = now.Hour.ToString("00");
				new[] {
					now.Minute < 5 ? null : $"{now.AddMinutes(-4):mm}",
					now.Minute < 4 ? null : $"{now.AddMinutes(-3):mm}",
					now.Minute < 3 ? null : $"{now.AddMinutes(-2):mm}",
					now.Minute < 2 ? null : $"{now.AddMinutes(-1):mm}",
					$"{now:mm}"
				}.Where(minuteID => minuteID != null).ToList().ForEach(minuteID =>
				{
					var counters = this.Statistics.Get(minuteID, hourID, dayID, monthID, yearID);
					this.SendVisitStatistic(counters, minuteID, hourID, dayID, monthID, yearID);
				});
			}
		}

		void SendVisitStatisticsSyncRequest(bool all = false)
			=> new CommunicateMessage(this.ServiceName)
			{
				Type = "VisitStatistics#Sync",
				ExcludedNodeID = this.NodeID,
				Data = new JObject
				{
					["All"] = all
				}
			}.Send(Router.GotBackupRouter());

		void SendSessionStatistic(SessionInfo sessionInfo)
			=> new CommunicateMessage(this.ServiceName)
			{
				Type = "SessionStatistics#Update",
				ExcludedNodeID = this.NodeID,
				Data = new JObject
				{
					["ID"] = sessionInfo.Session?.ID,
					["Session"] = sessionInfo.Session?.ToJson(),
					["User"] = sessionInfo.User?.ToJson(),
					["Service"] = sessionInfo.Service?.ToJson(),
					["LastAccess"] = sessionInfo.LastAccess
				}
			}.Send(Router.GotBackupRouter());

		void SendSessionStatistics(DateTime? checkpoint = null)
			=> this.Sessions.Get(checkpoint ?? DateTime.Now.AddMinutes(-15)).ForEach(this.SendSessionStatistic);

		void SendSessionStatisticsSyncRequest()
			=> new CommunicateMessage(this.ServiceName)
			{
				Type = "SessionStatistics#Sync",
				ExcludedNodeID = this.NodeID
			}.Send(Router.GotBackupRouter());
		#endregion

		#region Process communicate messages
		protected override async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message, CancellationToken cancellationToken = default)
		{
			if (message.Data is not JObject data)
				return;

			if (message.Type.IsEquals("Session#State") || message.Type.IsEquals("Session#Track"))
				this.Sessions.Track(data);

			else if (message.Type.IsEquals("Statistics#Track") || message.Type.IsEquals("VisitStatistics#Track"))
				this.TrackStatistics();

			else if (message.Type.IsEquals("VisitStatistics#Update"))
				this.TrackStatistics(data);

			else if (message.Type.IsEquals("VisitStatistics#Send") && this.IsUpdater)
				this.SendStatistics();

			else if (message.Type.IsEquals("VisitStatistics#Sync"))
				this.SendVisitStatistics(data.Get("All", false));

			else if (message.Type.IsEquals("SessionStatistics#Update"))
				this.Sessions.Update(data.Get<string>("ID"), new SessionInfo(data));

			else if (message.Type.IsEquals("SessionStatistics#Remove"))
				this.Sessions.Remove(data.Get<string>("ID"));

			else if (message.Type.IsEquals("SessionStatistics#Clear"))
				this.Sessions.ClearAsync(this.IsUpdater ? ids => Utility.Cache.RemoveAsync(ids.Select(id => id.GetCacheKey<Session>()), cancellationToken) : null).Execute(ex => this.Logger.LogInformation($"Error occurred while removing expired sessions => {ex.Message}", ex));

			else if (message.Type.IsEquals("SessionStatistics#Sync"))
				this.SendSessionStatistics();

			else if (message.Type.IsEquals("Statistics#Normalize") && this.IsUpdater)
				this.NormalizeStatisticsAsync(data.Get<string>("X-Clone-Date"), data.Get<string>("X-Clone-Date-By"), data.Get<string>("X-Clone-Min"), data.Get<string>("X-Clone-Max"), data.Get("X-Clone-As-Set", false), data.Get<string>("X-Suffix")).Execute(ex => this.Logger.LogInformation($"Error occurred while normalizing => {ex.Message}", ex));

			else if (message.Type.IsEquals("Statistics#Save") && this.IsUpdater)
				this.Statistics.SaveAsync(this.CancellationToken).Execute(ex => this.Logger.LogInformation($"Error occurred while saving => {ex.Message}", ex));

			else if (message.Type.IsEquals("Statistics#Reload"))
				this.ReloadStatisticsAsync(data.Get<string>("X-Correlation-ID"), !data.Get("X-Dont-Reload-Sessions", false)).Execute(ex => this.Logger.LogInformation($"Error occurred while reloading => {ex.Message}", ex));

			else if (message.Type.IsEquals("Statistics#Dump"))
				this.DumpStatisticsAsync(true, data.Get<string>("X-Suffix")).Execute(ex => this.Logger.LogInformation($"Error occurred while dumping JSONs => {ex.Message}", ex));

			if (this.IsDebugResultsEnabled)
				await this.WriteLogsAsync(data.Get<string>("CorrelationID") ?? data.Get<string>("X-Correlation-ID"), $"Got an inter-communicate message => {message.ToJson().AsString(this.JsonFormat)})", null, this.ServiceName, "Communicates", LogLevel.Warning).ConfigureAwait(false);
		}

		protected override Task ProcessGatewayCommunicateMessageAsync(CommunicateMessage message, CancellationToken cancellationToken = default)
		{
			if (message.Type.IsEquals("System#Statistics"))
				this.Statistics.UpdateSystemStatistics(message.Data);
			return Task.CompletedTask;
		}
		#endregion

		#region Timers for working with background workers & schedulers
		void RegisterTimers()
		{
			if (this.IsUpdater)
			{
				// send session statistics to controller
				var now = DateTime.Now;
				var time = now.AddMinutes(1);
				var delayMilliseconds = (int)(new DateTime(time.Year, time.Month, time.Day, time.Hour, time.Minute, 55) - now).TotalMilliseconds;
				this.StartTimer(() =>
				{
					new CommunicateMessage("APIGateway")
					{
						Type = "Session#Statistics",
						Data = this.GetStatistics(null)
					}.Send();
				}, 60, delayMilliseconds);

				// send visit statistics to clients
				delayMilliseconds = (int)(new DateTime(time.Year, time.Month, time.Day, time.Hour, time.Minute, 1) - now).TotalMilliseconds;
				this.StartTimer(() =>
				{
					this.PrepareStatistics();
					this.SendStatistics();
				}, this.UpdaterFrequency > 0 ? this.UpdaterFrequency : 60, delayMilliseconds);

				// sync statistics across nodes
				this.StartTimer(() =>
				{
					this.SendVisitStatistics();
					this.SendVisitStatisticsSyncRequest();
					this.SendSessionStatistics();
					this.SendSessionStatisticsSyncRequest();
				}, 5 * 60, delayMilliseconds);

				// persist statistics
				this.StartTimer(() => this.Statistics.SaveAsync(this.CancellationToken), 10 * 60);

				// clean expired sessions (12 hours)
				this.StartTimer(async () =>
				{
					var userID = UtilityService.GetAppSetting("Users:SystemAccountID", "VIEAppsNGX-MMXVII-System-Account");
					var sessions = await Session.FindAsync(Filters<Session>.LessThan("ExpiredAt", DateTime.Now), null, 0, 1, null, this.CancellationToken).ConfigureAwait(false) ?? [];
					await sessions.ForEachAsync(async session =>
					{
						await Session.DeleteAsync(session.ID, userID, this.CancellationToken).ConfigureAwait(false);
						this.Sessions.Remove(session.ID);
						new CommunicateMessage(this.ServiceName)
						{
							ExcludedNodeID = this.NodeID,
							Type = "SessionStatistics#Remove",
							Data = new JObject
							{
								["ID"] = session.ID
							}
						}.Send(Router.GotBackupRouter());
					}, true, false).ConfigureAwait(false);
				}, 12 * 60 * 60);
			}
			else
			{
				this.StartTimer(this.PrepareStatistics, 60);
				this.StartTimer(() => this.Statistics.Normalize(), 10 * 60);
			}

			// dump JSONs
			this.StartTimer(() => this.DumpStatisticsAsync().Execute(ex => this.Logger?.LogInformation($"Error occurred while dumping JSONs => {ex.Message}", ex)), 5 * 60);

			// clean-up
			this.StartTimer(() => this.Sessions.CleanupAsync(this.IsUpdater ? sessions => sessions.ForEachAsync(async sessionInfo =>
			{
				if (string.IsNullOrWhiteSpace(sessionInfo.Session.UserID))
				{
					var cacheKey = sessionInfo.Session.ID.GetCacheKey<Session>();
					var session = await Utility.Cache.GetAsync<Session>(cacheKey, this.CancellationToken).ConfigureAwait(false);
					if (session != null)
						await Utility.Cache.SetAsync(cacheKey, session, 15, this.CancellationToken).ConfigureAwait(false);
				}
			}, true, false) : null), 15 * 60);
		}

		protected override string OnMonitorAdditional()
		{
			if (DateTime.Now.Second < 50)
				return null;

			var visitStatistics = this.Statistics.GetDay();
			var systemStatistics = this.Statistics.GetSystemStatistics();
			return $"Updater: {this.IsUpdater} - Session statistics: {this.Sessions.Count:###,###0} - Visit statistics: {visitStatistics.Minutes.Count(counter => counter > 0):###,###0} - System statistics: {systemStatistics.Count(info => info != null):###,###0}\r\n--------------------";
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

		public override void DoWork(string[] args = null)
		{
			var writeDebugLogs = args?.FirstOrDefault(arg => arg.IsStartsWith("/logs")) != null;

			if (args?.FirstOrDefault(arg => arg.IsStartsWith("/reset-statistics")) != null)
				this.SendInterCommunicateMessage(new CommunicateMessage("APIGateway")
				{
					Type = "Statistics#Reset"
				}, false, writeDebugLogs);

			if (args?.FirstOrDefault(arg => arg.IsStartsWith("/rpc-gate-max")) != null || args?.FirstOrDefault(arg => arg.IsStartsWith("/change-rpc-gate")) != null)
			{
				var serviceName = args?.FirstOrDefault(arg => arg.IsStartsWith("/service:"))?.Replace("/service:", "", StringComparison.OrdinalIgnoreCase);
				var nodeID = args?.FirstOrDefault(arg => arg.IsStartsWith("/node:"))?.Replace("/node:", "", StringComparison.OrdinalIgnoreCase);
				var max = args?.FirstOrDefault(arg => arg.IsStartsWith("/max:"))?.Replace("/max:", "", StringComparison.OrdinalIgnoreCase);
				this.SendInterCommunicateMessage(new CommunicateMessage("APIGateway")
				{
					Type = "RpcGate#Max",
					Data = new JObject
					{
						["Service"] = serviceName,
						["NodeID"] = nodeID,
						["MaxCapacity"] = Int32.TryParse(max, out var maxCapacity) && maxCapacity > -1 && maxCapacity <= 20000 ? maxCapacity : 0
					}
				}, false, writeDebugLogs);
			}

			this.Logger?.LogWarning("Press ENTER to terminate...");
			Console.ReadLine();
		}

	}
}