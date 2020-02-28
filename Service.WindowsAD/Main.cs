using System;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;

namespace net.vieapps.Services.Users.WindowsAD
{
	public class ServiceComponent : ServiceBase
	{
		public override string ServiceName => "WindowsAD";

		public override void Start(string[] args = null, bool initializeRepository = true, Action<IService> next = null)
			=> base.Start(args, false, next);

		public override Task<JToken> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default)
		{
			var stopwatch = Stopwatch.StartNew();
			this.WriteLogs(requestInfo, $"Begin request ({requestInfo.Verb} {requestInfo.GetURI()})");
			try
			{
				JToken json = null;
				switch (requestInfo.Verb)
				{
					case "POST":
						json = this.SignIn(requestInfo);
						break;

					case "PUT":
						json = this.ChangePassword(requestInfo);
						break;

					default:
						throw new InvalidRequestException($"The request is invalid [({requestInfo.Verb}): {requestInfo.GetURI()}]");
				}
				stopwatch.Stop();
				this.WriteLogs(requestInfo, $"Success response - Execution times: {stopwatch.GetElapsedTimes()}");
				if (this.IsDebugResultsEnabled)
					this.WriteLogs(requestInfo,
						$"- Request: {requestInfo.ToString(this.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
						$"- Response: {json?.ToString(this.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
					);
				return Task.FromResult(json);
			}
			catch (Exception ex)
			{
				return Task.FromException<JToken>(this.GetRuntimeException(requestInfo, ex, stopwatch));
			}
		}

		JObject SignIn(RequestInfo requestInfo)
		{
			// verify
			if (requestInfo.Extra == null || !requestInfo.Extra.TryGetValue("Signature", out var signature) || !signature.Equals(requestInfo.Body.GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException();

			// prepare
			var body = requestInfo.GetBodyExpando();
			var domain = body.Get<string>("Domain").Decrypt(this.EncryptionKey).Trim();
			var username = body.Get<string>("Username").Decrypt(this.EncryptionKey).Trim();
			var password = body.Get<string>("Password").Decrypt(this.EncryptionKey);

			// perform sign-in with Windows Directory Service (when domain doesn't got dot (.) in the name, means local machine)
			using (var context = new PrincipalContext(domain.PositionOf(".") < 0 ? ContextType.Machine : ContextType.Domain, domain))
			{
				if (!context.ValidateCredentials(username, password, ContextOptions.Negotiate))
					throw new WrongAccountException();
			}

			return new JObject();
		}

		JObject ChangePassword(RequestInfo requestInfo)
		{
			// verify
			if (requestInfo.Extra == null || !requestInfo.Extra.TryGetValue("Signature", out var signature) || !signature.Equals(requestInfo.Body.GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException();

			// prepare
			var body = requestInfo.GetBodyExpando();
			var domain = body.Get<string>("Domain").Decrypt(this.EncryptionKey).Trim();
			var username = body.Get<string>("Username").Decrypt(this.EncryptionKey).Trim();
			var password = body.Get<string>("Password").Decrypt(this.EncryptionKey);
			var oldPassword = body.Get<string>("OldPassword").Decrypt(this.EncryptionKey);

			// perform sign-in and change password with Windows Directory Service (when domain doesn't got dot (.) in the name, means local machine)
			using (var context = new PrincipalContext(domain.PositionOf(".") < 0 ? ContextType.Machine : ContextType.Domain, domain))
			{
				if (context.ValidateCredentials(username, oldPassword, ContextOptions.Negotiate))
					using (var user = System.DirectoryServices.AccountManagement.UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username))
					{
						user.ChangePassword(oldPassword, password);
						user.Save();
					}
				else
					throw new WrongAccountException();
			}

			return new JObject();
		}
	}
}