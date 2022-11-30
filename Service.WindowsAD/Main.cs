using System;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;

namespace net.vieapps.Services.Users.WindowsAD
{
	public class ServiceComponent : ServiceBase
	{
		public override string ServiceName => "WindowsAD";

		public override void Start(string[] args = null, bool initializeRepository = true, Action<IService> next = null)
		{
			this.Syncable = false;
			base.Start(args, false, next);
		}

		public override async Task<JToken> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default)
		{
			var stopwatch = Stopwatch.StartNew();
			await this.WriteLogsAsync(requestInfo, $"Begin request ({requestInfo.Verb} {requestInfo.GetURI()})").ConfigureAwait(false);
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

		JObject SignIn(RequestInfo requestInfo)
		{
			// verify
			if (requestInfo.Extra == null || !requestInfo.Extra.TryGetValue("Signature", out var signature) || !signature.Equals(requestInfo.Body.GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException();

			// prepare
			var requestBody = requestInfo.GetBodyExpando();
			var domain = requestBody.Get<string>("Domain").Decrypt(this.EncryptionKey).Trim();
			var username = requestBody.Get<string>("Username").Decrypt(this.EncryptionKey).Trim();
			var password = requestBody.Get<string>("Password").Decrypt(this.EncryptionKey);

			// perform sign-in with Windows Directory Service (when domain doesn't have dot (.) in the name, means local machine)
			try
			{
				using var context = new PrincipalContext(domain.IsContains(".") ? ContextType.Domain : ContextType.Machine, domain);
				return context.ValidateCredentials(username, password, ContextOptions.Negotiate) ? new JObject() : throw new WrongAccountException();
			}
			catch (Exception ex)
			{
				this.WriteLogs(requestInfo, $"Cannot perform sign-in with Windows AD => {ex.Message}", ex, Microsoft.Extensions.Logging.LogLevel.Error);
				throw;
			}
		}

		JObject ChangePassword(RequestInfo requestInfo)
		{
			// verify
			if (requestInfo.Extra == null || !requestInfo.Extra.TryGetValue("Signature", out var signature) || !signature.Equals(requestInfo.Body.GetHMACSHA256(this.ValidationKey)))
				throw new InformationInvalidException();

			// prepare
			var requestBody = requestInfo.GetBodyExpando();
			var domain = requestBody.Get<string>("Domain").Decrypt(this.EncryptionKey).Trim();
			var username = requestBody.Get<string>("Username").Decrypt(this.EncryptionKey).Trim();
			var password = requestBody.Get<string>("Password").Decrypt(this.EncryptionKey);
			var oldPassword = requestBody.Get<string>("OldPassword").Decrypt(this.EncryptionKey);

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