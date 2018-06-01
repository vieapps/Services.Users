#region Related components
using System;
using System.Threading;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;

using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.Users.WindowsAD
{
	public class ServiceComponent : ServiceBase
	{
		public ServiceComponent() { }

		public override void Start(string[] args = null, bool initializeRepository = true, Func<ServiceBase, Task> nextAsync = null) => base.Start(args, false, nextAsync);

		public override string ServiceName => "WindowsAD";

		public override async Task<JObject> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
		{
			try
			{
				switch (requestInfo.Verb)
				{
					case "POST":
						return await UtilityService.ExecuteTask(() => this.SignIn(requestInfo), cancellationToken).ConfigureAwait(false);

					default:
						throw new InvalidRequestException($"The request is invalid [({requestInfo.Verb}): {requestInfo.URI}]");
				}
			}
			catch (Exception ex)
			{
				throw this.GetRuntimeException(requestInfo, ex);
			}
		}

		JObject SignIn(RequestInfo requestInfo)
		{
			// verify
			if (requestInfo.Extra == null || !requestInfo.Extra.ContainsKey("Signature") || !requestInfo.Extra["Signature"].Equals(requestInfo.Body.GetHMACSHA256(this.ValidationKey)))
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
	}
}