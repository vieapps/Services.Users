#region Related components
using System;
using System.Collections.Specialized;
using System.Threading.Tasks;

using Newtonsoft.Json.Linq;
using WampSharp.V2.Rpc;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.Users
{
	public class ServiceComponent : BaseService
	{

		#region Constructor & Destructor
		public ServiceComponent() { }

		~ServiceComponent()
		{
			this.Dispose();
		}

		internal void Start(string[] args = null, Func<Task> continueWith = null)
		{
			Task.Run(async () =>
			{
				try
				{
					await this.StartAsync(
						() => {
							Console.WriteLine("The service [" + this.ServiceURI + "] is registered");
						},
						(ex) => {
							Console.WriteLine("Error occurred while registering the service [" + this.ServiceURI + "]: " + ex.Message + "\r\n\r\n" + ex.StackTrace);
						},
						this.OnInterCommunicateMessageReceived
					);
				}
				catch (Exception ex)
				{
					Console.WriteLine("Error occurred while starting the service [" + this.ServiceURI + "]: " + ex.Message + "\r\n\r\n" + ex.StackTrace);
				}
			})
			.ContinueWith(async (task) =>
			{
				if (continueWith != null)
					await continueWith().ConfigureAwait(false);
			})
			.ConfigureAwait(false);
		}
		#endregion

		public override string ServiceName { get { return "users"; } }

		public override async Task<JObject> ProcessRequestAsync(RequestInfo requestInfo)
		{
			try
			{
				switch (requestInfo.ObjectName.ToLower())
				{
					case "session":
						switch (requestInfo.Verb)
						{
							case "GET":
								return await this.InitializeSessionAsync(requestInfo);

							default:
								throw new InvalidRequestException("Invalid [" + requestInfo.ServiceName + "." + requestInfo.ObjectName + "]");
						}

					default:
						throw new InvalidRequestException("Invalid [" + requestInfo.ServiceName + "." + requestInfo.ObjectName + "]");
				}
			}
			catch (Exception ex)
			{
				throw this.GetException(requestInfo,"Error occurred while processing with users ", ex);
			} 
		}

		#region Initialize keys
		public JObject GenerateKeys(RequestInfo requestInfo)
		{
			if (!requestInfo.Verb.IsEquals("get"))
				throw new InvalidRequestException();

			return new JObject()
			{
				{ "RSA",  new JObject()
					{
						{ "Exponent", Global.RSAExponent },
						{ "Modulus", Global.RSAModulus }
					}
				},
				{ "AES",  new JObject()
					{
						{ "Key", Global.GenerateEncryptionKey(requestInfo.Session.SessionID).ToHexa() },
						{ "IV", Global.GenerateEncryptionIV(requestInfo.Session.SessionID).ToHexa() }
					}
				},
				{ "JWT", Global.GenerateJWTKey() }
			};
		}
		#endregion

		#region Initialize session
		async Task<JObject> InitializeSessionAsync(RequestInfo requestInfo)
		{
			// prepare
			if (string.IsNullOrWhiteSpace(requestInfo.Session.SessionID))
				requestInfo.Session.SessionID = UtilityService.GetUUID();

			var deviceID = requestInfo.GetDeviceID();
			if (string.IsNullOrWhiteSpace(deviceID))
			{
				var appName = requestInfo.GetAppName();
				if (string.IsNullOrWhiteSpace(appName))
					appName = "N/A (" + UtilityService.NewUID + ")";

				var appPlatform = requestInfo.GetAppPlatform();
				if (string.IsNullOrWhiteSpace(appPlatform))
					appPlatform = "N/A (" + UtilityService.NewUID + ")";

				deviceID = "pwa@" + (appName + "/" + appPlatform + "@" + requestInfo.Session.AppAgent).GetHMACSHA256(requestInfo.Session.SessionID, true);
			}

			// update into cache to mark the session is issued by the system
			await Global.Cache.SetAbsoluteAsync("Session#" + requestInfo.Session.SessionID, deviceID + "|0");

			// response
			return new JObject()
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "DeviceID", deviceID }
			};
		}
		#endregion

		#region Register session
		#endregion

		#region Sign In
		public Task<JObject> SignBuiltInAccountInAsync(RequestInfo requestInfo)
		{
			return null;
		}
		#endregion

		void OnInterCommunicateMessageReceived(BaseMessage message)
		{

		}

	}
}