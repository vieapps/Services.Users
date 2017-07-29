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
	public class ServiceComponent : BaseService, IService, IDisposable
	{
		public string ServiceName { get { return "users"; } }

		#region Constructor & Destructor
		public ServiceComponent() { }

		~ServiceComponent()
		{
			this.Dispose();
		}

		internal void Start(string[] args = null)
		{
			Task.Run(async () =>
			{
				await this.StartAsync(
					() => {
						Console.WriteLine("The service [net.vieapps.services." + this.ServiceName + "] is registered");
					},
					(ex) => {
						Console.WriteLine("Error occurred while registering the service [net.vieapps.services." + this.ServiceName + "]: " + ex.Message + "\r\n\r\n" + ex.StackTrace);
					},
					this.OnInterCommunicateMessageReceived
				);
			}).ConfigureAwait(false);
		}
		#endregion

		[WampProcedure("net.vieapps.services.users")]
		public async Task<JObject> ProcessRequestAsync(RequestInfo requestInfo, NameValueCollection extra = null)
		{
			try
			{
				switch (requestInfo.ObjectName.ToLower())
				{
					case "session":
						switch (requestInfo.Verb)
						{
							case "GET":
								return await this.InitializeSessionAsync(requestInfo, extra);

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
		async Task<JObject> InitializeSessionAsync(RequestInfo requestInfo, NameValueCollection extra = null)
		{
			// prepare
			var sessionID = requestInfo.Session.SessionID;
			var deviceID = requestInfo.GetDeviceID();
			if (string.IsNullOrWhiteSpace(deviceID))
				deviceID = "pwa@" + requestInfo.Session.AppAgent.GetHMACSHA256(requestInfo.Session.SessionID, true);

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
		public Task<JObject> SignBuiltInAccountInAsync(RequestInfo requestInfo, NameValueCollection extra = null)
		{
			return null;
		}
		#endregion

		void OnInterCommunicateMessageReceived(BaseMessage message)
		{

		}

	}
}