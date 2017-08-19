#region Related components
using System;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.Configuration;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.Core.Listener;
using WampSharp.V2;
using WampSharp.V2.Realm;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.Users
{
	internal static class Global
	{
		internal static CancellationTokenSource CancellationTokenSource = new CancellationTokenSource();
		internal static Dictionary<string, IService> Services = new Dictionary<string, IService>();

		#region Get the app info
		internal static Tuple<string, string, string> GetAppInfo(NameValueCollection header, NameValueCollection query, string agentString, string ipAddress, Uri urlReferrer = null)
		{
			var name = UtilityService.GetAppParameter("x-app-name", header, query, "Generic App");

			var platform = UtilityService.GetAppParameter("x-app-platform", header, query);
			if (string.IsNullOrWhiteSpace(platform))
				platform = string.IsNullOrWhiteSpace(agentString)
					? "N/A"
					: agentString.IsContains("iPhone") || agentString.IsContains("iPad") || agentString.IsContains("iPod")
						? "iOS PWA"
						: agentString.IsContains("Android")
							? "Android PWA"
							: agentString.IsContains("Windows Phone")
								? "Windows Phone PWA"
								: agentString.IsContains("BlackBerry") || agentString.IsContains("BB10")
									? "BlackBerry PWA"
									: agentString.IsContains("IEMobile") || agentString.IsContains("Opera Mini")
										? "Mobile PWA"
										: "Desktop PWA";

			var origin = header?["origin"];
			if (string.IsNullOrWhiteSpace(origin))
				origin = urlReferrer?.AbsoluteUri;
			if (string.IsNullOrWhiteSpace(origin))
				origin = ipAddress;

			return new Tuple<string, string, string>(name, platform, origin);
		}

		internal static Tuple<string, string, string> GetAppInfo(this HttpContext context)
		{
			return Global.GetAppInfo(context.Request.Headers, context.Request.QueryString, context.Request.UserAgent, context.Request.UserHostAddress, context.Request.UrlReferrer);
		}
		#endregion

		#region Encryption keys
		static string _AESKey = null;

		/// <summary>
		/// Geths the key for working with AES
		/// </summary>
		internal static string AESKey
		{
			get
			{
				if (Global._AESKey == null)
					Global._AESKey = UtilityService.GetAppSetting("AESKey", "VIEApps-c98c6942-Default-0ad9-AES-40ed-Encryption-9e53-Key-65c501fcf7b3");
				return Global._AESKey;
			}
		}

		internal static byte[] GenerateEncryptionKey(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, false, 256);
		}

		internal static byte[] GenerateEncryptionIV(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, true, 128);
		}

		static string _JWTKey = null;

		/// <summary>
		/// Geths the key for working with JSON Web Token
		/// </summary>
		internal static string JWTKey
		{
			get
			{
				if (Global._JWTKey == null)
					Global._JWTKey = UtilityService.GetAppSetting("JWTKey", "VIEApps-49d8bd8c-Default-babc-JWT-43f4-Sign-bc30-Key-355b0891dc0f");
				return Global._JWTKey;
			}
		}

		internal static string GenerateJWTKey()
		{
			return Global.JWTKey.GetHMACSHA512(Global.AESKey).ToBase64Url(false, true);
		}

		static string _RSAKey = null;

		/// <summary>
		/// Geths the key for working with RSA
		/// </summary>
		internal static string RSAKey
		{
			get
			{
				if (Global._RSAKey == null)
					Global._RSAKey = UtilityService.GetAppSetting("RSAKey", "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");
				return Global._RSAKey;
			}
		}

		static RSACryptoServiceProvider _RSA = null;

		internal static RSACryptoServiceProvider RSA
		{
			get
			{
				if (Global._RSA == null)
					try
					{
						Global._RSA = CryptoService.CreateRSAInstance(Global.RSAKey.Decrypt());
					}
					catch (Exception)
					{
						throw;
					}
				return Global._RSA;
			}
		}

		static string _RSAExponent = null;

		internal static string RSAExponent
		{
			get
			{
				if (Global._RSAExponent == null)
				{
					var xmlDoc = new System.Xml.XmlDocument();
					xmlDoc.LoadXml(Global.RSA.ToXmlString(false));
					Global._RSAExponent = xmlDoc.DocumentElement.ChildNodes[1].InnerText.ToHexa(true);
				}
				return Global._RSAExponent;
			}
		}

		static string _RSAModulus = null;

		internal static string RSAModulus
		{
			get
			{
				if (Global._RSAModulus == null)
				{
					var xmlDoc = new System.Xml.XmlDocument();
					xmlDoc.LoadXml(Global.RSA.ToXmlString(false));
					Global._RSAModulus = xmlDoc.DocumentElement.ChildNodes[0].InnerText.ToHexa(true);
				}
				return Global._RSAModulus;
			}
		}
		#endregion

		#region WAMP channels
		internal static IWampChannel IncommingChannel = null, OutgoingChannel = null;
		internal static long IncommingChannelSessionID = 0, OutgoingChannelSessionID = 0;
		internal static bool ChannelAreClosedBySystem = false;

		static Tuple<string, string, bool> GetLocationInfo()
		{
			var address = UtilityService.GetAppSetting("RouterAddress", "ws://127.0.0.1:26429/");
			var realm = UtilityService.GetAppSetting("RouterRealm", "VIEAppsRealm");
			var mode = UtilityService.GetAppSetting("RouterChannelsMode", "MsgPack");
			return new Tuple<string, string, bool>(address, realm, mode.IsEquals("json"));
		}

		internal static async Task OpenIncomingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (Global.IncommingChannel != null)
				return;

			var info = Global.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			Global.IncommingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			Global.IncommingChannel.RealmProxy.Monitor.ConnectionEstablished += (sender, arguments) =>
			{
				Global.IncommingChannelSessionID = arguments.SessionId;
			};

			if (onConnectionEstablished != null)
				Global.IncommingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				Global.IncommingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				Global.IncommingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await Global.IncommingChannel.Open();
		}

		internal static void CloseIncomingChannel()
		{
			if (Global.IncommingChannel != null)
			{
				Global.IncommingChannel.Close("The incoming channel is closed when stop the User HTTP Service", new GoodbyeDetails());
				Global.IncommingChannel = null;
			}
		}

		internal static void ReOpenIncomingChannel(int delay = 0, System.Action onSuccess = null, Action<Exception> onError = null)
		{
			if (Global.IncommingChannel != null)
				(new WampChannelReconnector(Global.IncommingChannel, async () =>
				{
					if (delay > 0)
						await Task.Delay(delay);

					try
					{
						await Global.IncommingChannel.Open();
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				})).Start();
		}

		internal static async Task OpenOutgoingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (Global.OutgoingChannel != null)
				return;

			var info = Global.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			Global.OutgoingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			Global.OutgoingChannel.RealmProxy.Monitor.ConnectionEstablished += (sender, arguments) =>
			{
				Global.OutgoingChannelSessionID = arguments.SessionId;
			};

			if (onConnectionEstablished != null)
				Global.OutgoingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				Global.OutgoingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				Global.OutgoingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await Global.OutgoingChannel.Open();
		}

		internal static void CloseOutgoingChannel()
		{
			if (Global.OutgoingChannel != null)
			{
				Global.OutgoingChannel.Close("The outgoing channel is closed when stop the User HTTP Service", new GoodbyeDetails());
				Global.OutgoingChannel = null;
			}
		}

		internal static void ReOpenOutgoingChannel(int delay = 0, System.Action onSuccess = null, Action<Exception> onError = null)
		{
			if (Global.OutgoingChannel != null)
				(new WampChannelReconnector(Global.OutgoingChannel, async () =>
				{
					if (delay > 0)
						await Task.Delay(delay);

					try
					{
						await Global.OutgoingChannel.Open();
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				})).Start();
		}

		internal static async Task OpenChannelsAsync()
		{
			await Global.OpenIncomingChannelAsync(
				(sender, arguments) => {
					Global.WriteLogs("The incoming connection is established - Session ID: " + arguments.SessionId);
				},
				(sender, arguments) => {
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLogs("The incoming connection is broken because the router is not found or the router is refused - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
					else
					{
						if (Global.ChannelAreClosedBySystem)
							Global.WriteLogs("The incoming connection is closed - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
						else
							Global.ReOpenIncomingChannel(
								123,
								() => {
									Global.WriteLogs("Re-connect the incoming connection successful");
								},
								(ex) => {
									Global.WriteLogs("Error occurred while re-connecting the incoming connection", ex);
								}
							);
					}
				},
				(sender, arguments) => {
					Global.WriteLogs("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);

			await Global.OpenOutgoingChannelAsync(
				(sender, arguments) => {
					Global.WriteLogs("The outgoing connection is established - Session ID: " + arguments.SessionId);
				},
				(sender, arguments) => {
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLogs("The outgoing connection is broken because the router is not found or the router is refused - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
					else
					{
						if (Global.ChannelAreClosedBySystem)
							Global.WriteLogs("The outgoing connection is closed - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
						else
							Global.ReOpenOutgoingChannel(
								123,
								() => {
									Global.WriteLogs("Re-connect the outgoing connection successful");
								},
								(ex) => {
									Global.WriteLogs("Error occurred while re-connecting the outgoing connection", ex);
								}
							);
					}
				},
				(sender, arguments) => {
					Global.WriteLogs("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);
		}
		#endregion

		#region Working with logs
		internal static string GetCorrelationID(IDictionary items)
		{
			if (items == null)
				return UtilityService.GetUUID();

			var id = items.Contains("Correlation-ID")
				? items["Correlation-ID"] as string
				: null;

			if (string.IsNullOrWhiteSpace(id))
			{
				id = UtilityService.GetUUID();
				items.Add("Correlation-ID", id);
			}

			return id;
		}

		internal static string GetCorrelationID()
		{
			return Global.GetCorrelationID(HttpContext.Current?.Items);
		}

		static IManagementService ManagementService = null;

		internal static async Task InitializeManagementServiceAsync()
		{
			if (Global.ManagementService == null)
			{
				await Global.OpenOutgoingChannelAsync();
				Global.ManagementService = Global.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IManagementService>();
			}
		}

		internal static async Task WriteLogsAsync(string correlationID, List<string> logs, Exception exception = null)
		{
			// prepare
			var stack = "";
			if (exception != null)
			{
				stack = exception.StackTrace;
				var inner = exception.InnerException;
				int counter = 0;
				while (inner != null)
				{
					counter++;
					stack += "\r\n" + "-> Inner (" + counter.ToString() + "): ---->>>>" + "\r\n" + inner.StackTrace;
					inner = inner.InnerException;
				}
				stack += "\r\n" + "-------------------------------------" + "\r\n";
			}

			// write logs
			try
			{
				await Global.InitializeManagementServiceAsync();
				await Global.ManagementService.WriteLogsAsync(correlationID, "files", "http", logs, stack);
			}
			catch { }
		}

		internal static async Task WriteLogsAsync(string correlationID, string log, Exception exception = null)
		{
			var logs = !string.IsNullOrEmpty(log)
				? new List<string>() { log }
				: exception != null
					? new List<string>() { exception.Message + " [" + exception.GetType().ToString() + "]" }
					: new List<string>();
			await Global.WriteLogsAsync(correlationID, logs, exception);
		}

		internal static async Task WriteLogsAsync(List<string> logs, Exception exception = null)
		{
			await Global.WriteLogsAsync(Global.GetCorrelationID(), logs, exception);
		}

		internal static async Task WriteLogsAsync(string log, Exception exception = null)
		{
			await Global.WriteLogsAsync(Global.GetCorrelationID(), log, exception);
		}

		internal static void WriteLogs(string correlationID, List<string> logs, Exception exception = null)
		{
			Task.Run(async () =>
			{
				await Global.WriteLogsAsync(correlationID, logs, exception);
			}).ConfigureAwait(false);
		}

		internal static void WriteLogs(string correlationID, string log, Exception exception = null)
		{
			var logs = !string.IsNullOrEmpty(log)
				? new List<string>() { log }
				: exception != null
					? new List<string>() { exception.Message + " [" + exception.GetType().ToString() + "]" }
					: new List<string>();
			Global.WriteLogs(correlationID, logs, exception);
		}

		internal static void WriteLogs(List<string> logs, Exception exception = null)
		{
			Global.WriteLogs(Global.GetCorrelationID(), logs, exception);
		}

		internal static void WriteLogs(string log, Exception exception = null)
		{
			Global.WriteLogs(Global.GetCorrelationID(), log, exception);
		}
		#endregion

		#region Start/End the app
		internal static HashSet<string> HiddenSegments = null, BypassSegments = null, StaticSegments = null;

		internal static void OnAppStart(HttpContext context)
		{
			var stopwatch = new Stopwatch();
			stopwatch.Start();

			// Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// open WAMP channels
			Task.Run(async () =>
			{
				await Global.OpenChannelsAsync();
			}).ConfigureAwait(false);

			// special segments
			var segments = UtilityService.GetAppSetting("BypassSegments");
			Global.BypassSegments = string.IsNullOrWhiteSpace(segments)
				? new HashSet<string>()
				: segments.Trim().ToLower().ToHashSet('|', true);

			segments = UtilityService.GetAppSetting("HiddenSegments");
			Global.HiddenSegments = string.IsNullOrWhiteSpace(segments)
				? new HashSet<string>()
				: segments.Trim().ToLower().ToHashSet('|', true);

			segments = UtilityService.GetAppSetting("StaticSegments");
			Global.StaticSegments = string.IsNullOrWhiteSpace(segments)
				? new HashSet<string>()
				: segments.Trim().ToLower().ToHashSet('|', true);

			// handling unhandled exception
			AppDomain.CurrentDomain.UnhandledException += (sender, arguments) =>
			{
				Global.WriteLogs("An unhandled exception is thrown", arguments.ExceptionObject as Exception);
			};

			stopwatch.Stop();
			Global.WriteLogs("*** The User HTTP Service is ready for serving. The app is initialized in " + stopwatch.GetElapsedTimes());
		}

		internal static void OnAppEnd()
		{
			Global.CancellationTokenSource.Cancel();
			Global.ChannelAreClosedBySystem = true;
			Global.CloseIncomingChannel();
			Global.CloseOutgoingChannel();
		}
		#endregion

		#region Begin/End the request
		internal static void OnAppBeginRequest(HttpApplication app)
		{
			// update default headers to allow access from everywhere
			app.Context.Response.HeaderEncoding = Encoding.UTF8;
			app.Context.Response.Headers.Add("access-control-allow-origin", "*");
			app.Context.Response.Headers.Add("x-correlation-id", Global.GetCorrelationID(app.Context.Items));

			// update special headers on OPTIONS request
			if (app.Context.Request.HttpMethod.Equals("OPTIONS"))
			{
				app.Context.Response.Headers.Add("access-control-allow-methods", "HEAD,GET,POST,OPTIONS");

				var allowHeaders = app.Context.Request.Headers.Get("access-control-request-headers");
				if (!string.IsNullOrWhiteSpace(allowHeaders))
					app.Context.Response.Headers.Add("access-control-allow-headers", allowHeaders);

				return;
			}

			// decrypt session state cookie
			var cookie = app.Request.Cookies?[Global.StateCookieName];
			if (cookie != null)
				try
				{
					cookie.Value = cookie.Value.StartsWith("VIEApps|")
						? cookie.Value.ToArray('|', true).Last().Decrypt(Global.AESKey)
						: "";
				}
				catch
				{
					cookie.Value = "";
				}

			// prepare
			var requestTo = app.Request.AppRelativeCurrentExecutionFilePath;
			if (requestTo.StartsWith("~/"))
				requestTo = requestTo.Right(requestTo.Length - 2);
			requestTo = string.IsNullOrEmpty(requestTo)
				? ""
				: requestTo.ToLower().ToArray('/', true).First();

			// by-pass segments
			if (Global.BypassSegments.Count > 0 && Global.BypassSegments.Contains(requestTo))
				return;

			// hidden segments
			else if (Global.HiddenSegments.Count > 0 && Global.HiddenSegments.Contains(requestTo))
			{
				Global.ShowError(app.Context, 403, "Forbidden", "AccessDeniedException", null);
				app.Context.Response.End();
				return;
			}

			// 403/404 errors
			else if (requestTo.IsEquals("global.ashx"))
			{
				var errorElements = app.Context.Request.QueryString != null && app.Context.Request.QueryString.Count > 0
					? app.Context.Request.QueryString.ToString().UrlDecode().ToArray(';')
					: new string[] { "500", "" };
				var errorMessage = errorElements[0].Equals("403")
					? "Forbidden"
					: errorElements[0].Equals("404")
						? "Not Found"
						: "Unknown (" + errorElements[0] + " : " + (errorElements.Length > 1 ? errorElements[1].Replace(":80", "").Replace(":443", "") : "unknown") + ")";
				var errorType = errorElements[0].Equals("403")
					? "AccessDeniedException"
					: errorElements[0].Equals("404")
						? "FileNotFoundException"
						: "Unknown";
				Global.ShowError(app.Context, errorElements[0].CastAs<int>(), errorMessage, errorType, null);
				app.Context.Response.End();
				return;
			}

#if DEBUG || REQUESTLOGS
			var appInfo = app.Context.GetAppInfo();
			Global.WriteLogs(new List<string>() {
					"Begin process [" + app.Context.Request.HttpMethod + "]: " + app.Context.Request.Url.Scheme + "://" + app.Context.Request.Url.Host + app.Context.Request.RawUrl,
					"- Origin: " + appInfo.Item1 + " / " + appInfo.Item2 + " - " + appInfo.Item3,
					"- IP: " + app.Context.Request.UserHostAddress,
					"- Agent: " + app.Context.Request.UserAgent,
				});

			app.Context.Items["StopWatch"] = new Stopwatch();
			(app.Context.Items["StopWatch"] as Stopwatch).Start();
#endif

			// rewrite url
			var query = "";
			foreach (string key in app.Request.QueryString)
				if (!string.IsNullOrWhiteSpace(key))
					query += (query.Equals("") ? "" : "&") + key + "=" + app.Request.QueryString[key].UrlEncode();

			app.Context.RewritePath(app.Request.ApplicationPath + "Global.ashx", null, query);
		}

		internal static void OnAppEndRequest(HttpApplication app)
		{
			// encrypt session state cookie
			var cookie = app.Response.Cookies?[Global.StateCookieName];
			if (cookie != null && !string.IsNullOrWhiteSpace(cookie.Value))
				try
				{
					cookie.Value = "VIEApps|" + cookie.Value.Encrypt(Global.AESKey);
					cookie.HttpOnly = true;
				}
				catch { }

#if DEBUG || REQUESTLOGS
			// add execution times
			if (!app.Context.Request.HttpMethod.Equals("OPTIONS") && app.Context.Items.Contains("StopWatch"))
			{
				(app.Context.Items["StopWatch"] as Stopwatch).Stop();
				var executionTimes = (app.Context.Items["StopWatch"] as Stopwatch).GetElapsedTimes();
				Global.WriteLogs("End process - Execution times: " + executionTimes);
				try
				{
					app.Response.Headers.Add("x-execution-times", executionTimes);
				}
				catch { }
			}
#endif
		}

		static string _StateCookieName = null;

		internal static string StateCookieName
		{
			get
			{
				if (Global._StateCookieName == null)
				{
					var section = ConfigurationManager.GetSection("system.web/sessionState") as SessionStateSection;
					Global._StateCookieName = section != null && !string.IsNullOrWhiteSpace(section.CookieName)
						? section.CookieName
						: "ASP.NET_SessionId";
				}
				return Global._StateCookieName;
			}
		}
		#endregion

		#region Authenticate request
		public static void OnAppAuthenticateRequest(HttpApplication app)
		{
			if (app.Context.User == null || !(app.Context.User is UserPrincipal))
			{
				var authTicket = Global.GetAuthenticateTicket(app.Context);
				if (!string.IsNullOrWhiteSpace(authTicket))
				{
					var ticket = User.ParseAuthenticateToken(authTicket, Global.RSA, Global.AESKey);
					var userID = ticket.Item1;
					var accessToken = ticket.Item2;
					var sessionID = ticket.Item3;
					var deviceID = ticket.Item4;

					app.Context.User = new UserPrincipal(User.ParseAccessToken(accessToken, Global.RSA, Global.AESKey));
					app.Context.Items["Session-ID"] = sessionID;
					app.Context.Items["Device-ID"] = deviceID;
				}
				else
				{
					app.Context.User = new UserPrincipal();
					Global.GetSessionID(app.Context);
					Global.GetDeviceID(app.Context);
				}
			}
		}

		internal static void SetSessionID(HttpContext context, string sessionID)
		{
			context = context ?? HttpContext.Current;
			context.Items["Session-ID"] = sessionID;
			var cookie = new HttpCookie(".VIEApps-Authenticated-Session-ID")
			{
				Value = "VIEApps|" + sessionID.Encrypt(Global.AESKey),
				HttpOnly = true,
				Expires = DateTime.Now.AddDays(180)
			};
			context.Response.SetCookie(cookie);
		}

		internal static string GetSessionID(HttpContext context)
		{
			context = context ?? HttpContext.Current;
			if (!context.Items.Contains("Session-ID"))
			{
				var cookie = context.Request.Cookies?[".VIEApps-Authenticated-Session-ID"];
				if (cookie != null && cookie.Value.StartsWith("VIEApps|"))
					try
					{
						context.Items["Session-ID"] = cookie.Value.ToArray('|').Last().Decrypt(Global.AESKey);
					}
					catch { }
			}
			return context.Items["Session-ID"] as string;
		}

		internal static void SetDeviceID(HttpContext context, string sessionID)
		{
			context = context ?? HttpContext.Current;
			context.Items["Device-ID"] = sessionID;
			var cookie = new HttpCookie(".VIEApps-Authenticated-Device-ID")
			{
				Value = "VIEApps|" + sessionID.Encrypt(Global.AESKey),
				HttpOnly = true,
				Expires = DateTime.Now.AddDays(180)
			};
			context.Response.SetCookie(cookie);
		}

		internal static string GetDeviceID(HttpContext context)
		{
			context = context ?? HttpContext.Current;
			if (!context.Items.Contains("Device-ID"))
			{
				var cookie = context.Request.Cookies?[".VIEApps-Authenticated-Device-ID"];
				if (cookie != null && cookie.Value.StartsWith("VIEApps|"))
					try
					{
						context.Items["Device-ID"] = cookie.Value.ToArray('|').Last().Decrypt(Global.AESKey);
					}
					catch { }
			}
			return context.Items["Device-ID"] as string;
		}
		#endregion

		#region Pre excute handlers/send headers
		internal static void OnAppPreHandlerExecute(HttpApplication app)
		{
			// check
			if (app.Context.Request.HttpMethod.Equals("OPTIONS") || app.Context.Request.HttpMethod.Equals("HEAD"))
				return;

			// check
			var acceptEncoding = app.Context.Request.Headers["accept-encoding"];
			if (string.IsNullOrWhiteSpace(acceptEncoding))
				return;

			// apply compression
			var previousStream = app.Context.Response.Filter;

			// deflate
			if (acceptEncoding.IsContains("deflate") || acceptEncoding.Equals("*"))
			{
				app.Context.Response.Filter = new DeflateStream(previousStream, CompressionMode.Compress);
				app.Context.Response.Headers.Add("content-encoding", "deflate");
			}

			// gzip
			else if (acceptEncoding.IsContains("gzip"))
			{
				app.Context.Response.Filter = new GZipStream(previousStream, CompressionMode.Compress);
				app.Context.Response.Headers.Add("content-encoding", "gzip");
			}
		}

		internal static void OnAppPreSendHeaders(HttpApplication app)
		{
			// remove un-nessesary headers
			app.Context.Response.Headers.Remove("allow");
			app.Context.Response.Headers.Remove("public");
			app.Context.Response.Headers.Remove("x-powered-by");

			// add special headers
			if (app.Response.Headers["server"] != null)
				app.Response.Headers.Set("server", "VIEApps NGX");
			else
				app.Response.Headers.Add("server", "VIEApps NGX");
		}
		#endregion

		#region Error handlings
		static string ShowErrorStacks = null;

		internal static bool IsShowErrorStacks
		{
			get
			{
				if (string.IsNullOrWhiteSpace(Global.ShowErrorStacks))
#if DEBUG
					Global.ShowErrorStacks = "true";
#else
					Global.ShowErrorStacks = UtilityService.GetAppSetting("ShowErrorStacks", "false");
#endif
				return Global.ShowErrorStacks.IsEquals("true");
			}
		}

		internal static void ShowError(this HttpContext context, int code, string message, string type, string stack)
		{
			context.ShowHttpError(code, message, type, Global.GetCorrelationID(context.Items), stack, Global.IsShowErrorStacks);
		}

		internal static void ShowError(this HttpContext context, Exception exception)
		{
			context.ShowError(exception != null ? exception.GetHttpStatusCode() : 0, exception != null ? exception.Message : "Unknown", exception != null ? exception.GetType().ToString().ToArray('.').Last() : "Unknown", exception != null && Global.IsShowErrorStacks ? exception.StackTrace : null);
		}

		internal static void OnAppError(HttpApplication app)
		{
			var exception = app.Server.GetLastError();
			app.Server.ClearError();

			Global.WriteLogs("", exception);
			app.Context.ShowError(exception);
		}
		#endregion

		#region Session & Authentication
		internal static Services.Session GetSession(NameValueCollection header, NameValueCollection query, string agentString, string ipAddress, Uri urlReferrer = null)
		{
			var appInfo = Global.GetAppInfo(header, query, agentString, ipAddress, urlReferrer);
			return new Services.Session()
			{
				IP = ipAddress,
				AppAgent = agentString,
				DeviceID = UtilityService.GetAppParameter("x-device-id", header, query, ""),
				AppName = appInfo.Item1,
				AppPlatform = appInfo.Item2,
				AppOrigin = appInfo.Item3
			};
		}

		internal static Services.Session GetSession(HttpContext context = null)
		{
			context = context ?? HttpContext.Current;
			var session = Global.GetSession(context.Request.Headers, context.Request.QueryString, context.Request.UserAgent, context.Request.UserHostAddress, context.Request.UrlReferrer);
			session.User = context.User as User;
			if (string.IsNullOrWhiteSpace(session.SessionID))
				session.SessionID = Global.GetSessionID(context);
			if (string.IsNullOrWhiteSpace(session.DeviceID))
				session.DeviceID = Global.GetDeviceID(context);
			return session;
		}

		internal static string GetAuthenticateTicket (HttpContext context = null)
		{
			context = context ?? HttpContext.Current;
			var authCookie = context.Request.Cookies?[FormsAuthentication.FormsCookieName];
			return authCookie?.Value;
		}

		internal static async Task SignInAsync(HttpContext context = null)
		{
			// parse
			context = context ?? HttpContext.Current;
			var token = User.ParsePassportToken(context.Request.QueryString["x-passport-token"], Global.AESKey, Global.GenerateJWTKey());
			var userID = token.Item1;
			var accessToken = token.Item2;
			var sessionID = token.Item3;
			var deviceID = token.Item4;

			var ticket = User.ParseAuthenticateToken(accessToken, Global.RSA, Global.AESKey);
			accessToken = ticket.Item2;

			var user = User.ParseAccessToken(accessToken, Global.RSA, Global.AESKey);
			if (!user.ID.Equals(ticket.Item1) || !user.ID.Equals(userID))
				throw new InvalidTokenException("Token is invalid (User identity is invalid)");

			// validate
			var session = Global.GetSession(context);
			session.User = user;
			session.SessionID = sessionID;
			session.DeviceID = deviceID;
			if (!await session.ExistsAsync())
				throw new SessionNotFoundException();

			// assign user credential
			context.User = new UserPrincipal(user);

			var persistent = "persistent".Encrypt().Url64Encode().Equals(context.Request.QueryString["persistent"]);
			var cookie = new HttpCookie(FormsAuthentication.FormsCookieName)
			{
				Value = User.GetAuthenticateToken(userID, accessToken, sessionID, deviceID, FormsAuthentication.Timeout.Minutes, persistent),
				HttpOnly = true
			};
			if (persistent)
				cookie.Expires = DateTime.Now.AddDays(14);
			context.Response.SetCookie(cookie);

			// assign session/device identity
			Global.SetSessionID(context, sessionID);
			Global.SetDeviceID(context, deviceID);
		}

		internal static void SignOut(HttpContext context = null)
		{
			// perform sign out
			FormsAuthentication.Initialize();
			FormsAuthentication.SignOut();

			// parse
			context = context ?? HttpContext.Current;
			var token = User.ParsePassportToken(context.Request.QueryString["x-passport-token"], Global.AESKey, Global.GenerateJWTKey());
			var userID = token.Item1;
			var accessToken = token.Item2;
			var sessionID = token.Item3;
			var deviceID = token.Item4;

			// assign user credential
			context.User = new UserPrincipal();

			// assign session/device identity
			Global.SetSessionID(context, sessionID);
			Global.SetDeviceID(context, deviceID);
		}

		internal static async Task<bool> ExistsAsync(this Services.Session session)
		{
			var result = await Global.CallServiceAsync(session, "users", "mediator", "GET", null, null, new Dictionary<string, string>() { { "Exist", "" } });
			return result != null && result["Existed"] is JValue && (result["Existed"] as JValue).Value != null && (result["Existed"] as JValue).Value.CastAs<bool>() == true;
		}
		#endregion

		#region Get & call services
		internal static async Task<JObject> CallServiceAsync(RequestInfo requestInfo, string correlationID = null)
		{
			requestInfo.CorrelationID = correlationID ?? requestInfo.CorrelationID;
			var name = requestInfo.ServiceName.Trim().ToLower();

#if DEBUG
			Global.WriteLogs(requestInfo.CorrelationID, "Call the service [net.vieapps.services." + name + "]" + "\r\n" + requestInfo.ToJson().ToString(Formatting.Indented));
#endif

			if (!Global.Services.TryGetValue(name, out IService service))
			{
				await Global.OpenOutgoingChannelAsync();
				lock (Global.Services)
				{
					if (!Global.Services.TryGetValue(name, out service))
					{
						service = Global.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IService>(new CachedCalleeProxyInterceptor(new ProxyInterceptor(name)));
						Global.Services.Add(name, service);
					}
				}
			}

			JObject json = null;
			try
			{
				json = await service.ProcessRequestAsync(requestInfo, Global.CancellationTokenSource.Token);
			}
			catch (Exception)
			{
				throw;
			}

#if DEBUG
			Global.WriteLogs(requestInfo.CorrelationID, "Result of the service [net.vieapps.services." + name + "]" + "\r\n" + json.ToString(Formatting.Indented));
#endif

			return json;
		}

		internal static Task<JObject> CallServiceAsync(Services.Session session, string serviceName, string objectName, string verb = "GET", Dictionary<string, string> header = null, Dictionary<string, string> query = null, Dictionary<string, string> extra = null, string body = null, string correlationID = null)
		{
			return Global.CallServiceAsync(new RequestInfo(session)
			{
				ServiceName = serviceName,
				ObjectName = objectName,
				Verb = verb,
				Header = header,
				Query = query,
				Body = body,
				Extra = extra,
				CorrelationID = correlationID ?? Global.GetCorrelationID()
			});
		}

		internal static Task<JObject> CallServiceAsync(HttpContext context, string serviceName, string objectName, string verb = "GET", Dictionary<string, string> header = null, Dictionary<string, string> query = null, Dictionary<string, string> extra = null, string body = null)
		{
			context = context ?? HttpContext.Current;
			return Global.CallServiceAsync(Global.GetSession(context), serviceName, objectName, verb, header, query, extra, body, Global.GetCorrelationID(context.Items));
		}
		#endregion

	}

	// ------------------------------------------------------------------------------

	#region Global.ashx
	public class GlobalHandler : HttpTaskAsyncHandler
	{
		public override bool IsReusable { get { return true; } }

		public override async Task ProcessRequestAsync(HttpContext context)
		{
			// stop process request is OPTIONS
			if (context.Request.HttpMethod.Equals("OPTIONS"))
				return;

			// prepare
			var requestTo = context.Request.RawUrl.Substring(context.Request.ApplicationPath.Length);
			while (requestTo.StartsWith("/"))
				requestTo = requestTo.Right(requestTo.Length - 2);
			if (requestTo.IndexOf("?") > 0)
				requestTo = requestTo.Left(requestTo.IndexOf("?"));
			requestTo = string.IsNullOrEmpty(requestTo)
				? ""
				: requestTo.ToLower().ToArray('/', true).First();

			// static resources
			if (Global.StaticSegments.Contains(requestTo))
			{
				var path = context.Request.RawUrl;
				if (path.IndexOf("?") > 0)
					path = path.Left(path.IndexOf("?"));

				try
				{
					var contentType = path.IsEndsWith(".json") || path.IsEndsWith(".js")
						? "application/" + (path.IsEndsWith(".js") ? "javascript" : "json")
						: "text/"
							+ (path.IsEndsWith(".css")
								? "css"
								: path.IsEndsWith(".html") || path.IsEndsWith(".htm")
									? "html"
									: "plain");
					context.Response.Cache.SetNoStore();
					context.Response.ContentType = contentType;
					await context.Response.Output.WriteAsync(await UtilityService.ReadTextFileAsync(context.Server.MapPath(path)));
				}
				catch (FileNotFoundException ex)
				{
					context.ShowError((int)HttpStatusCode.NotFound, "Not found [" + path + "]", "FileNotFoundException", ex.StackTrace);
				}
				catch (Exception ex)
				{
					context.ShowError(ex);
				}
			}

			// session initializer (sign in)
			else if (requestTo.Equals("initializer"))
				await Initializer.ProcessRequestAsync(context);

			// session finalizer (sign out)
			else if (requestTo.Equals("finalizer"))
				await Finalizer.ProcessRequestAsync(context);

			// session validator
			else if (requestTo.Equals("validator"))
				await Validator.ProcessRequestAsync(context);

			// unknown
			else
				context.ShowError((int)HttpStatusCode.NotFound, "Not Found", "FileNotFoundException", null);
		}
	}
	#endregion

	#region Global.asax
	public class GlobalApp : HttpApplication
	{

		protected void Application_Start(object sender, EventArgs args)
		{
			Global.OnAppStart(sender as HttpContext);
		}

		protected void Application_BeginRequest(object sender, EventArgs args)
		{
			Global.OnAppBeginRequest(sender as HttpApplication);
		}

		protected void Application_AuthenticateRequest(object sender, EventArgs args)
		{
			Global.OnAppAuthenticateRequest(sender as HttpApplication);
		}

		protected void Application_PreRequestHandlerExecute(object sender, EventArgs args)
		{
			Global.OnAppPreHandlerExecute(sender as HttpApplication);
		}

		protected void Application_PreSendRequestHeaders(object sender, EventArgs args)
		{
			Global.OnAppPreSendHeaders(sender as HttpApplication);
		}

		protected void Application_EndRequest(object sender, EventArgs args)
		{
			Global.OnAppEndRequest(sender as HttpApplication);
		}

		protected void Application_Error(object sender, EventArgs args)
		{
			Global.OnAppError(sender as HttpApplication);
		}

		protected void Application_End(object sender, EventArgs args)
		{
			Global.OnAppEnd();
		}
	}
	#endregion

}