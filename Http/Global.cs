#region Related components
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
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

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;

using net.vieapps.Services.Base.AspNet;
#endregion

namespace net.vieapps.Services.Users
{
	public static partial class Global
	{

		internal static IDisposable InterCommunicateMessageUpdater = null;

		#region Start/End the app
		internal static void OnAppStart(HttpContext context)
		{
			var stopwatch = new Stopwatch();
			stopwatch.Start();

			// Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Newtonsoft.Json.Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// default service name
			Base.AspNet.Global.ServiceName = "Users";
			var correlationID = Base.AspNet.Global.GetCorrelationID(context?.Items);

			// open WAMP channels
			Task.Run(async () =>
			{
				await Base.AspNet.Global.OpenChannelsAsync(
					(sender, args) =>
					{
						Global.InterCommunicateMessageUpdater = Base.AspNet.Global.IncommingChannel.RealmProxy.Services
							.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.users")
							.Subscribe(
								async (message) =>
								{
									var relatedID = Base.AspNet.Global.GetCorrelationID();
									try
									{
										await Global.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false);
										await Task.WhenAll(
											Base.AspNet.Global.WriteDebugLogsAsync(relatedID, Base.AspNet.Global.ServiceName, $"Process an inter-communicate message successful\r\n{message?.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Newtonsoft.Json.Formatting.Indented : Newtonsoft.Json.Formatting.None)}"),
											Base.AspNet.Global.IsDebugLogEnabled ? Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU", $"Process an inter-communicate message successful\r\n{message?.ToJson().ToString(Newtonsoft.Json.Formatting.Indented)}") : Task.CompletedTask
										).ConfigureAwait(false);
									}
									catch (Exception ex)
									{
										await Task.WhenAll(
											Base.AspNet.Global.WriteDebugLogsAsync(relatedID, Base.AspNet.Global.ServiceName, $"Error occurred while processing an inter-communicate message\r\n{message?.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Newtonsoft.Json.Formatting.Indented : Newtonsoft.Json.Formatting.None)}", ex),
											Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU", $"Error occurred while processing an inter-communicate message\r\n{message?.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Newtonsoft.Json.Formatting.Indented : Newtonsoft.Json.Formatting.None)}", ex)
										).ConfigureAwait(false);
									}
								},
								async (exception) =>
								{
									var relatedID = Base.AspNet.Global.GetCorrelationID();
									await Task.WhenAll(
										Base.AspNet.Global.WriteDebugLogsAsync(relatedID, Base.AspNet.Global.ServiceName, "Error occurred while fetching inter-communicate message", exception),
										Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU", "Error occurred while fetching inter-communicate message", exception)
									).ConfigureAwait(false);
								}
							);
					},
					(sender, args) =>
					{
						Task.Run(async () =>
						{
							var relatedID = Base.AspNet.Global.GetCorrelationID();
							try
							{
								await Task.WhenAll(
									Base.AspNet.Global.InitializeLoggingServiceAsync(),
									Base.AspNet.Global.InitializeRTUServiceAsync()
								).ConfigureAwait(false);
								await Task.WhenAll(
									Base.AspNet.Global.WriteDebugLogsAsync(relatedID, "RTU", "Initializing helper services succesful"),
									Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU", "Initializing helper services succesful")
								).ConfigureAwait(false);
							}
							catch (Exception ex)
							{
								await Task.WhenAll(
									Base.AspNet.Global.WriteDebugLogsAsync(relatedID, "RTU", "Error occurred while initializing helper services", ex),
									Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU", "Error occurred while initializing helper services", ex)
								).ConfigureAwait(false);
							}
						}).ConfigureAwait(false);
					}
				).ConfigureAwait(false);
			}).ConfigureAwait(false);

			// handling unhandled exception
			AppDomain.CurrentDomain.UnhandledException += (sender, args) =>
			{
				Base.AspNet.Global.WriteDebugLogs(Base.AspNet.Global.GetCorrelationID(), Base.AspNet.Global.ServiceName, "An unhandled exception is thrown", args.ExceptionObject as Exception);
				Base.AspNet.Global.WriteLogs("An unhandled exception is thrown", args.ExceptionObject as Exception);
			};

			stopwatch.Stop();
			Task.Run(async () =>
			{
				await Task.Delay(345).ConfigureAwait(false);
				await Task.WhenAll(
					Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, $"*** The Users HTTP Service is ready for serving. The app is initialized in {stopwatch.GetElapsedTimes()}"),
					Base.AspNet.Global.IsInfoLogEnabled ? Base.AspNet.Global.WriteLogsAsync(correlationID, $"*** The Users HTTP Service is ready for serving. The app is initialized in {stopwatch.GetElapsedTimes()}") : Task.CompletedTask
				).ConfigureAwait(false);
			}).ConfigureAwait(false);
		}

		internal static void OnAppEnd()
		{
			Base.AspNet.Global.WriteDebugLogsAsync(UtilityService.NewUUID, Base.AspNet.Global.ServiceName, "Stop the Users HTTP Service...");
			Global.InterCommunicateMessageUpdater?.Dispose();
			Base.AspNet.Global.CancellationTokenSource.Cancel();
			Base.AspNet.Global.CancellationTokenSource.Dispose();
			Base.AspNet.Global.CloseChannels();
			Base.AspNet.Global.RSA.Dispose();
		}
		#endregion

		#region Begin/End the request
		internal static void OnAppBeginRequest(HttpApplication app)
		{
			// update default headers to allow access from everywhere
			app.Context.Response.HeaderEncoding = Encoding.UTF8;
			app.Context.Response.Headers.Add("access-control-allow-origin", "*");
			app.Context.Response.Headers.Add("x-correlation-id", Base.AspNet.Global.GetCorrelationID(app.Context.Items));

			// update special headers on OPTIONS request
			if (app.Context.Request.HttpMethod.Equals("OPTIONS"))
			{
				app.Context.Response.Headers.Add("access-control-allow-methods", "GET");

				var allowHeaders = app.Context.Request.Headers.Get("access-control-request-headers");
				if (!string.IsNullOrWhiteSpace(allowHeaders))
					app.Context.Response.Headers.Add("access-control-allow-headers", allowHeaders);

				return;
			}

			// prepare
			var requestTo = app.Request.AppRelativeCurrentExecutionFilePath;
			if (requestTo.StartsWith("~/"))
				requestTo = requestTo.Right(requestTo.Length - 2);
			requestTo = string.IsNullOrEmpty(requestTo)
				? ""
				: requestTo.ToLower().ToArray('/', true).First();

			var correlationID = Base.AspNet.Global.GetCorrelationID(app.Context.Items);

			// by-pass segments
			if (Base.AspNet.Global.BypassSegments.Count > 0 && Base.AspNet.Global.BypassSegments.Contains(requestTo))
			{
				Base.AspNet.Global.WriteDebugLogs(correlationID, Base.AspNet.Global.ServiceName, $"Bypass the request of by-pass segment [{app.Context.Request.RawUrl}]");
				return;
			}

			// hidden segments
			else if (Base.AspNet.Global.HiddenSegments.Count > 0 && Base.AspNet.Global.HiddenSegments.Contains(requestTo))
			{
				Base.AspNet.Global.WriteDebugLogs(correlationID, Base.AspNet.Global.ServiceName, $"Stop the request of hidden segment [{app.Context.Request.RawUrl}]");
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

			var appInfo = app.Context.GetAppInfo();
			var logs = new List<string>()
			{
				"Begin of request [" + app.Context.Request.HttpMethod + "]: " + app.Context.Request.Url.Scheme + "://" + app.Context.Request.Url.Host + app.Context.Request.RawUrl,
				"- Origin: " + appInfo.Item1 + " / " + appInfo.Item2 + " - " + appInfo.Item3,
				"- IP: " + app.Context.Request.UserHostAddress,
				"- Agent: " + app.Context.Request.UserAgent,
			};
			Base.AspNet.Global.WriteDebugLogs(correlationID, Base.AspNet.Global.ServiceName, logs);

			// diagnostics
			if (Base.AspNet.Global.IsInfoLogEnabled)
			{
				app.Context.Items["StopWatch"] = new Stopwatch();
				(app.Context.Items["StopWatch"] as Stopwatch).Start();
			}

			// rewrite url
			var url = app.Request.ApplicationPath + "Global.ashx?";
			foreach (string key in app.Request.QueryString)
				if (!string.IsNullOrWhiteSpace(key))
					url += $"{key}={app.Request.QueryString[key].UrlEncode()}&";

			if (Base.AspNet.Global.IsInfoLogEnabled)
			{
				if (Base.AspNet.Global.IsDebugLogEnabled)
					logs.Add($"Rewrite URL: [{app.Context.Request.Url.Scheme}://{app.Context.Request.Url.Host + app.Context.Request.RawUrl}] => [{app.Context.Request.Url.Scheme}://{app.Context.Request.Url.Host + url.Left(url.Length - 1)}]");
				Base.AspNet.Global.WriteLogs(logs);
			}

			app.Context.RewritePath(url.Left(url.Length - 1));
		}

		internal static void OnAppEndRequest(HttpApplication app)
		{
			var executionTimes = "";
			if (Base.AspNet.Global.IsInfoLogEnabled && app.Context.Items.Contains("StopWatch"))
			{
				(app.Context.Items["StopWatch"] as Stopwatch).Stop();
				executionTimes = $" - Execution times: {(app.Context.Items["StopWatch"] as Stopwatch).GetElapsedTimes()}";
				Base.AspNet.Global.WriteLogs($"End of request{executionTimes}");
				try
				{
					app.Response.Headers.Add("x-execution-times", executionTimes);
				}
				catch { }
			}
			Base.AspNet.Global.WriteDebugLogs(Base.AspNet.Global.GetCorrelationID(), Base.AspNet.Global.ServiceName, $"End of request{executionTimes}");
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
					var ticket = AspNetSecurityService.ParseAuthenticateToken(authTicket, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey);
					var userID = ticket.Item1;
					var accessToken = ticket.Item2;
					var sessionID = ticket.Item3;
					var deviceID = ticket.Item4;

					app.Context.User = new UserPrincipal(accessToken.ParseAccessToken(Base.AspNet.Global.ECCKey));
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
				Value = "VIEApps|" + sessionID.Encrypt(Base.AspNet.Global.EncryptionKey),
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
						context.Items["Session-ID"] = cookie.Value.ToArray('|').Last().Decrypt(Base.AspNet.Global.EncryptionKey);
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
				Value = "VIEApps|" + sessionID.Encrypt(Base.AspNet.Global.EncryptionKey),
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
						context.Items["Device-ID"] = cookie.Value.ToArray('|').Last().Decrypt(Base.AspNet.Global.EncryptionKey);
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
			context.ShowHttpError(code, message, type, Base.AspNet.Global.GetCorrelationID(context.Items), stack, Global.IsShowErrorStacks);
		}

		internal static void ShowError(this HttpContext context, Exception exception)
		{
			context.ShowError(exception != null ? exception.GetHttpStatusCode() : 0, exception != null ? exception.Message : "Unknown", exception != null ? exception.GetType().ToString().ToArray('.').Last() : "Unknown", exception != null && Global.IsShowErrorStacks ? exception.StackTrace : null);
		}

		internal static void OnAppError(HttpApplication app)
		{
			var exception = app.Server.GetLastError();
			app.Server.ClearError();

			Base.AspNet.Global.WriteLogs("Got an error while processing", exception);
			app.Context.ShowError(exception);
		}
		#endregion

		#region Call services
		internal static Task<JObject> CallServiceAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
		{
			var name = $"net.vieapps.services.{requestInfo?.ServiceName}".ToLower();
			return Base.AspNet.Global.CallServiceAsync(requestInfo, cancellationToken,
				(info) =>
				{
					if (Base.AspNet.Global.IsDebugLogEnabled)
						Base.AspNet.Global.WriteLogs(info.CorrelationID, null, $"Call the service [{name}]\r\n{info?.ToJson().ToString(Newtonsoft.Json.Formatting.Indented)}");
				},
				(info, json) =>
				{
					if (Base.AspNet.Global.IsDebugLogEnabled)
						Base.AspNet.Global.WriteLogs(info.CorrelationID, null, $"Results from the service [{name}]\r\n{json?.ToString(Newtonsoft.Json.Formatting.Indented)}");
				},
				(info, ex) =>
				{
					if (Base.AspNet.Global.IsDebugLogEnabled)
						Base.AspNet.Global.WriteLogs(info.CorrelationID, null, $"Error occurred while calling the service [{name}]", ex);
				}
			);
		}

		internal static Task<JObject> CallServiceAsync(Services.Session session, string serviceName, string objectName, string verb = "GET", Dictionary<string, string> query = null, Dictionary<string, string> header = null, string body = null, Dictionary<string, string> extra = null, string correlationID = null)
		{
			return Global.CallServiceAsync(new RequestInfo(session ?? Global.GetSession(), serviceName, objectName, verb, query, header, body, extra, correlationID ?? Base.AspNet.Global.GetCorrelationID()));
		}

		internal static Task<JObject> CallServiceAsync(HttpContext context, string serviceName, string objectName, string verb = "GET", Dictionary<string, string> query = null, Dictionary<string, string> header = null, string body = null, Dictionary<string, string> extra = null)
		{
			context = context ?? HttpContext.Current;
			return Global.CallServiceAsync(Global.GetSession(context), serviceName, objectName, verb, query, header, body, extra, Base.AspNet.Global.GetCorrelationID(context.Items));
		}
		#endregion

		#region Session & Authentication
		internal static Services.Session GetSession(NameValueCollection header, NameValueCollection query, string agentString, string ipAddress, Uri urlReferrer = null)
		{
			var appInfo = Base.AspNet.Global.GetAppInfo(header, query, agentString, ipAddress, urlReferrer);
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
			session.User = context.User as UserIdentity;
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
			/*
			// parse
			context = context ?? HttpContext.Current;
			var token = context.Request.QueryString["x-passport-token"].ParsePassportToken(Base.AspNet.Global.EncryptionKey, Base.AspNet.Global.JWTKey, Base.AspNet.Global.ECCKey);
			var userID = token.Item1;
			var accessToken = token.Item2;
			var sessionID = token.Item3;
			var deviceID = token.Item4;

			var ticket = AspNetSecurityService.ParseAuthenticateToken(accessToken, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey);
			accessToken = ticket.Item2;

			var user = User.ParseAccessToken(accessToken, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey);
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
				Value = AspNetSecurityService.GetAuthenticateToken(userID, accessToken, sessionID, deviceID, FormsAuthentication.Timeout.Minutes, persistent),
				HttpOnly = true
			};
			if (persistent)
				cookie.Expires = DateTime.Now.AddDays(14);
			context.Response.SetCookie(cookie);

			// assign session/device identity
			Global.SetSessionID(context, sessionID);
			Global.SetDeviceID(context, deviceID);
			*/
		}

		internal static void SignOut(HttpContext context = null)
		{
			// perform sign out
			FormsAuthentication.Initialize();
			FormsAuthentication.SignOut();

			/*
			// parse
			context = context ?? HttpContext.Current;
			var token = User.ParsePassportToken(context.Request.QueryString["x-passport-token"], Base.AspNet.Global.EncryptionKey, Base.AspNet.Global.JWTKey);
			var userID = token.Item1;
			var accessToken = token.Item2;
			var sessionID = token.Item3;
			var deviceID = token.Item4;

			// assign user credential
			context.User = new UserPrincipal();

			// assign session/device identity
			Global.SetSessionID(context, sessionID);
			Global.SetDeviceID(context, deviceID);
			*/
		}

		internal static async Task<bool> ExistsAsync(this Services.Session session)
		{
			var result = await Global.CallServiceAsync(session, "users", "session");
			return result != null && result["ID"] is JValue && session.SessionID.IsEquals((result["ID"] as JValue).Value as string);
		}
		#endregion

		#region Send & process inter-communicate message
		internal static async Task SendInterCommunicateMessageAsync(CommunicateMessage message)
		{
			try
			{
				await Base.AspNet.Global.RTUService.SendInterCommunicateMessageAsync(message, Base.AspNet.Global.CancellationTokenSource.Token).ConfigureAwait(false);
			}
			catch { }
		}

		static Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			return Task.CompletedTask;
		}
		#endregion

	}

	// ------------------------------------------------------------------------------

	#region Global.ashx
	public class GlobalHandler : HttpTaskAsyncHandler
	{
		public GlobalHandler() : base() { }

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
			if (Base.AspNet.Global.StaticSegments.Contains(requestTo))
			{
				// check "If-Modified-Since" request to reduce traffict
				var eTag = "StaticResource#" + context.Request.RawUrl.ToLower().GetMD5();
				if (context.Request.Headers["If-Modified-Since"] != null && eTag.Equals(context.Request.Headers["If-None-Match"]))
				{
					context.Response.Cache.SetCacheability(HttpCacheability.Public);
					context.Response.StatusCode = (int)HttpStatusCode.NotModified;
					context.Response.StatusDescription = "Not Modified";
					context.Response.Headers.Add("ETag", "\"" + eTag + "\"");
					return;
				}

				// prepare
				var path = context.Request.RawUrl;
				if (path.IndexOf("?") > 0)
					path = path.Left(path.IndexOf("?"));

				try
				{
					// check exist
					var fileInfo = new FileInfo(context.Server.MapPath(path));
					if (!fileInfo.Exists)
						throw new FileNotFoundException();

					// set cache policy
					context.Response.Cache.SetCacheability(HttpCacheability.Public);
					context.Response.Cache.SetExpires(DateTime.Now.AddDays(1));
					context.Response.Cache.SetSlidingExpiration(true);
					context.Response.Cache.SetOmitVaryStar(true);
					context.Response.Cache.SetValidUntilExpires(true);
					context.Response.Cache.SetLastModified(fileInfo.LastWriteTime);
					context.Response.Cache.SetETag(eTag);

					// prepare content
					var staticMimeType = MimeMapping.GetMimeMapping(fileInfo.Name);
					if (string.IsNullOrWhiteSpace(staticMimeType))
						staticMimeType = "text/plain";
					var staticContent = await UtilityService.ReadTextFileAsync(fileInfo).ConfigureAwait(false);
					if (staticMimeType.IsEndsWith("json"))
						staticContent = JObject.Parse(staticContent).ToString(Formatting.Indented);

					// write content
					context.Response.ContentType = staticMimeType;
					await context.Response.Output.WriteAsync(staticContent).ConfigureAwait(false);
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