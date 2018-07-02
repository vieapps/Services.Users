#region Related components
using System;
using System.Net;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Caching;
using net.vieapps.Components.Security;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.Users
{
	public class Handler
	{
		HashSet<string> SpecialRequests { get; } = "initializer,validator,signout".ToHashSet();

		bool AlwaysUseSecureConnections { get; set; } = "true".IsEquals(UtilityService.GetAppSetting("AlwaysUseSecureConnections", "false"));

		string UniqueHostname { get; set; } = UtilityService.GetAppSetting("UniqueHostname", "");

		RequestDelegate Next { get; }

		public Handler(RequestDelegate next) => this.Next = next;

		public async Task Invoke(HttpContext context)
		{
			// prepare
			var requestUri = context.GetRequestUri();
			var requestPath = requestUri.GetRequestPathSegments(true).First();

			// load balancing health check
			if (context.Request.Path.Value.IsEquals("/load-balancing-health-check"))
				await context.WriteAsync("OK", "text/plain", null, 0, null, TimeSpan.Zero, null, Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// request to favicon.ico file
			else if (requestPath.IsEquals("favicon.ico"))
				context.ShowHttpError((int)HttpStatusCode.NotFound, "Not Found", "FileNotFoundException", context.GetCorrelationID());

			// request to static segments
			else if (Global.StaticSegments.Contains(requestPath))
				await context.ProcessStaticFileRequestAsync().ConfigureAwait(false);

			else if (this.UniqueHostname != "" && !requestUri.Host.IsEquals(this.UniqueHostname))
				context.Redirect($"{(this.AlwaysUseSecureConnections ? "https://" : "http://")}{this.UniqueHostname}{requestUri.PathAndQuery}");

			else if (this.AlwaysUseSecureConnections && !requestUri.Scheme.IsEquals("https"))
				context.Redirect($"{requestUri}".Replace("http://", "https://"));

			// special requests: initializer, validator
			else if (this.SpecialRequests.Contains(requestPath))
			{
				context.Items["PipelineStopwatch"] = Stopwatch.StartNew();
				context.Response.Headers["Access-Control-Allow-Origin"] = "*";
				switch (requestPath)
				{
					case "initializer":
						await this.ProcessInitializerRequestAsync(context).ConfigureAwait(false);
						break;

					case "validator":
						await this.ProcessValidatorRequestAsync(context).ConfigureAwait(false);
						break;

					default:
						await this.ProcessSignOutRequestAsync(context).ConfigureAwait(false);
						break;
				}
			}

			// set headers & invoke next middleware
			else
			{
				context.Response.Headers["Server"] = "VIEApps NGX";
				try
				{
					await this.Next.Invoke(context).ConfigureAwait(false);
				}
				catch (InvalidOperationException) { }
				catch (Exception ex)
				{
					Global.Logger.LogCritical($"Error occurred while invoking the next middleware: {ex.Message}", ex);
				}
			}
		}

		internal async Task ProcessInitializerRequestAsync(HttpContext context)
		{
			var redirectUrl = "";
			try
			{
				redirectUrl = context.GetQueryParameter("r").ToBase64(false, true).Decrypt(Global.EncryptionKey).ToArray('|').Last();
				if (string.IsNullOrWhiteSpace(redirectUrl))
					redirectUrl = context.GetReferUrl();
				redirectUrl += (redirectUrl.IndexOf("?") < 0 ? "?" : "&") + "r=";

				var userID = context.GetQueryParameter("u").ToBase64(false, true).Decrypt(Global.EncryptionKey).ToArray('|').Last();
				var isAuthenticated = context.GetQueryParameter("s").ToBase64(false, true).Decrypt(Global.EncryptionKey).ToArray('|').Last().CastAs<bool>();

				if (context.User.Identity.IsAuthenticated ? !isAuthenticated || !userID.Equals(context.User.Identity.Name) : isAuthenticated)
				{
					var session = context.GetSession();
					redirectUrl += $"&x-passport-token={session.GetAuthenticateToken(payload => payload["dev"] = session.DeviceID)}";
				}
			}
			catch (Exception ex)
			{
				await context.WriteLogsAsync("Passport", $"Error occurred while initializing: {ex.Message}", ex).ConfigureAwait(false);
			}

			context.Redirect(redirectUrl);
		}

		internal async Task ProcessValidatorRequestAsync(HttpContext context)
		{
			try
			{
				var userID = context.GetQueryParameter("u").ToBase64(false, true).Decrypt(Global.EncryptionKey).ToArray('|').Last();
				var isAuthenticated = context.GetQueryParameter("s").ToBase64(false, true).Decrypt(Global.EncryptionKey).ToArray('|').Last().CastAs<bool>();

				var scripts = "/*still authenticated*/";
				var needProcess = context.User.Identity.IsAuthenticated
					? !isAuthenticated || !userID.Equals(context.User.Identity.Name)
					: isAuthenticated;

				if (needProcess)
				{
					var session = context.GetSession();
					var token = session.GetAuthenticateToken(payload => payload["dev"] = session.DeviceID);

					var callbackFunction = context.GetQueryParameter("c").ToBase64(false, true).Decrypt(Global.EncryptionKey).ToArray('|').Last();
					if (string.IsNullOrWhiteSpace(callbackFunction))
					{
						var redirectUrl = context.GetReferUrl();
						redirectUrl += (redirectUrl.IndexOf("?") < 0 ? "?" : "&") + $"x-passport-token={token}";
						scripts = $"location.href=\"{redirectUrl}\"";
					}
					else
						scripts = $"{callbackFunction}({JSONWebToken.DecodeAsJson(token, Global.JWTKey).ToString(Formatting.None)})";

					await context.WriteAsync(scripts, "application/javascript", context.GetCorrelationID(), Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
			}
			catch (Exception ex)
			{
				await Task.WhenAll(
					context.WriteAsync($"console.error('Error occurred while validating: {ex.Message.Replace("'", @"\'")}')", "application/javascript", context.GetCorrelationID(), Global.CancellationTokenSource.Token),
					context.WriteLogsAsync("Passport", $"Error occurred while validating: {ex.Message}", ex)
				).ConfigureAwait(false);
			}
		}

		internal async Task ProcessSignOutRequestAsync(HttpContext context)
		{
			try
			{
				// sign-out
				var correlationID = context.GetCorrelationID();
				var session = context.GetSession();
				await context.CallServiceAsync(new RequestInfo(session, "Users", "Session", "DELETE")
				{
					Header = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "x-app-token", $"x-session-temp-token-{correlationID}" }
					},
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", $"x-session-temp-token-{correlationID}".GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = correlationID
				}, Global.CancellationTokenSource.Token).ConfigureAwait(false);

				await context.SignOutAsync().ConfigureAwait(false);
				context.User = new UserPrincipal();
				context.Session.Clear();

				// register new session
				session.User = new User("", "", new List<string> { SystemRole.All.ToString() }, new List<Privilege>())
				{
					SessionID = session.SessionID = UtilityService.NewUUID
				};

				var body = new JObject
				{
					{ "ID", session.SessionID },
					{ "IssuedAt", DateTime.Now },
					{ "RenewedAt", DateTime.Now },
					{ "ExpiredAt", DateTime.Now.AddDays(90) },
					{ "UserID", session.User.ID },
					{ "AccessToken", session.User.GetAccessToken(Global.ECCKey) },
					{ "IP", session.IP },
					{ "DeviceID", session.DeviceID },
					{ "AppInfo", session.AppName + " @ " + session.AppPlatform },
					{ "OSInfo", $"{session.AppAgent.GetOSInfo()} [{session.AppAgent}]" },
					{ "Verification", false },
					{ "Online", true }
				}.ToString(Formatting.None);

				await context.CallServiceAsync(new RequestInfo(session, "Users", "Session", "POST")
				{
					Body = body,
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = correlationID
				}, Global.CancellationTokenSource.Token).ConfigureAwait(false);

				// prepare url for redirecting
				var token = session.GetAuthenticateToken(payload => payload["dev"] = session.DeviceID);
				var redirectUrl = context.GetQueryParameter("ReturnUrl");
				if (string.IsNullOrWhiteSpace(redirectUrl))
					redirectUrl = context.GetReferUrl();
				redirectUrl += (redirectUrl.IndexOf("?") < 0 ? "?" : "&") + $"x-passport-token={token}";
				context.Redirect(redirectUrl);
			}
			catch (Exception ex)
			{
				await context.WriteLogsAsync("Passport", $"Error occurred while signing-out: {ex.Message}", ex).ConfigureAwait(false);
				context.ShowHttpError(ex.GetHttpStatusCode(), ex.Message, ex.GetType().GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
			}
		}

		#region Helper: WAMP connections & real-time updaters
		internal static void OpenWAMPChannels(int waitingTimes = 6789)
		{
			Global.Logger.LogInformation($"Attempting to connect to WAMP router [{WAMPConnections.GetRouterStrInfo()}]");
			Global.OpenWAMPChannels(
				(sender, args) =>
				{
					Global.Logger.LogInformation($"Incoming channel to WAMP router is established - Session ID: {args.SessionId}");
					WAMPConnections.IncomingChannel.Update(WAMPConnections.IncomingChannelSessionID, Global.ServiceName, $"Incoming ({Global.ServiceName} HTTP service)");
					Global.InterCommunicateMessageUpdater?.Dispose();
					Global.InterCommunicateMessageUpdater = WAMPConnections.IncomingChannel.RealmProxy.Services
						.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.files")
						.Subscribe(
							async (message) =>
							{
								var correlationID = UtilityService.NewUUID;
								try
								{
									await Handler.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false);
									if (Global.IsDebugResultsEnabled)
										await Global.WriteLogsAsync(Global.Logger, "RTU",
											$"Successfully process an inter-communicate message" + "\r\n" +
											$"- Type: {message?.Type}" + "\r\n" +
											$"- Message: {message?.Data?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
										, null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									await Global.WriteLogsAsync(Global.Logger, "RTU", $"{ex.Message} => {message?.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false);
								}
							},
							exception => Global.WriteLogs(Global.Logger, "RTU", $"{exception.Message}", exception)
						);
				},
				(sender, args) =>
				{
					Global.Logger.LogInformation($"Outgoing channel to WAMP router is established - Session ID: {args.SessionId}");
					WAMPConnections.OutgoingChannel.Update(WAMPConnections.OutgoingChannelSessionID, Global.ServiceName, $"Outgoing ({Global.ServiceName} HTTP service)");
					try
					{
						Task.WaitAll(new[] { Global.InitializeLoggingServiceAsync(), Global.InitializeRTUServiceAsync() }, waitingTimes > 0 ? waitingTimes : 6789, Global.CancellationTokenSource.Token);
						Global.Logger.LogInformation("Helper services are succesfully initialized");
					}
					catch (Exception ex)
					{
						Global.Logger.LogError($"Error occurred while initializing helper services: {ex.Message}", ex);
					}
				},
				waitingTimes
			);
		}

		static Task ProcessInterCommunicateMessageAsync(CommunicateMessage message) => Task.CompletedTask;
		#endregion

	}
}